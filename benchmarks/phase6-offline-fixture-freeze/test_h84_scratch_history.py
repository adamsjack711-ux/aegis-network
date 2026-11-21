"""Check the sealed h84 linked handoff against disposable research history."""

from contextlib import closing
from datetime import datetime
import json
import sqlite3

import pytest

from aegis.intelligence.feeds import FeedClient, snapshot
from aegis.intelligence.handoff import read_history
from aegis.intelligence.models import Asset
from aegis.intelligence.report import read_asset_report

import h84_linked_trial as linked
from osv_row_selection import canonical, load_target
from osv_two_stage import check_b
import scratch_history_admission as admission


# From the original h84 byte spans in seal/oracle/labels.json.
REFERENCES = (("/affected/0", 13, 149), ("/affected/2", 228, 312))


def stored_rows(database):
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as reader:
        reader.text_factory = bytes
        return reader.execute("""
            SELECT rowid, sequence, vulnerability_id, asset_digest, investigation
            FROM research_results ORDER BY rowid
        """).fetchall()


def row_ids(body):
    return [row["row_id"] for row in json.loads(json.loads(body)["input"])["candidate_rows"]]


@pytest.mark.parametrize(
    ("identity_indices", "version_indices", "stage_status", "stage_reason"),
    [
        ((2, 0), (0, 1), "verified", None),
        ((2, 0), (0,), "refused", "unaffected-selection-incomplete"),
        ((0,), (0, 1), "blocked", "identity-selection-is-incomplete-or-incorrect"),
    ],
    ids=["complete", "one-row-exclusion", "blocked-identity"],
)
def test_h84_linked_scratch_history(identity_indices, version_indices, stage_status, stage_reason):
    raw, target_bytes = linked.fixture()
    target = load_target(target_bytes)
    freeze, _ = admission.sealed_inputs()
    now = datetime.fromisoformat(freeze["clock"])
    advisory = json.loads(raw)["id"]
    uri = FeedClient().canonical_uri("osv", advisory)
    source = snapshot("osv", uri, raw, retrieved_at=now)
    asset = Asset(asset_id="synthetic-h84", identity_kind="purl",
                  identity=f"pkg:npm/{target.package}", version=target.version)
    asset_digest = admission.asset_digest(asset)

    a_ids = row_ids(linked.request_a())
    complete_a = canonical({"identity_outcome": "match", "selected_row_ids": [a_ids[2], a_ids[0]]})
    b_ids = row_ids(linked.request_b(complete_a))
    identity = canonical({"identity_outcome": "match", "selected_row_ids": [a_ids[i] for i in identity_indices]})
    version = canonical({"proposed_outcome": "unaffected", "selected_row_ids": [b_ids[i] for i in version_indices]})
    decision = check_b(raw, target_bytes, identity, version, arm="linked")
    assert (decision["status"], decision.get("reason")) == (stage_status, stage_reason)

    with admission.scratch() as scratch:
        database = scratch.path
        event, = scratch.scout.ingest(source)
        assert stored_rows(database) == []
        args = (event.sequence, advisory, source.sha256, asset, target_bytes, identity, version)
        receipt = scratch.admit(*args, now=now, commit_now=now)
        history = read_history(database, "osv", advisory)
        report = read_asset_report(database, "osv", advisory, advisory, asset_digest)
        stored = stored_rows(database)

        if stage_status == "verified":
            assert (receipt.outcome, receipt.reason) == ("committed", "verified-two-stage-current-at-commit")
            saved_row, = stored
            _, sequence, vulnerability, stored_asset, _ = saved_row
            assert (sequence, vulnerability, stored_asset) == (event.sequence, advisory.encode(), asset_digest.encode())
            entry, = history
            assert entry["status"] == "current" and entry["revision"] == linked.SOURCE_SHA
            candidate = entry["research"]["candidate"]
            current = report["current"]
            assert current["sequence"] == event.sequence and current["revision"] == linked.SOURCE_SHA
            assert current["reportable_outcome"] == "unaffected" and current["check_status"] == "research-consistent"
            expected_refs = [
                {"kind": "osv", "acquisition": "fixture", "uri": uri,
                 "retrieved_at": "2026-11-20T00:00:00Z", "sha256": linked.SOURCE_SHA, "pointer": pointer}
                for pointer, _, _ in REFERENCES
            ]
            assert current["applicability_references"] == candidate["applicability_references"] == expected_refs
            assert [
                (item["source_sha256"], item["byte_start"], item["byte_end"], item["quote"].encode())
                for item in candidate["excerpts"]
            ] == [(linked.SOURCE_SHA, start, end, raw[start:end]) for _, start, end in REFERENCES]

            retry = scratch.admit(*args, now=now, commit_now=now)
            assert (retry.outcome, retry.reason) == ("duplicate", "already-recorded")
            assert stored_rows(database) == stored
            assert read_history(database, "osv", advisory) == history
            assert read_asset_report(database, "osv", advisory, advisory, asset_digest) == report
            print(json.dumps({"stage": stage_status, "receipt": receipt.outcome, "rows": len(stored),
                              "reportable_outcome": current["reportable_outcome"],
                              "references": REFERENCES, "source_sha256": linked.SOURCE_SHA,
                              "retry": retry.outcome, "retry_row_identical": True}))
        else:
            assert decision["references"] == []
            assert (receipt.outcome, receipt.reason) == ("held", "unverified-two-stage-bundle")
            assert stored == history == report["history"] == []
            assert report["current"] is None
            print(json.dumps({"stage": stage_status, "stage_reason": stage_reason, "receipt": receipt.outcome,
                              "receipt_reason": receipt.reason, "rows": len(stored)}))
    assert not database.parent.exists()
