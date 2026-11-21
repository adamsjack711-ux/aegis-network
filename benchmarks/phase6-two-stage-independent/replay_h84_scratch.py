"""Independently replay frozen h84 scripted drafts against disposable history."""
import argparse
from contextlib import closing
from dataclasses import asdict
from datetime import datetime
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

from score import load, pack, raw_hash


def stored_bytes(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as reader:
        return [
            content for (content,) in reader.execute(
                "SELECT CAST(investigation AS BLOB) FROM research_results ORDER BY sequence"
            )
        ]


def verify_references(row, current, source, gold, source_hash):
    expected_refs = {(reference["pointer"], source_hash) for reference in gold}
    candidate = row["research"]["candidate"]
    for references in (candidate["applicability_references"], current["applicability_references"]):
        assert len(references) == len(expected_refs)
        assert {(reference["pointer"], reference["sha256"]) for reference in references} == expected_refs
    evidence = []
    for actual, expected in zip(candidate["excerpts"], gold, strict=True):
        assert actual["source_sha256"] == source_hash
        start, end = expected["byte_start"], expected["byte_end"]
        assert (actual["byte_start"], actual["byte_end"]) == (start, end)
        excerpt = actual["quote"].encode()
        assert excerpt == source[start:end]
        assert raw_hash(excerpt) == expected["row_sha256"]
        evidence.append(expected | {"source_sha256": source_hash})
    return evidence


def draft(outcome_field, outcome, pointers, row_ids):
    return pack({outcome_field: outcome, "selected_row_ids": [row_ids[pointer] for pointer in pointers]})


def replay(checkout):
    sys.path[:0] = [
        str(checkout / "src"),
        str(checkout / "benchmarks/phase6-offline-fixture-freeze"),
    ]
    from aegis.intelligence.feeds import FeedClient, snapshot
    from aegis.intelligence.handoff import read_history
    from aegis.intelligence.models import Asset
    from aegis.intelligence.report import read_asset_report
    from osv_two_stage import check_b, prepare_a
    from scratch_history_admission import scratch

    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    frozen = load("preselection-h84-scratch.json")
    linked_gold = Path("preselection-h84.json").read_bytes()
    assert raw_hash(linked_gold) == frozen["linked_preselection_sha256"]
    linked = json.loads(linked_gold)
    folder = Path("seal/inputs") / frozen["case"]
    source = (folder / "source.json").read_bytes()
    target = (folder / "target.json").read_bytes()
    assert raw_hash(source) == linked["source_sha256"] and raw_hash(target) == linked["target_sha256"]
    advisory = frozen["advisory_id"]
    assert json.loads(source)["id"] == advisory
    asset = Asset(**frozen["asset"])
    asset_hash = raw_hash(pack(asset.model_dump(mode="json")))
    clocks = {key: datetime.fromisoformat(value) for key, value in frozen["clocks"].items()}
    uri = FeedClient().canonical_uri("osv", advisory)
    pinned = snapshot("osv", uri, source, retrieved_at=clocks["retrieval"])
    prepared_a = prepare_a(source, target)
    assert prepared_a["request_sha256"] == linked["A"]["prepared_sha256"]
    a_ids = dict(zip(linked["A"]["complete_set"], linked["A"]["row_ids"], strict=True))
    b_refs = linked["linked_B"]["expected_refs"]
    b_ids = dict(zip((ref["pointer"] for ref in b_refs), linked["linked_B"]["row_ids"], strict=True))
    positive = frozen["supported"]
    controls = frozen["controls"]
    supported_a = draft("identity_outcome", positive["identity_outcome"], positive["identity_pointers"], a_ids)
    supported_b = draft("proposed_outcome", positive["version_outcome"], positive["version_pointers"], b_ids)

    def exercise(a, b, control=None):
        result = check_b(source, target, a, b, arm="linked")
        with scratch() as trial:
            path = trial.path
            event, = trial.scout.ingest(pinned)
            reads = []

            def sample_clock():
                assert trial.writer.db.in_transaction
                reads.append(frozen["clocks"]["commit"])
                return clocks["commit"]

            def admit():
                return trial.admit(
                    event.sequence, advisory, pinned.sha256, asset, target, a, b,
                    now=clocks["evaluation"], commit_clock=sample_clock,
                )

            def fresh_report():
                return read_asset_report(path, "osv", advisory, advisory, asset_hash)

            assert read_history(path, "osv", advisory) == stored_bytes(path) == []
            assert fresh_report()["current"] is None
            receipt = admit()
            after = read_history(path, "osv", advisory)
            stored = stored_bytes(path)
            report = fresh_report()
            current = report["current"]
            observation = {"admission": asdict(receipt), "rows_before": 0, "rows_after": len(stored)}
            if control is None:
                assert result["status"] == "verified"
                assert result["reportable_outcome"] == positive["version_outcome"]
                assert receipt.outcome == positive["admission"]
                assert len(stored) == positive["rows_after"]
                row, = after
                payload, = stored
                assert json.loads(payload) == row["research"]
                expected = positive["fresh_history"]
                assert row["status"] == expected["status"]
                assert current["check_status"] == expected["check"]
                assert current["reportable_outcome"] == expected["reportable_outcome"]
                assert row["revision"] == current["revision"] == linked["source_sha256"]
                assert row["asset_digest"] == asset_hash and row["sequence"] == event.sequence
                evidence = verify_references(row, current, source, b_refs, linked["source_sha256"])
                assert reads == [frozen["clocks"]["commit"]]
                retry = admit()
                assert retry.outcome == positive["retry"]["outcome"]
                assert stored_bytes(path) == [payload]
                assert read_history(path, "osv", advisory) == after and fresh_report() == report
                assert reads == [frozen["clocks"]["commit"]] * 2
                precision = [len(evidence), len(current["applicability_references"])]
                coverage = [len(evidence), len(b_refs)]
                assert precision == positive["reference_precision"] and coverage == positive["support_coverage"]
                observation.update(
                    linked_status=result["status"], fresh_current=current, exact_references=evidence,
                    reference_precision=precision, support_coverage=coverage,
                    stored_investigation_sha256=raw_hash(payload), retry=asdict(retry),
                    retry_rows_after=len(stored_bytes(path)), retry_bytes_identical=True,
                )
            else:
                expected = controls["shared_expected"]
                assert (result["status"], result["reason"]) == (control["linked_status"], control["linked_reason"])
                assert not result["references"]
                assert (receipt.outcome, receipt.reason) == (expected["admission"], expected["reason"])
                assert after == stored == report["history"] == []
                assert current == expected["fresh_current"] and len(reads) == expected["commit_clock_samples"]
                observation.update(linked_status=result["status"], linked_reason=result["reason"], fresh_current=current)
            observation["commit_clock_samples"] = reads
        assert not path.parent.exists()
        return observation, path

    partial_b = controls["one_row_exclusion"]
    blocked_a = controls["blocked_identity"]
    version = draft("proposed_outcome", partial_b["version_outcome"], partial_b["version_pointers"], b_ids)
    identity = draft("identity_outcome", blocked_a["identity_outcome"], blocked_a["identity_pointers"], a_ids)
    supported, positive_path = exercise(supported_a, supported_b)
    partial, partial_path = exercise(supported_a, version, partial_b)
    blocked, blocked_path = exercise(identity, supported_b, blocked_a)
    assert len({positive_path, partial_path, blocked_path}) == 3
    return {
        "candidate": revision,
        "case": frozen["case"],
        "clocks": frozen["clocks"],
        "supported": supported,
        "one_row_exclusion": partial,
        "blocked_identity": blocked,
        "independent_disposable_databases": 3,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    args = parser.parse_args()
    print(json.dumps(replay(args.checkout.resolve()), indent=2))
