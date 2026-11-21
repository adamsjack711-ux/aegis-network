"""Focused checks for scratch-only two-stage history admission."""

from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import json

import pytest

from aegis.intelligence.feeds import FeedClient, snapshot
from aegis.intelligence.handoff import read_history
from aegis.intelligence.models import Asset
from aegis.intelligence.report import read_asset_report

from osv_row_selection import canonical, load_target
from osv_two_stage import check_a, check_b, prepare_a, prepare_b
import scratch_history_admission as trial


def test_frozen_admission_replay():
    observed = trial.run()
    assert observed["h28-fresh"]["rows_after"] == 1
    assert observed["h28-fresh"]["retry"]["outcome"] == "duplicate"
    for case in ("h28-stale", "h28-expired-at-commit", "h62-mixed-policy"):
        assert observed[case]["receipt"]["outcome"] == "held"
        assert observed[case]["rows_before"] == observed[case]["rows_after"] == 0

    for case, status in (("h53-frozen-conflict", "conflict"),
                         ("h53-advanced-withdrawal", "withdrawn"),
                         ("h31-pending-superseded", "superseded")):
        result = observed[case]
        assert result["receipt"]["outcome"] == "held"
        before, = result["before_history"]
        assert result["history"] == [before | {"status": status}]

    pending = observed["h31-pending-superseded"]
    assert pending["schedule"]["evaluated_check"] == "research-consistent"
    assert pending["schedule"]["evaluated_outcome"] == "affected"
    assert pending["schedule"]["pending_before"]["history"] == []
    assert pending["fresh_subject_report"]["history"] == []
    assert pending["schedule"]["pending_before"]["asset_digest"] != pending["history"][0]["asset_digest"]


@pytest.mark.parametrize("difference, reason", [
    ("digest", "source-binding-mismatch"),
    ("target", "target-binding-mismatch"),
    ("identity", "unverified-two-stage-bundle"),
    ("version", "unverified-two-stage-bundle"),
])
def test_unbound_or_invalid_stage_bundle_writes_nothing(difference, reason):
    _, pairs = trial.sealed_inputs()
    raw, target, advisory, uri, asset, (identity, version) = trial.case_setup(
        "h28", pairs["h28"], matches=[1], selected=[0], outcome="affected",
    )
    now = datetime(2026, 11, 20, tzinfo=timezone.utc)
    source = snapshot("osv", uri, raw, retrieved_at=now)
    with trial.scratch() as scratch:
        path = scratch.path
        event, = scratch.scout.ingest(source)
        digest = source.sha256
        if difference == "digest":
            digest = "0" * 64
        elif difference == "target":
            asset = asset.model_copy(update={"version": "9.9"})
        elif difference == "identity":
            identity = canonical({"identity_outcome": "no_match", "selected_row_ids": []})
        else:
            version = canonical({"proposed_outcome": "affected", "selected_row_ids": ["r-forged"]})
        receipt = scratch.admit(event.sequence, advisory, digest, asset, target, identity, version, now=now)
        assert (receipt.outcome, receipt.reason) == ("held", reason)
        assert read_history(path, "osv", advisory) == []
    assert not path.parent.exists()


def test_duplicate_source_text_cannot_substitute_for_exact_selected_spans():
    _, pairs = trial.sealed_inputs()
    original, target = pairs["h28"]
    body = json.loads(original)
    body["affected"] = [body["affected"][1], body["affected"][1]]
    raw, target, advisory, uri, asset, drafts = trial.case_setup(
        "h28", (canonical(body), target), matches=[0, 1], selected=[0, 1], outcome="affected",
    )
    now = datetime(2026, 11, 20, tzinfo=timezone.utc)
    source = snapshot("osv", uri, raw, retrieved_at=now)
    with trial.scratch() as scratch:
        event, = scratch.scout.ingest(source)
        receipt = scratch.admit(event.sequence, advisory, source.sha256, asset, target, *drafts, now=now)
        assert (receipt.outcome, receipt.reason) == ("held", "selected-evidence-binding-mismatch")
        assert read_history(scratch.path, "osv", advisory) == []


def test_freshness_is_sampled_after_the_contended_writer_lock():
    observed = trial.run_lock_contention()
    expired, fresh = observed["expired_while_waiting"], observed["fresh_after_same_wait"]
    for report in (expired, fresh):
        assert report["evaluated_outcome"] == "affected"
        assert report["competing_writer"] == "SQLITE_BUSY"
        assert report["rows_while_contended"] == 0
        assert report["observed_wait_ms"] >= report["hold_window_ms"]
        assert report["transaction"][:4] == ["SELECT", "BEGIN IMMEDIATE", "CLOCK", "SELECT"]
        assert report["evaluation_clock"] == fresh["sampled_commit_clock"]
        assert report["source_retrieved_at"] == fresh["source_retrieved_at"]
        assert report["hold_window_ms"] == fresh["hold_window_ms"]

    assert expired["clock_advanced_while_held"] is True
    assert expired["sampled_commit_clock"] > expired["evaluation_clock"]
    assert expired["receipt"]["reason"] == "stale-or-future-source"
    assert expired["rows_after"] == 0 and expired["fresh_subject_report"]["current"] is None
    assert expired["transaction"][4:] == ["ROLLBACK"]

    assert fresh["clock_advanced_while_held"] is False
    assert fresh["rows_after"] == 1 and fresh["receipt"]["outcome"] == "committed"
    assert fresh["transaction"][4:] == ["INSERT", "COMMIT"]
    assert fresh["retry"]["outcome"] == "duplicate"


def test_h75_missing_version_evidence_holds_all_three_drafts():
    # Original sealed bytes and expected stage inputs from the independent
    # preselection at a6ce6fe. The three proposals below are local scripts.
    folder = trial.SEAL / "inputs/original/h75"
    raw = (folder / "source.json").read_bytes()
    target_bytes = (folder / "target.json").read_bytes()
    assert sha256(raw).hexdigest() == "94b223291ee528b5c64034e0db0aed1de1d5be500a938b2006cb5ae9fdcac9b7"
    assert sha256(target_bytes).hexdigest() == "30d491527322ff9b42bda3f80cd86f280b6d726910c90ccf9769863bdde8bb5c"
    target = load_target(target_bytes)
    original = json.loads(raw)
    decoy, matching = original["affected"]
    assert decoy["package"]["ecosystem"] != target.ecosystem and target.version in decoy["versions"]
    assert matching["package"] == {"ecosystem": target.ecosystem, "name": target.package}
    assert set(matching) == {"package"}

    prepared_a = prepare_a(raw, target_bytes)
    assert prepared_a["request_sha256"] == "fbef57e551cde0865e01eeecba73cb7aecc431b72c4f33789ac2597d12a771dd"
    _, chosen = prepared_a["payload"]["candidate_rows"]
    identity = canonical({"identity_outcome": "match", "selected_row_ids": [chosen["row_id"]]})
    checked_a = check_a(raw, target_bytes, identity)
    assert checked_a["status"] == "verified" and checked_a["matched_pointers"] == ["/affected/1"]

    admission = canonical({"matched_pointers": ["/affected/1"]})
    oracle = prepare_b(raw, target_bytes, admission, arm="oracle")
    linked = prepare_b(raw, target_bytes, identity, arm="linked")
    assert linked["request_sha256"] == oracle["request_sha256"] == (
        "4b718bf90275996488bc45a738dc6672016a96bdb53723df20670cf14e56679a"
    )
    candidate, = linked["payload"]["candidate_rows"]
    assert json.loads(candidate["osv_row"]) == matching

    freeze, _ = trial.sealed_inputs()
    now = datetime.fromisoformat(freeze["clock"])
    advisory = original["id"]
    uri = FeedClient().canonical_uri("osv", advisory)
    asset = Asset(asset_id="synthetic-h75", identity_kind="purl",
                  identity=f"pkg:pypi/{target.package}", version=target.version)
    source = snapshot("osv", uri, raw, retrieved_at=now)
    results = []
    with trial.scratch() as scratch:
        database = scratch.path
        event, = scratch.scout.ingest(source)
        assert read_history(database, "osv", advisory) == []
        for outcome in ("unknown", "affected", "unaffected"):
            chosen_ids = [] if outcome == "unknown" else [candidate["row_id"]]
            version = canonical({"proposed_outcome": outcome, "selected_row_ids": chosen_ids})
            decision = check_b(raw, target_bytes, identity, version, arm="linked")
            oracle_decision = check_b(raw, target_bytes, admission, version, arm="oracle")
            assert decision["status"] == oracle_decision["status"] == (
                "abstained" if outcome == "unknown" else "refused"
            )
            assert decision["reportable_outcome"] == oracle_decision["reportable_outcome"] == "unknown"
            assert decision["references"] == oracle_decision["references"] == []

            writes = []

            def trace(sql):
                operation = sql.strip().split()[0].upper()
                if operation in {"BEGIN", "INSERT"}:
                    writes.append(operation)

            scratch.writer.db.set_trace_callback(trace)
            try:
                receipt = scratch.admit(event.sequence, advisory, source.sha256, asset, target_bytes,
                                        identity, version, now=now)
            finally:
                scratch.writer.db.set_trace_callback(None)
            assert (receipt.outcome, receipt.reason) == ("held", "unverified-two-stage-bundle")
            assert writes == []
            fresh = read_history(database, "osv", advisory)
            report = read_asset_report(database, "osv", advisory, advisory, trial.asset_digest(asset))
            assert fresh == report["history"] == [] and report["current"] is None
            results.append({"proposed_outcome": outcome, "oracle_status": oracle_decision["status"],
                            "linked_status": decision["status"], "references": len(decision["references"]),
                            "receipt": asdict(receipt), "fresh_research_rows": len(fresh),
                            "write_statements": writes})
    assert not database.parent.exists()
    print(json.dumps({"fixture": "h75", "identity_status": checked_a["status"],
                      "matched_pointers": checked_a["matched_pointers"], "controls": results}, sort_keys=True))
