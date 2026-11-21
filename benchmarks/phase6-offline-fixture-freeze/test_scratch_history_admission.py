"""Focused checks for scratch-only two-stage history admission."""

from datetime import datetime, timezone
import json

import pytest

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.handoff import read_history

from osv_row_selection import canonical
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
