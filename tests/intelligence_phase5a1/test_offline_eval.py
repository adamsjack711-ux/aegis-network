"""Frozen private Phase 5A-1 denominators and non-authority controls."""

from pathlib import Path

import pytest

from aegis.intelligence.alpha_eval import OfflineBudget, ScriptedStressProvider
from aegis.intelligence.phase5a1_eval import V_CORPUS, _load_v, evaluate_phase5a1


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def report():
    return evaluate_phase5a1(ROOT)


def test_separate_frozen_denominators_and_order(report):
    assert report["schema_version"] == "phase5a1-offline-eval-v1"
    assert len(report["v_trials"]) == 6
    assert [(t["order"], t["repeat"]) for t in report["v_trials"]] == [
        (order, repeat) for order in ("fixed", "seeded-shuffled") for repeat in (1, 2, 3)]
    for trial in report["v_trials"]:
        summary = trial["summary"]
        assert (summary["planned"], summary["eligible"], summary["inconclusive"]) == (12, 11, 1)
        assert (summary["exact_all_planned"], summary["exact_eligible"],
                summary["false_affected"]) == (9, 9, 0)
        assert summary["atomic_claim_errors"] == 0
    assert (report["v_total"]["planned"], report["v_total"]["eligible"],
            report["v_total"]["exact_all_planned"]) == (72, 66, 54)
    assert len(report["visible36_trials"]) == 3
    for trial in report["visible36_trials"]:
        assert (trial["planned_cases"], trial["baseline"]["completed"],
                trial["baseline"]["correct"]) == (36, 34, 33)
        assert trial["source_claims"]["independently_semantic_adjudicated"] == 0


def test_v_negative_cases_and_no_point_promotion(report):
    rows = {row["id"]: row for row in report["v_trials"][0]["rows"]}
    assert rows["V03-ecosystem-collision"]["observed"] == "unknown"
    assert rows["V10-withdrawn"]["observed"] == "unknown"
    assert rows["V11-epoch"]["status"] == "inconclusive"
    assert rows["V06-unconfirmed"]["observed"] == "unknown"
    assert rows["V07-injection"]["observed"] == "unaffected"
    assert report["v_total"]["scripted_points_attempted"] == 72
    assert report["v_total"]["scripted_points_emitted"] == 0
    assert report["v_total"]["scripted_checked_false_affected"] == 0
    assert report["v_total"]["scripted_raw_false_affected"] == 66
    assert report["v_total"]["independently_semantic_adjudicated"] == 0
    assert report["v_total"]["source_byte_bound_emitted"] == 30
    for trial in report["v_trials"]:
        for row in trial["rows"]:
            assert row["raw_point"]["support"] == "unchecked"
            assert row["raw_point"]["reportable"] is False
            for source in row["sources"]:
                if source["claim"] is not None:
                    assert source["claim"]["independently_verified"] is False
                    assert source["claim"]["source_sha256"] == source["sha256"]


def test_model_arm_explicitly_skipped_and_cost_unmeasured(report):
    assert report["real_model"] == {
        "status": "skipped", "planned_units": 72, "attempted_units": 0,
        "reason": "no separately approved endpoint/model, export scope, credential or billing oracle",
        "billed_tokens": None, "usd_cost": None}


def test_v_corpus_digest_rejects_changed_label(tmp_path):
    target = tmp_path / V_CORPUS
    target.parent.mkdir(parents=True)
    target.write_bytes((ROOT / V_CORPUS).read_bytes().replace(b"V01-exact-affected", b"V01-changed-label"))
    with pytest.raises(ValueError, match="corpus bytes changed"):
        _load_v(tmp_path)


def test_inert_provider_limits_and_rejects_non_json():
    provider = ScriptedStressProvider()
    with pytest.raises(ValueError, match="input byte limit"):
        provider.complete_json(b"x" * 10, budget=OfflineBudget(max_input_bytes=9))
    with pytest.raises(ValueError, match="invalid provider input"):
        provider.complete_json(b"not json", budget=OfflineBudget())
    with pytest.raises(ValueError, match="provider output budget"):
        provider.complete_json(b'{"sources":[]}', budget=OfflineBudget(max_output_bytes=1))
