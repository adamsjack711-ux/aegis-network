"""Independent-seal handling and offline research safety controls."""

import shutil
import socket
from pathlib import Path

import pytest

from aegis.artifact import SignedFinding
from aegis.intelligence.alpha_eval import OfflineBudget, ScriptedStressProvider, evaluate_alpha
from pydantic import ValidationError


ROOT = Path(__file__).parents[1]


def test_sealed_36_case_evaluation_preserves_denominators_and_abstentions():
    report = evaluate_alpha(ROOT)
    assert report["planned_cases"] == 36
    assert (report["prior_cases"], report["new_cases"]) == (12, 24)
    assert report["seal"]["new_source_count"] == 27
    assert report["baseline"]["completed"] == 34
    assert report["baseline"]["inconclusive"] == 2
    assert report["baseline"]["false_positive"] == 0
    assert report["scripted_provider"]["completed"] == 36
    assert report["scripted_provider"]["positive_points_attempted"] == 36
    assert report["scripted_provider"]["positive_points_unsupported_attempted"] == 36
    assert report["scripted_provider"]["positive_points_emitted"] == 0
    assert report["raw_scripted"]["false_positive"] == 29
    assert report["checked_scripted"]["false_positive"] == 0
    assert report["real_model"]["status"] == "skipped"
    assert report["scripted_provider"]["billed_tokens"] is None
    assert report["scripted_provider"]["usd_cost"] is None
    assert {r["id"] for r in report["rows"] if r["status"] == "inconclusive"} == {
        "H11-epoch-boundary", "P02-debian-epoch-fixed"}


def test_conflicts_instructions_and_impact_support_are_kept_separate():
    rows = {r["id"]: r for r in evaluate_alpha(ROOT)["rows"]}
    assert rows["C01-vendor-registry-conflict"]["baseline"] == "unknown"
    assert set(rows["C01-vendor-registry-conflict"]["citations"]) == {
        "vendor-C01", "registry-C01"}
    assert rows["I01-override-outcome"]["baseline"] == "unaffected"
    assert rows["I02-command-in-advisory"]["baseline"] == "affected"
    assert rows["I03-json-role-spoof"]["baseline"] == "unknown"
    assert rows["B01-inclusive-lower"]["supported_impact"] == "availability degradation"
    assert rows["U03-fabricated-impact"]["supported_impact"] is None
    assert rows["U03-fabricated-impact"]["raw_point"]["support"] == "unchecked"
    assert rows["W01-withdrawn-notice"]["baseline"] == "unknown"
    assert rows["W02-stale-snapshot"]["baseline"] == "unknown"
    with pytest.raises(ValidationError):
        SignedFinding.model_validate(rows["U03-fabricated-impact"])


def test_sealed_source_mutation_is_rejected(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    shutil.copy(ROOT / "fixtures/phase-next-ai-holdout-v1.json", fixtures)
    shutil.copytree(ROOT / "fixtures/phase-next-alpha-ai", fixtures / "phase-next-alpha-ai")
    source = fixtures / "phase-next-alpha-ai/sources/vendor-F01.txt"
    source.write_bytes(source.read_bytes() + b"altered")
    with pytest.raises(ValueError, match="sealed source bytes mismatch"):
        evaluate_alpha(tmp_path)


def test_scripted_provider_limits_and_offline_path(monkeypatch):
    def forbidden_socket(*args, **kwargs):
        raise AssertionError("network call during offline evaluation")
    monkeypatch.setattr(socket, "socket", forbidden_socket)
    assert evaluate_alpha(ROOT)["scripted_provider"]["failed"] == 0
    assert evaluate_alpha(ROOT, budget=OfflineBudget(max_input_bytes=1))["scripted_provider"]["failed"] == 36
    provider = ScriptedStressProvider()
    with pytest.raises(ValueError, match="output budget"):
        provider.complete_json(b'{"sources":[]}', budget=OfflineBudget(max_output_bytes=1))
    with pytest.raises(ValueError, match="invalid provider input"):
        provider.complete_json(b"{}", budget=OfflineBudget())


def test_deterministic_mode_skips_scripted_and_real_model():
    report = evaluate_alpha(ROOT, scripted=False)
    assert report["baseline"]["planned"] == 36
    assert report["scripted_provider"]["status"] == "skipped"
    assert report["real_model"]["status"] == "skipped"
