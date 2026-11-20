"""Offline control and authorization checks for the optional inference arm."""

import json
from pathlib import Path

import pytest

from aegis.intelligence.model_evaluation import evaluate_model
from aegis.intelligence.provider import HTTPSJSONProvider
from aegis.intelligence import Asset, normalize, snapshot
from aegis.intelligence.research import FixtureProvider, research


CORPUS = Path(__file__).parent / "fixtures" / "phase5a_model_cases.json"


def test_comparison_keeps_raw_hypotheses_separate_from_checked_outcomes():
    offline = evaluate_model(CORPUS)
    scripted = evaluate_model(CORPUS, mode="scripted")
    assert offline["baseline"]["correct"] == scripted["baseline"]["correct"] == 20
    assert offline["raw_model"] is None
    assert scripted["raw_model"]["correct"] == 17
    assert scripted["raw_model"]["false_positive"] == 3
    assert scripted["checked"]["correct"] == 20
    assert scripted["checked"]["false_positive"] == 0
    assert scripted["positive_points_unchecked"] > 0
    assert scripted["unsupported_assertions_adjudicated"] is None
    assert scripted["real_model_evaluation_verified"] is False
    assert scripted["meaningful_improvement_verified"] is False
    for row in scripted["cases"]:
        if row["id"].endswith("positive-trap"):
            assert row["raw_model"] == "affected"
            assert row["checked"] == "unknown"


def test_corpus_digest_and_labels_are_required(tmp_path):
    corpus = tmp_path / "phase5a_model_cases.json"
    manifest = tmp_path / "phase5a_model_manifest.json"
    corpus.write_bytes(CORPUS.read_bytes())
    manifest.write_bytes(CORPUS.with_name("phase5a_model_manifest.json").read_bytes())
    cases = json.loads(corpus.read_text())
    cases[0]["gold"] = "unaffected"
    corpus.write_text(json.dumps(cases))
    with pytest.raises(ValueError, match="manifest mismatch"):
        evaluate_model(corpus)


def test_external_transport_is_denied_before_open(monkeypatch):
    def fail_open(*args, **kwargs):
        raise AssertionError("network attempted")
    monkeypatch.setattr("urllib.request.build_opener", fail_open)
    provider = HTTPSJSONProvider(endpoint="https://inference.example.test/complete",
                                 model="pinned-model", token="test-token")
    with pytest.raises(PermissionError, match="authorization"):
        provider.complete_json("instructions", "payload", max_output_tokens=700)
    with pytest.raises(ValueError, match="HTTPS"):
        HTTPSJSONProvider(endpoint="http://inference.example.test/complete",
                          model="pinned-model", token="test-token", authorized=True)
    with pytest.raises(ValueError, match="budget"):
        HTTPSJSONProvider(endpoint="https://inference.example.test/complete",
                          model="pinned-model", token="test-token", authorized=True).complete_json(
                              "instructions", "payload", max_output_tokens=1001)


def test_research_prompt_does_not_disclose_baseline_label():
    case = json.loads(CORPUS.read_text())[0]
    source = case["sources"][0]
    evidence = snapshot(source["kind"], source["uri"], json.dumps(source["body"]).encode())
    captured = {}
    class Capture(FixtureProvider):
        def complete_json(self, instructions, payload, *, max_output_tokens):
            captured["payload"] = json.loads(payload)
            return super().complete_json(instructions, payload, max_output_tokens=max_output_tokens)
    research(Asset.model_validate(case["asset"]), normalize(evidence), case["vulnerability_id"],
             Capture(case["fixture_response"]), source_snapshots=(evidence,))
    assert "baseline_outcome" not in captured["payload"]
    assert "gold" not in captured["payload"]


def test_provider_response_limit_and_usage_validation(monkeypatch):
    class Response:
        status = 200
        def __init__(self, body):
            self.body = body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, limit):
            return self.body[:limit]
    class Opener:
        def __init__(self, body):
            self.body = body
        def open(self, request, timeout):
            assert timeout == 5
            assert request.full_url == "https://inference.example.test/complete"
            return Response(self.body)
    provider = HTTPSJSONProvider(endpoint="https://inference.example.test/complete",
                                 model="pinned-model", token="test-token", authorized=True,
                                 timeout_seconds=5)
    good = {"content": "{}", "usage": {"input_tokens": 3, "output_tokens": 2},
            "provider_version": "2026-11"}
    monkeypatch.setattr("urllib.request.build_opener", lambda *_: Opener(json.dumps(good).encode()))
    result = provider.complete_json("instructions", "payload", max_output_tokens=700)
    assert result.usage.input_tokens == 3
    bad = {**good, "usage": {"input_tokens": 3, "output_tokens": 701}}
    monkeypatch.setattr("urllib.request.build_opener", lambda *_: Opener(json.dumps(bad).encode()))
    with pytest.raises(ValueError, match="invalid provider response"):
        provider.complete_json("instructions", "payload", max_output_tokens=700)
