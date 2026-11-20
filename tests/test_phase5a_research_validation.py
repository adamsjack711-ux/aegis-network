"""Independent scoring and dormant provider boundary tests."""

import json
from pathlib import Path

import pytest

from aegis.intelligence.alpha_eval import _source_decision, evaluate_alpha
from aegis.intelligence.independent_validation import validate_offline_report
from aegis.intelligence.openai_provider import OpenAIResponsesProvider


ROOT = Path(__file__).parents[1]


def test_independent_validator_uses_sealed_labels_and_rejects_tampering():
    report = evaluate_alpha(ROOT)
    scored = validate_offline_report(ROOT, report)["trials"][0]
    assert (scored["planned"], scored["eligible"], scored["exact"], scored["inconclusive"]) == (36, 34, 33, 2)
    assert scored["false_positive"] == 0
    assert scored["citation_id_errors"] == 0
    report["rows"][0]["expected"] = "affected"
    with pytest.raises(ValueError, match="sealed oracle"):
        validate_offline_report(ROOT, report)


def test_validator_rejects_positive_prose_promotion():
    report = evaluate_alpha(ROOT)
    report["rows"][0]["raw_point"]["support"] = "supported"
    with pytest.raises(ValueError, match="promoted"):
        validate_offline_report(ROOT, report)


def test_openai_provider_is_inert_without_authorization(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network was opened")
    monkeypatch.setattr("urllib.request.build_opener", forbidden)
    provider = OpenAIResponsesProvider(model="test-model", api_key="test-only")
    with pytest.raises(PermissionError, match="not been authorized"):
        provider.complete_json("instructions", "{}", max_output_tokens=200)


def test_backport_exact_identity_does_not_swallow_sentence_period():
    text = "AEGIS-ADV-D01 concerns Debian maple-lib. Version 1.2-3+deb12u1 is fixed by a distribution backport."
    assert _source_decision(text, {"ecosystem": "deb", "name": "maple-lib",
                                   "version": "1.2-3+deb12u1"}) == ("unaffected", "explicit-fixed-or-unaffected")


def test_openai_response_contract_with_in_memory_transport(monkeypatch):
    payload = {"status": "completed", "model": "test-model", "usage": {"input_tokens": 12,
               "output_tokens": 20}, "output": [{"type": "message", "role": "assistant",
               "content": [{"type": "output_text", "text": '{"candidate_outcome":"unknown"}'}]}]}
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self, limit): return json.dumps(payload).encode()
    class Opener:
        def open(self, request, timeout):
            sent = json.loads(request.data)
            assert sent["store"] is False and sent["tools"] == []
            assert request.full_url == "https://api.openai.com/v1/responses"
            return Response()
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener())
    result = OpenAIResponsesProvider(model="test-model", api_key="test-only", authorized=True).complete_json(
        "instructions", "{}", max_output_tokens=200)
    assert result.usage.input_tokens == 12 and result.provider == "openai-responses"
    payload["status"] = "incomplete"
    with pytest.raises(ValueError, match="incomplete"):
        OpenAIResponsesProvider(model="test-model", api_key="test-only", authorized=True).complete_json(
            "instructions", "{}", max_output_tokens=200)
