"""Offline contract checks for the approval gate and Responses adapter."""

import json
import socket
import time
from pathlib import Path

import httpx
import pytest

from aegis.intelligence.alpha_eval import _verified_cases, evaluate_alpha
from aegis.intelligence import openai_eval
from aegis.intelligence.openai_eval import (
    MAX_CALLS, MODEL, PROMPT_SHA256, _support, approval_template, case_payload,
    evaluate_openai, parse_response, request_body, worst_case_usd,
    OpenAIResponsesProvider,
)


ROOT = Path(__file__).parents[1]


def _response(draft, *, tokens=(100, 30)):
    return json.dumps({"id": "resp_fixture", "status": "completed", "model": MODEL,
                       "service_tier": "default",
                       "output": [{"type": "message", "content": [
                           {"type": "output_text", "text": json.dumps(draft)}]}],
                       "usage": {"input_tokens": tokens[0], "output_tokens": tokens[1]}}).encode()


def test_offline_report_keeps_seal_and_all_denominators_without_socket(monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("network attempted"))
    report = evaluate_openai(ROOT)
    assert report["model_status"] == "skipped-unapproved"
    assert report["model_benefit"] == "unverified"
    assert report["baseline"]["planned"] == 36
    assert report["baseline"]["completed"] == 34
    assert report["baseline"]["inconclusive"] == 2
    assert report["baseline"]["correct"] == 33
    assert len(report["payload_sha256"]) == 36
    assert report["prompt_sha256"] == PROMPT_SHA256
    assert report["actual_billed_usd"] is None
    assert worst_case_usd() <= .20


def test_payload_projection_and_approval_are_exact_and_disabled_by_default(tmp_path):
    cases, seal = _verified_cases(ROOT)
    payload = json.loads(case_payload(cases[0]))
    assert set(payload) == {"asset", "sources"}
    assert set(payload["sources"][0]) == {"id", "role", "retrieved_at", "text"}
    assert "expected" not in payload and "raw_path" not in json.dumps(payload)
    body = json.loads(request_body(case_payload(cases[0])))
    assert body["store"] is False and body["tools"] == []
    assert body["truncation"] == "disabled"
    template = approval_template(seal)
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(template))
    with pytest.raises(PermissionError, match="explicit inference approval"):
        evaluate_openai(ROOT, approval_path=approval, api_key="fake")
    template.update(approved=True, approved_by="reviewer", approved_at="2026-11-19T00:00:00Z")
    template["prompt_sha256"] = "0" * 64
    approval.write_text(json.dumps(template))
    with pytest.raises(PermissionError, match="fixed prompt_sha256"):
        evaluate_openai(ROOT, approval_path=approval, api_key="fake")


def test_response_schema_citations_and_usage_reject_unsafe_outputs():
    draft = {"decision": "affected", "citations": ["vendor-B01"],
             "version_claim": "affected", "impact_claim": "availability_degradation"}
    parsed = parse_response(_response(draft), {"vendor-B01"}, 1.23)
    assert parsed.draft == draft and parsed.input_tokens == 100
    with pytest.raises(ValueError):
        parse_response(_response({**draft, "citations": ["invented"]}), {"vendor-B01"}, 1)
    with pytest.raises(ValueError):
        parse_response(_response(draft, tokens=(9000, 30)), {"vendor-B01"}, 1)
    with pytest.raises(ValueError):
        parse_response(_response({**draft, "command": "run this"}), {"vendor-B01"}, 1)


def test_fixture_source_check_flags_fabricated_impact_and_unsupported_version():
    rows = {r["id"]: r for r in evaluate_alpha(ROOT, scripted=False)["rows"]}
    draft = {"decision": "affected", "citations": ["vendor-U03"],
             "version_claim": "affected", "impact_claim": "remote_execution"}
    check = _support(draft, rows["U03-fabricated-impact"])
    assert check["version_fixture_parser_consistent"]
    assert check["unsupported_impact"]
    assert check["model_claims_emitted_as_authority"] == 0
    supported = _support({**draft, "citations": ["vendor-B01"],
                          "impact_claim": "availability_degradation"}, rows["B01-inclusive-lower"])
    assert supported["version_fixture_parser_consistent"]
    assert supported["impact_fixture_parser_consistent"]
    unsupported = _support({**draft, "citations": ["vendor-F01"],
                            "impact_claim": "none"}, rows["F01-outside-range"])
    assert unsupported["unsupported_positive_version"]


def test_mock_responses_transport_has_fixed_shape_and_no_network():
    requests = []

    def handle(request):
        requests.append(request)
        body = json.loads(request.content)
        assert str(request.url) == "https://api.openai.com/v1/responses"
        assert body["model"] == MODEL and body["store"] is False
        return httpx.Response(200, content=_response({"decision": "unknown", "citations": [],
                                                     "version_claim": "none", "impact_claim": "none"}))

    provider = OpenAIResponsesProvider("fake-test-token", transport=httpx.MockTransport(handle))
    try:
        case = _verified_cases(ROOT)[0][0]
        reply = provider.complete(case_payload(case), {s["id"] for s in case["sources"]})
    finally:
        provider.close()
    assert reply.draft["decision"] == "unknown"
    assert len(requests) == 1


def test_process_wall_alarm_interrupts_blocked_provider(monkeypatch):
    monkeypatch.setattr(openai_eval, "TIMEOUT_SECONDS", .01)
    with pytest.raises(TimeoutError, match="hard wall deadline"):
        openai_eval._with_hard_deadline(lambda: time.sleep(.1))


def test_mock_experiment_retains_108_case_rows_and_never_claims_verified_benefit(tmp_path):
    _, seal = _verified_cases(ROOT)
    approval = approval_template(seal)
    approval.update(approved=True, approved_by="offline test", approved_at="2026-11-19T00:00:00Z")
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(approval))
    calls = []

    def factory(key):
        assert key == "fake"

        def handle(request):
            calls.append(request)
            return httpx.Response(200, content=_response({"decision": "unknown", "citations": [],
                                                         "version_claim": "none", "impact_claim": "none"}))

        return OpenAIResponsesProvider(key, transport=httpx.MockTransport(handle))

    report = evaluate_openai(ROOT, approval_path=path, api_key="fake", provider_factory=factory)
    assert len(calls) == MAX_CALLS == 108
    assert len(report["model_trials"]) == 3
    assert all(t["counts"]["denominator"] == 36 and
               t["paired_evaluable_counts"]["denominator"] == 34 for t in report["model_trials"])
    assert report["model_benefit"] == "unverified"
    assert report["actual_billed_usd"] is None
    assert report["model_status"] == "completed-needs-independent-adjudication"
