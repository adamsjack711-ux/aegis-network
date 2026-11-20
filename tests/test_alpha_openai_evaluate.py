"""Offline authorization and scoring checks; no external model calls."""

import json
from pathlib import Path

import pytest

from aegis.intelligence.alpha_eval import evaluate_alpha

from scripts.alpha_openai_evaluate import (canonical, digest, prepared, run, score,
                                          _validate_draft)


ROOT = Path(__file__).parents[1]


def test_prepared_bundle_preserves_seal_and_excludes_labels():
    bundle, cases = prepared()
    assert len(bundle["payloads"]) == len(cases) == 36
    assert all("expected" not in canonical(item).decode() for item in bundle["payloads"])
    assert bundle["seal"]["new_source_count"] == 27
    assert {item["id"] for item in bundle["payloads"]} == {case["id"] for case in cases}


def test_authorization_gate_and_bounded_local_transport(tmp_path):
    bundle, cases = prepared()
    with pytest.raises(FileNotFoundError):
        run(bundle, cases, "test-model", 10, 1, 1, tmp_path / "missing.json",
            transport=lambda _: b"{}")
    auth = {"authorization": "explicit-user-approval", "model": "test-model",
            "prepared_inputs_sha256": digest(canonical(bundle)), "max_usd": 10.0,
            "input_usd_per_million": 1.0, "output_usd_per_million": 1.0}
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(auth))
    calls = []

    def fake(body):
        calls.append(json.loads(body))
        return canonical({"status": "completed", "output": [{"content": [{"type": "output_text",
            "text": json.dumps({"decision": "unknown", "citations": [], "claims": []})}]}],
            "usage": {"input_tokens": 10, "output_tokens": 5}})

    results = run(bundle, cases, "test-model", 10, 1, 1, path, transport=fake)
    assert len(results) == len(calls) == 36
    assert all(r["usage"] == {"input_tokens": 10, "output_tokens": 5} for r in results)
    assert all(call["store"] is False for call in calls)
    auth["prepared_inputs_sha256"] = "0" * 64
    path.write_text(json.dumps(auth))
    with pytest.raises(ValueError, match="authorization required"):
        run(bundle, cases, "test-model", 10, 1, 1, path, transport=fake)


def test_extract_quotes_and_same_case_comparison():
    bundle, cases = prepared()
    baseline = evaluate_alpha(ROOT, scripted=False)
    source = cases[0]["sources"][0]
    draft = _validate_draft({"decision": "unaffected", "citations": [source["id"]],
                             "claims": [{"source_id": source["id"],
                                         "quote": source["text"][:35]}]}, cases[0])
    result = score(cases, baseline, [{"id": cases[0]["id"], "status": "completed", "draft": draft}])
    summary = result["summary"]
    assert summary["planned"] == 36
    assert summary["baseline_completed"] == 34
    assert summary["baseline_exact_on_eligible"] == 33
    assert summary["model_eligible_denominator"] == 1
    assert summary["exact_quote_supported_claims"] == 1
    assert summary["citation_ids_valid_cases"] == 1
