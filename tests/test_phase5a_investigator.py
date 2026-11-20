"""Offline contract and failure tests for the bounded Investigator."""

import json
import time
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.investigator import (
    AdvisoryInput, Authorization, Limits, OpenAIProvider, ScriptedProvider, SpendLedger,
    investigate, verify_investigation,
)
from aegis.intelligence.investigator_eval import evaluate_investigator
from aegis.intelligence.models import Asset

CORPUS = Path(__file__).parent / "fixtures/phase5a_cases.json"
NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)


def sample(index=0):
    case = json.loads(CORPUS.read_text())[index]
    sources = tuple(snapshot(s["kind"], s["uri"],
                             json.dumps(s["body"], sort_keys=True,
                                        separators=(",", ":")).encode(),
                             retrieved_at=datetime.fromisoformat(s["retrieved_at"]))
                    for s in case["sources"])
    advisory = AdvisoryInput(advisory_id=case["id"],
                             vulnerability_id=case["vulnerability_id"],
                             asset=Asset.model_validate(case["asset"]), sources=sources)
    quote = case["sources"][0]["body"].get("summary", sources[0].content.decode()[:25])
    response = {"proposed_outcome": case["gold"], "claims": [
        {"kind": "applicability", "source_id": "S1", "quote": quote}],
        "uncertainties": []}
    return advisory, response


def test_sealed_offline_comparison_is_explicitly_not_model_accuracy():
    report = evaluate_investigator(CORPUS)
    assert report["planned"] == 12
    assert report["baseline_correct"] == report["investigator_correct"] == 12
    assert report["false_affected"] == 0
    assert report["actual_model"]["status"] == "skipped"
    assert report["actual_model_accuracy"] is None


def test_source_excerpt_is_exact_and_audit_has_no_private_content():
    advisory, response = sample()
    result = investigate(advisory, ScriptedProvider(response), now=NOW)
    assert result.candidate.reportable_outcome == "affected"
    assert result.check.status == "research-consistent"
    assert result.candidate.independently_verified is False
    verify_investigation(advisory, result, now=NOW)
    audit = result.audit.model_dump_json()
    assert "private-prod-1" not in audit
    assert "secret-host.internal" not in audit
    assert "acme-parser" not in audit
    assert "crafted request" not in audit
    excerpt = result.candidate.excerpts[0]
    assert advisory.sources[0].content[excerpt.byte_start:excerpt.byte_end] == excerpt.quote.encode()
    bad = result.model_copy(update={"candidate": result.candidate.model_copy(update={
        "excerpts": (excerpt.model_copy(update={"quote": "fabricated impact"}),)})})
    with pytest.raises(ValueError, match="excerpt"):
        verify_investigation(advisory, bad, now=NOW)


def test_conflict_remains_conflicting_and_unsupported_positive_abstains():
    advisory, response = sample(3)
    response["proposed_outcome"] = "affected"
    result = investigate(advisory, ScriptedProvider(response), now=NOW)
    assert result.candidate.reportable_outcome == "conflicting"
    assert "source-disagreement-preserved" in result.check.reason_codes
    assert {s.outcome for s in result.candidate.source_dispositions} == {"affected", "unaffected"}
    advisory, response = sample(5)
    response["proposed_outcome"] = "affected"
    result = investigate(advisory, ScriptedProvider(response), now=NOW)
    assert result.candidate.reportable_outcome == "unknown"
    assert result.check.status == "needs-evidence"


@pytest.mark.parametrize("mutation", [
    lambda r: r["claims"][0].update(source_id="S99"),
    lambda r: r["claims"][0].update(quote="fabricated remote execution"),
    lambda r: r.update(extra="unauthorized"),
])
def test_invalid_model_claim_is_rejected(mutation):
    advisory, response = sample()
    mutation(response)
    result = investigate(advisory, ScriptedProvider(response), now=NOW)
    assert result.check.status == "rejected"
    assert result.candidate.reportable_outcome == "unknown"
    assert result.candidate.excerpts == ()


def test_live_provider_is_inert_without_exact_authorization(monkeypatch):
    advisory, _ = sample()
    called = []
    monkeypatch.setattr("httpx.Client.stream", lambda *a, **k: called.append(True))
    with pytest.raises(PermissionError, match="authorization"):
        investigate(advisory, OpenAIProvider(), now=NOW)
    assert not called
    auth = Authorization(model="gpt-4.1-mini-2025-04-14", corpus_sha256="a" * 64,
                         spending_cap_usd=Decimal("0.001"),
                         input_usd_per_million=Decimal("1"),
                         output_usd_per_million=Decimal("4"))
    with pytest.raises(PermissionError, match="authorization"):
        investigate(advisory, OpenAIProvider(auth), authorization=auth,
                    ledger=SpendLedger(auth), corpus_sha256="b" * 64, now=NOW)
    assert not called
    with pytest.raises(ValueError, match="cap"):
        investigate(advisory, OpenAIProvider(auth), authorization=auth,
                    ledger=SpendLedger(auth),
                    corpus_sha256="a" * 64, now=NOW)
    assert not called


def test_shared_spend_ledger_limits_multiple_live_calls_without_network():
    advisory, response = sample()
    auth = Authorization(model="test-live", corpus_sha256="a" * 64,
                         spending_cap_usd=Decimal("0.03"),
                         input_usd_per_million=Decimal("1"),
                         output_usd_per_million=Decimal("4"))
    ledger = SpendLedger(auth)

    class InertLive:
        live = True
        model = "test-live"
        calls = 0

        def complete(self, instructions, payload, limits):
            from aegis.intelligence.investigator import ModelReply
            self.calls += 1
            return ModelReply(content=json.dumps(response), provider="inert-live",
                              model=self.model, input_tokens=12_000, output_tokens=512)

    provider = InertLive()
    for _ in range(2):
        result = investigate(advisory, provider, authorization=auth, ledger=ledger,
                             corpus_sha256="a" * 64, now=NOW)
        assert result.candidate.reportable_outcome == "affected"
    assert provider.calls == 2
    with pytest.raises(ValueError, match="cap"):
        investigate(advisory, provider, authorization=auth, ledger=ledger,
                    corpus_sha256="a" * 64, now=NOW)
    assert provider.calls == 2


def test_budgets_and_versioned_input_are_strict():
    advisory, response = sample()
    body = json.loads(advisory.sources[0].content)
    body["summary"] = "A" * 2_000
    long_source = snapshot(advisory.sources[0].kind, advisory.sources[0].uri,
                           json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
                           retrieved_at=NOW)
    advisory = advisory.model_copy(update={"sources": (long_source,)})
    with pytest.raises(ValueError, match="input budget"):
        investigate(advisory, ScriptedProvider(response),
                    limits=Limits(max_input_bytes=1_000), now=NOW)
    with pytest.raises(Exception):
        AdvisoryInput.model_validate({**advisory.model_dump(), "schema_version": "other"})


def test_provider_deadline_and_output_limit_fail_closed():
    advisory, response = sample()

    class SlowProvider(ScriptedProvider):
        def complete(self, instructions, payload, limits):
            time.sleep(0.01)
            return super().complete(instructions, payload, limits)

    late = investigate(advisory, SlowProvider(response),
                       limits=Limits(timeout_seconds=0.001), now=NOW)
    assert late.check.status == "rejected"
    assert late.candidate.reportable_outcome == "unknown"
    response["uncertainties"] = ["x" * 1_000]
    oversized = investigate(advisory, ScriptedProvider(response),
                            limits=Limits(max_output_bytes=256), now=NOW)
    assert oversized.check.status == "rejected"
    assert oversized.candidate.reportable_outcome == "unknown"
