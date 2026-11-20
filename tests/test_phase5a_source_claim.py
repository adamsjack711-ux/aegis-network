"""Byte- and field-level checks for private, non-authoritative source claims."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis.artifact import SignedFinding
from aegis.intelligence.alpha_eval import evaluate_alpha
from aegis.intelligence.source_claim import (AtomicSourceClaim, affirmative_effect, build_atomic_claim,
                                             exact_source_bytes, verify_atomic_claim)


ROOT = Path(__file__).parents[1]


def _case(case_id):
    report = evaluate_alpha(ROOT)
    return next(row for row in report["rows"] if row["id"] == case_id)


def test_atomic_claim_denominators_keep_conflicts_and_model_points_separate():
    report = evaluate_alpha(ROOT)
    assert report["schema_version"] == "phase5a-alpha-eval-v3"
    assert report["planned_cases"] == 36
    assert report["source_claims"] == {
        "attempted": 23, "emitted": 15, "positive_attempted": 10,
        "positive_emitted": 6, "effect_emitted": 1,
        "independently_semantic_adjudicated": 0, "authenticated_real_advisory": 0}
    assert report["scripted_provider"]["positive_points_attempted"] == 36
    assert report["scripted_provider"]["positive_points_emitted"] == 0
    conflict = next(r for r in report["rows"] if r["id"] == "C01-vendor-registry-conflict")
    assert len(conflict["source_claims_attempted"]) == 2
    assert conflict["source_claims_emitted"] == []


def test_effect_quote_requires_exact_current_source_and_affected_product():
    row = _case("B01-inclusive-lower")
    effect_data = next(c for c in row["source_claims_emitted"] if c["claim_kind"] == "effect")
    claim = AtomicSourceClaim.model_validate(effect_data)
    assert claim.quote == "availability degradation"
    assert claim.effect_type == "availability-degradation"
    assert claim.product_ecosystem == "pypi"
    assert claim.product_name == "maple-json"
    assert claim.asset_version == "1.2.0"
    assert claim.support == "fixture-parser-consistent"
    assert claim.independently_verified is False
    assert row["fixture_impact_observation"] == "availability degradation"
    with pytest.raises(ValidationError):
        SignedFinding.model_validate(effect_data)
    assert _case("U03-fabricated-impact")["fixture_impact_observation"] is None


def test_source_claim_rejects_tampered_bytes_locator_product_polarity_and_predicate():
    import json
    case = next(c for c in json.loads((ROOT / "fixtures/phase-next-alpha-ai/holdout-v1.json").read_text())["cases"]
                if c["id"] == "B01-inclusive-lower")
    source, asset = case["sources"][0], case["asset"]
    raw, _ = exact_source_bytes(ROOT, source)
    data = _case("B01-inclusive-lower")["source_claims_emitted"][0]
    claim = AtomicSourceClaim.model_validate(data)
    verify_atomic_claim(claim, raw, source, asset, polarity="affected", predicate="explicit-numeric-range")
    for invalid in (
        (claim, raw + b"tampered", source, asset, "affected", "explicit-numeric-range"),
        (claim.model_copy(update={"byte_start": 0}), raw, source, asset, "affected", "explicit-numeric-range"),
        (claim.model_copy(update={"product_name": "other"}), raw, source, asset, "affected", "explicit-numeric-range"),
        (claim.model_copy(update={"source_product_name": "other"}), raw, source, asset,
         "affected", "explicit-numeric-range"),
        (claim.model_copy(update={"polarity": "unaffected"}), raw, source, asset, "affected", "explicit-numeric-range"),
        (claim.model_copy(update={"version_predicate": "explicit-before-range"}), raw, source, asset,
         "affected", "explicit-numeric-range"),
        (claim, raw, {**source, "role": "unverified-blog"}, asset, "affected", "explicit-numeric-range"),
        (claim, raw, {**source, "retrieved_at": "2025-01-01T00:00:00Z"}, asset,
         "affected", "explicit-numeric-range"),
    ):
        with pytest.raises(ValueError):
            verify_atomic_claim(invalid[0], invalid[1], invalid[2], invalid[3],
                                polarity=invalid[4], predicate=invalid[5])


def test_withdrawn_stale_unknown_and_injected_impact_emit_no_claim():
    rows = {r["id"]: r for r in evaluate_alpha(ROOT)["rows"]}
    for case_id in ("W01-withdrawn-notice", "W02-stale-snapshot", "W03-no-affected-version",
                    "I03-json-role-spoof", "H09-hallucination-trap"):
        assert rows[case_id]["source_claims_emitted"] == []
    assert rows["I02-command-in-advisory"]["source_claims_emitted"][0]["claim_kind"] == "version-applicability"
    assert rows["I02-command-in-advisory"]["fixture_impact_observation"] is None


def test_effect_polarity_and_product_are_not_inferred_from_stray_phrase():
    asset = {"ecosystem": "pypi", "name": "maple-json", "version": "1.2.0"}
    assert affirmative_effect("PyPI maple-json 1.2.0 is affected. A crafted document can cause availability degradation.", asset)
    assert not affirmative_effect("PyPI maple-json 1.2.0 is affected. No availability degradation is known.", asset)
    assert not affirmative_effect("PyPI maple-json 1.2.0 is affected. A different product can cause availability degradation.", asset)
    assert not affirmative_effect("PyPI maple-json 1.2.0 is affected. npm other 1.0.0 can cause availability degradation.", asset)


def test_exact_val_r_quote_role_acquisition_and_unrelated_database_regressions():
    import json
    case = next(c for c in json.loads((ROOT / "fixtures/phase-next-alpha-ai/holdout-v1.json").read_text())["cases"]
                if c["id"] == "B01-inclusive-lower")
    source, asset = case["sources"][0], case["asset"]
    raw, _ = exact_source_bytes(ROOT, source)
    claim = AtomicSourceClaim.model_validate(_case("B01-inclusive-lower")["source_claims_emitted"][0])
    unrelated_quote = b"no code execution"
    start = raw.index(unrelated_quote)
    swapped = claim.model_copy(update={"byte_start": start, "byte_end": start + len(unrelated_quote),
                                       "source_locator": f"utf8-byte:{start}:{start + len(unrelated_quote)}",
                                       "quote": unrelated_quote.decode()})
    for invalid in (swapped, claim.model_copy(update={"source_role": "registry"}),
                    claim.model_copy(update={"acquisition": "pinned-inline-fixture"})):
        with pytest.raises(ValueError):
            verify_atomic_claim(invalid, raw, source, asset,
                                polarity="affected", predicate=claim.version_predicate)
    fabricated = {"id": "adversarial-inline", "role": "vendor", "text":
                  "PyPI maple-json 1.2.0 is affected. An unrelated database outage can cause availability degradation."}
    with pytest.raises(ValueError):
        build_atomic_claim(ROOT, fabricated, asset, polarity="affected",
                           predicate="explicit-affected-version", kind="effect")
    assert not affirmative_effect(fabricated["text"], asset)
