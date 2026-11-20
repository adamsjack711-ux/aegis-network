"""Private, offline research checks; no signed or enforcement adapter is involved."""

import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from aegis.artifact import SignedFinding
from aegis.intelligence import Asset, assess, normalize, snapshot
from aegis.intelligence.models import Claim, SourceRef, VersionClaim
from aegis.intelligence.research import FixtureProvider, research
from pydantic import ValidationError
import pytest


def draft(outcome, text):
    point = {"text": text, "fact_ids": ["F1"]}
    return {"candidate_outcome": outcome, "points": [point], "ambiguities": [],
            "prerequisites": [], "local_explanation": point, "lab_experiments": []}


def source_case(*, withdrawn=False, age_days=0, versions=None):
    body = {"id": "OSV-2099-101", "summary": "A version predicate is listed.",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "sample"},
                          "versions": versions if versions is not None else ["1.5"]}]}
    if withdrawn:
        body["withdrawn"] = "2026-11-19T00:00:00Z"
    raw = json.dumps(body).encode()
    source = snapshot("osv", "https://fixture.invalid/OSV-2099-101", raw,
                      retrieved_at=datetime.now(timezone.utc) - timedelta(days=age_days))
    claims = normalize(source)
    asset = Asset(asset_id="lab-1", identity_kind="purl", identity="pkg:pypi/sample", version="1.5")
    return asset, claims, source


def test_original_unsupported_positive_is_explicitly_unknown_and_unchecked():
    now = datetime.now(timezone.utc)
    ref = SourceRef(kind="vendor-ghsa", acquisition="fixture", uri="https://fixture.invalid/H09",
                    retrieved_at=now, sha256=sha256(b"No affected versions confirmed").hexdigest(),
                    pointer="/summary")
    claim = Claim(vulnerability_id="AEGIS-ADV-109", identity_kind="purl",
                  identity="pkg:deb/hemlock", versions=(VersionClaim(scheme="none"),),
                  confidence="fixture", missing=("affected-versions",),
                  summary="No affected versions, package ecosystem, or fix have been confirmed.",
                  reference=ref)
    asset = Asset(asset_id="holdout-H09", identity_kind="purl", identity="pkg:deb/hemlock",
                  version="5.0-2")
    result = research(asset, (claim,), claim.vulnerability_id, FixtureProvider(
        draft("affected", "Confirmed affected 5.0-2 with remote execution.")))
    assert result.baseline_outcome == "unknown"
    assert result.candidate_outcome == result.check.reportable_outcome == "unknown"
    assert result.model_candidate_outcome == "affected"
    assert result.check.disposition == "needs-evidence"
    assert "model-exceeds-deterministic-evidence" in result.check.reason_codes
    assert "source-binding-unavailable" in result.check.reason_codes
    assert all(point.support == "unchecked" for point in result.check.point_support)
    assert result.raw_hypothesis.points[0].support == "unchecked"
    assert result.raw_hypothesis.local_explanation.support == "unchecked"
    public = result.model_dump(mode="json")
    assert "points" not in public and "local_explanation" not in public
    assert public["raw_hypothesis"]["points"][0]["support"] == "unchecked"
    assert result.independently_verified is False
    with pytest.raises(ValidationError):
        SignedFinding.model_validate(result.model_dump(mode="json"))


def test_source_backed_version_outcome_does_not_verify_fabricated_impact():
    asset, claims, source = source_case()
    result = research(asset, claims, claims[0].vulnerability_id, FixtureProvider(
        draft("affected", "Confirmed affected 1.5 with remote execution.")),
        source_snapshots=(source,))
    assert assess(asset, claims, claims[0].vulnerability_id).outcome == "affected"
    assert result.candidate_outcome == "affected"
    assert result.check.disposition == "research-consistent"
    assert result.check.source_binding == "digest-checked"
    assert result.check.source_snapshot_digests == (source.sha256,)
    assert all(point.support == "unchecked" for point in result.check.point_support)
    assert all(point.support == "unchecked" for point in result.raw_hypothesis.points)
    assert "points" not in result.model_dump(mode="json")
    assert "unsupported-free-text-claim" in result.check.reason_codes


def test_source_binding_requires_exact_reparsed_claims():
    asset, claims, source = source_case()
    changed = claims[0].model_copy(update={"summary": "An invented source claim."})
    result = research(asset, (changed,), changed.vulnerability_id, FixtureProvider(
        draft("affected", "The version is affected.")), source_snapshots=(source,))
    assert result.candidate_outcome == "unknown"
    assert result.check.disposition == "needs-evidence"
    assert "source-binding-unavailable" in result.check.reason_codes


@pytest.mark.parametrize("withdrawn,age_days", [(True, 0), (False, 8)])
def test_withdrawn_or_stale_source_cannot_report_affected(withdrawn, age_days):
    asset, claims, source = source_case(withdrawn=withdrawn, age_days=age_days)
    result = research(asset, claims, claims[0].vulnerability_id, FixtureProvider(
        draft("affected", "Confirmed affected 1.5.")), source_snapshots=(source,))
    assert result.baseline_outcome == result.candidate_outcome == "unknown"
    assert result.check.disposition == "needs-evidence"
    assert "model-exceeds-deterministic-evidence" in result.check.reason_codes


def test_supported_negative_source_is_advisory_only():
    asset, claims, source = source_case(versions=["1.4"])
    result = research(asset, claims, claims[0].vulnerability_id, FixtureProvider(
        draft("unaffected", "Version 1.5 is safe against every attack.")),
        source_snapshots=(source,))
    assert result.candidate_outcome == "unaffected"
    assert result.check.disposition == "research-consistent"
    assert result.raw_hypothesis.points[0].support == "unchecked"
    assert result.independently_verified is False


def test_unsupported_version_and_mismatched_model_abstain():
    asset, claims, source = source_case(versions=[])
    result = research(asset, claims, claims[0].vulnerability_id, FixtureProvider(
        draft("affected", "Confirmed affected 1.5.")), source_snapshots=(source,))
    assert result.candidate_outcome == "unknown"
    assert result.check.disposition == "needs-evidence"
    asset, claims, source = source_case()
    result = research(asset, claims, claims[0].vulnerability_id, FixtureProvider(
        draft("unaffected", "Version 1.5 is safe.")), source_snapshots=(source,))
    assert result.baseline_outcome == "affected"
    assert result.candidate_outcome == "unknown"
    assert "model-contradicts-deterministic-evidence" in result.check.reason_codes
