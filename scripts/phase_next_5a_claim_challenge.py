"""Independent offline checks of a clean exact private Phase 5A research pin."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-pin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.candidate_root.resolve()
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip()
    if actual != args.source_pin or dirty:
        raise ValueError("candidate is not the clean exact requested pin")
    sys.path.insert(0, str(root / "src"))
    from aegis.artifact import SignedFinding
    from aegis.intelligence import Asset, normalize, snapshot
    from aegis.intelligence.models import Claim, SourceRef, VersionClaim
    from aegis.intelligence.research import FixtureProvider, ResearchResult, research
    from pydantic import ValidationError

    cases: list[dict] = []

    def add(name: str, passed: bool, observed: dict) -> None:
        cases.append({"case": name, "status": "pass" if passed else "fail", "observed": observed})

    def draft(outcome: str, prose: str) -> dict:
        point = {"text": prose, "fact_ids": ["F1"]}
        return {"candidate_outcome": outcome, "points": [point], "ambiguities": [],
                "prerequisites": [], "local_explanation": point, "lab_experiments": []}

    ref = SourceRef(kind="vendor-ghsa", acquisition="fixture", uri="https://fixture.invalid/H09",
                    retrieved_at=datetime.now(timezone.utc),
                    sha256=sha256(b"No affected versions confirmed").hexdigest(), pointer="/summary")
    unconfirmed = Claim(vulnerability_id="AEGIS-ADV-109", identity_kind="purl",
                        identity="pkg:deb/hemlock", versions=(VersionClaim(scheme="none"),),
                        confidence="fixture", missing=("affected-versions",),
                        summary="No affected versions, package ecosystem, or fix have been confirmed.",
                        reference=ref)
    asset = Asset(asset_id="holdout-H09", identity_kind="purl", identity="pkg:deb/hemlock",
                  version="5.0-2")
    unsupported = research(asset, (unconfirmed,), unconfirmed.vulnerability_id,
                           FixtureProvider(draft("affected", "Confirmed affected 5.0-2 with remote execution.")))
    u = unsupported.model_dump(mode="json")
    check = u["check"]
    expected = (u["schema_version"] == "phase5a-research-v2" and
                u["candidate_outcome"] == check["reportable_outcome"] == "unknown" and
                u["model_candidate_outcome"] == "affected" and
                check["disposition"] == "needs-evidence" and
                {"source-binding-unavailable", "model-exceeds-deterministic-evidence"}.issubset(
                    check["reason_codes"]) and
                all(point["support"] == "unchecked" for point in check["point_support"]) and
                "points" not in u and "local_explanation" not in u)
    add("original_unsupported_alternative_disposition", expected,
        {"reportable": u["candidate_outcome"], "model": u["model_candidate_outcome"],
         "check": check, "raw_hypothesis": u["raw_hypothesis"],
         "top_level_points_present": "points" in u})

    body = {"id": "OSV-2099-101", "summary": "Version list is present; no impact type is stated.",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "sample"}, "versions": ["1.5"]}]}
    source = snapshot("osv", "https://fixture.invalid/OSV-2099-101", json.dumps(body).encode())
    claims = normalize(source)
    supported_asset = Asset(asset_id="lab-1", identity_kind="purl", identity="pkg:pypi/sample",
                            version="1.5")
    consistent = research(supported_asset, claims, claims[0].vulnerability_id,
                          FixtureProvider(draft("affected", "Confirmed remote execution at 1.5.")),
                          source_snapshots=(source,))
    c = consistent.model_dump(mode="json")
    expected = (c["candidate_outcome"] == "affected" and
                c["check"]["source_binding"] == "digest-checked" and
                c["check"]["disposition"] == "research-consistent" and
                "unsupported-free-text-claim" in c["check"]["reason_codes"] and
                all(point["support"] == "unchecked" for point in c["check"]["point_support"]) and
                "points" not in c and "local_explanation" not in c)
    add("matching_version_does_not_validate_fabricated_impact", expected,
        {"reportable": c["candidate_outcome"], "check": c["check"],
         "raw_hypothesis": c["raw_hypothesis"], "top_level_points_present": "points" in c})

    for name, payload in (
        ("reject_v1", {**c, "schema_version": "phase5a-research-v1"}),
        ("reject_versionless", {key: value for key, value in c.items() if key != "schema_version"}),
        ("reject_v1_top_level_prose", {**c, "schema_version": "phase5a-research-v1",
                                       "points": c["raw_hypothesis"]["points"]}),
    ):
        try:
            ResearchResult.model_validate_json(json.dumps(payload))
        except ValidationError as exc:
            add(name, True, {"rejected_by": type(exc).__name__})
        else:
            add(name, False, {"accepted": True})
    parsed = ResearchResult.model_validate_json(json.dumps(c))
    add("accept_exact_v2", parsed.check is not None and parsed.candidate_outcome == "affected",
        {"schema_version": parsed.schema_version, "reportable": parsed.candidate_outcome})

    # This is an additional reader-integrity challenge, distinct from v1 rejection.
    for name, payload in (
        ("reject_v2_missing_check", {**u, "check": None}),
        ("reject_v2_forged_reportable_outcome", {**u, "candidate_outcome": "affected"}),
    ):
        try:
            parsed = ResearchResult.model_validate_json(json.dumps(payload))
        except ValidationError as exc:
            add(name, True, {"rejected_by": type(exc).__name__})
        else:
            add(name, False, {"accepted": True, "reportable": parsed.candidate_outcome,
                              "check_reportable": parsed.check.reportable_outcome if parsed.check else None})

    tampered = json.loads(json.dumps(c))
    tampered["raw_hypothesis"]["points"][0]["text"] = "Invented remote execution."
    try:
        ResearchResult.model_validate_json(json.dumps(tampered))
    except ValidationError as exc:
        add("reject_unrecomputed_raw_prose_tamper", True, {"rejected_by": type(exc).__name__})
    else:
        add("reject_unrecomputed_raw_prose_tamper", False, {"accepted": True})

    # A malicious producer can create internally consistent private bytes without
    # owning the cited source or a verifier key. This is a boundary observation,
    # not a demand that an unkeyed digest authenticate anything.
    forged = json.loads(json.dumps(u))
    forged["baseline_outcome"] = "affected"
    forged["candidate_outcome"] = "affected"
    forged["check"].update({"source_binding": "digest-checked",
                            "source_snapshot_digests": ["0" * 64],
                            "deterministic_outcome": "affected",
                            "disposition": "research-consistent",
                            "reportable_outcome": "affected",
                            "reason_codes": ["unsupported-free-text-claim"]})
    forged["check"].pop("research_result_digest")
    forged["check"]["research_result_digest"] = sha256(
        json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    try:
        accepted = ResearchResult.model_validate_json(json.dumps(forged))
    except ValidationError as exc:
        add("self_consistent_unkeyed_forgery_boundary", False,
            {"rejected_by": type(exc).__name__, "expected": "parser accepts self-consistent private bytes"})
    else:
        add("self_consistent_unkeyed_forgery_boundary",
            accepted.candidate_outcome == "affected" and accepted.independently_verified is False,
            {"accepted": True, "reportable": accepted.candidate_outcome,
             "independently_verified": accepted.independently_verified,
             "source_binding": accepted.check.source_binding,
             "interpretation": "internal consistency only; no source authentication"})

    for name, payload in (("unsupported", u), ("matching_impact", c)):
        try:
            SignedFinding.model_validate(payload)
        except ValidationError as exc:
            add("no_signed_finding_promotion_" + name, True, {"rejected_by": type(exc).__name__})
        else:
            add("no_signed_finding_promotion_" + name, False, {"accepted": True})

    result = {"source_pin": actual, "topology": "offline one-process scripted provider",
              "source_sha256": {"research.py": sha256((root / "src/aegis/intelligence/research.py").read_bytes()).hexdigest()},
              "cases": cases, "summary": {status: sum(row["status"] == status for row in cases)
                                   for status in ("pass", "fail", "inconclusive", "skipped")},
              "limitations": ["Scripted provider is not a real model or source authentication",
                              "No actuator or Mesh service was exercised"]}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()
