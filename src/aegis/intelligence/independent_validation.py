"""Separate read-only scorer for the validator-owned sealed advisory labels."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


_MANIFEST_SHA256 = "20a3a37da8f941f17e6db514d1437d8d6575140e2e3bde61fc2cad9c6d4a234b"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_offline_report(root: Path, report: dict) -> dict:
    """Score output without importing the baseline or accepting provider supplied labels."""
    root = root.resolve()
    manifest_raw = (root / "fixtures/phase-next-alpha-ai/seal-manifest.json").read_bytes()
    if _sha(manifest_raw) != _MANIFEST_SHA256:
        raise ValueError("independent label manifest changed")
    manifest = json.loads(manifest_raw)
    old_raw = (root / "fixtures/phase-next-ai-holdout-v1.json").read_bytes()
    new_raw = (root / "fixtures/phase-next-alpha-ai/holdout-v1.json").read_bytes()
    if _sha(old_raw) != manifest["existing_corpus_sha256"] or _sha(new_raw) != manifest["corpus_sha256"]:
        raise ValueError("independent labels changed")
    cases = json.loads(old_raw)["cases"] + json.loads(new_raw)["cases"]
    if len(cases) != 36 or len({c["id"] for c in cases}) != 36:
        raise ValueError("independent case denominator changed")
    sealed_sources = {s["id"]: s for s in manifest["sources"]}
    for case in json.loads(new_raw)["cases"]:
        for source in case["sources"]:
            path = (root / source["raw_path"]).resolve()
            if not path.is_relative_to((root / "fixtures/phase-next-alpha-ai/sources").resolve()):
                raise ValueError("source path escaped fixture root")
            raw = path.read_bytes()
            seal = sealed_sources[source["id"]]
            if _sha(raw) != seal["sha256"] or len(raw) != seal["bytes"] or raw.decode().rstrip("\n") != source["text"]:
                raise ValueError("independent source changed")
    trials = report.get("trials", [report])
    if not isinstance(trials, list) or not trials:
        raise ValueError("missing trials")
    scores = []
    for trial in trials:
        rows = trial["rows"]
        if len(rows) != 36 or {r["id"] for r in rows} != {c["id"] for c in cases}:
            raise ValueError("trial case denominator changed")
        indexed = {r["id"]: r for r in rows}
        if len(indexed) != len(rows):
            raise ValueError("duplicate result row")
        detail = []
        for case in cases:
            row = indexed[case["id"]]
            expected = case["expected"]
            if row["expected"] != expected:
                raise ValueError("result label disagrees with sealed oracle")
            source_ids = {s["id"] for s in case["sources"]}
            citations = set(row["citations"])
            bad_citations = sorted(citations - source_ids)
            missing_required = sorted(set(case.get("required_citations", [])) - citations)
            if row["status"] not in {"completed", "inconclusive"}:
                raise ValueError("invalid result status")
            if row["baseline"] not in {"affected", "unaffected", "unknown"}:
                raise ValueError("invalid baseline decision")
            raw_point = row.get("raw_point")
            if raw_point and raw_point.get("support") != "unchecked":
                raise ValueError("raw model point was promoted")
            if row.get("positive_points_emitted", 0) or row.get("unsupported_positive_points_emitted", 0):
                raise ValueError("positive model point was emitted")
            detail.append({"id": case["id"], "stratum": case["stratum"], "expected": expected,
                           "decision": row["baseline"], "status": row["status"],
                           "exact": row["status"] == "completed" and row["baseline"] == expected,
                           "bad_citations": bad_citations, "missing_required_citations": missing_required,
                           "reason_codes": row["reasons"]})
        eligible = [d for d in detail if d["status"] == "completed"]
        affected = [d for d in eligible if d["expected"] == "affected"]
        positive = [d for d in eligible if d["decision"] == "affected"]
        scores.append({"planned": 36, "observed": len(detail), "eligible": len(eligible),
                       "inconclusive": len(detail) - len(eligible),
                       "exact": sum(d["exact"] for d in eligible),
                       "true_positive": sum(d["expected"] == "affected" for d in positive),
                       "false_positive": sum(d["expected"] != "affected" for d in positive),
                       "false_negative_including_abstention": sum(d["decision"] != "affected" for d in affected),
                       "correct_abstention": sum(d["decision"] == "unknown" and d["expected"] == "unknown" for d in eligible),
                       "wrong_abstention": sum(d["decision"] == "unknown" and d["expected"] != "unknown" for d in eligible),
                       "citation_id_errors": sum(bool(d["bad_citations"] or d["missing_required_citations"]) for d in detail),
                       "rows": detail})
    return {"schema_version": "phase5a-independent-score-v1",
            "label_owner": "independent validation lane, sealed before implementation",
            "label_manifest_sha256": _MANIFEST_SHA256,
            "source_authenticity": "synthetic fixture roles only",
            "semantic_citation_entailment": "unverified",
            "model_inference": "skipped",
            "trials": scores}
