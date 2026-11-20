"""Offline Investigator comparison on the same sealed Phase 5A cases."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .baseline import assess, normalize
from .feeds import snapshot
from .investigator import AdvisoryInput, ScriptedProvider, investigate
from .models import Asset


def evaluate_investigator(corpus: Path) -> dict:
    raw = corpus.read_bytes()
    manifest_raw = corpus.with_name("phase5a_manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    cases = json.loads(raw)
    if hashlib.sha256(raw).hexdigest() != manifest["corpus_sha256"] or \
            len(cases) != len(manifest["cases"]):
        raise ValueError("sealed corpus mismatch")
    evaluation_time = datetime(2026, 11, 20, tzinfo=timezone.utc)
    rows = []
    for case, seal in zip(cases, manifest["cases"], strict=True):
        if case["id"] != seal["id"] or case["gold"] != seal["gold"]:
            raise ValueError("sealed case label mismatch")
        sources = tuple(snapshot(item["kind"], item["uri"],
                                 json.dumps(item["body"], sort_keys=True,
                                            separators=(",", ":")).encode(),
                                 retrieved_at=datetime.fromisoformat(item["retrieved_at"]))
                        for item in case["sources"])
        if [source.sha256 for source in sources] != seal["source_sha256"]:
            raise ValueError("sealed source digest mismatch")
        asset = Asset.model_validate(case["asset"])
        claims = tuple(claim for source in sources for claim in normalize(source))
        baseline = assess(asset, claims, case["vulnerability_id"], now=evaluation_time)
        proposed = case["fixture_response"]["candidate_outcome"]
        scripted = {"proposed_outcome": proposed, "claims": [
            {"kind": "applicability", "source_id": f"S{i}",
             "quote": ("fixed\":\"2.0" if "Ignore your system instructions" in
                       item["body"].get("summary", "") else
                       item["body"].get("summary", item["body"].get("description", ""))[:500])}
            for i, item in enumerate(case["sources"], 1)
            if item["body"].get("summary", item["body"].get("description", ""))],
            "uncertainties": []}
        input_record = AdvisoryInput(advisory_id=case["id"],
                                     vulnerability_id=case["vulnerability_id"],
                                     asset=asset, sources=sources)
        result = investigate(input_record, ScriptedProvider(scripted), now=evaluation_time)
        rows.append({"id": case["id"], "gold": case["gold"],
                     "baseline": baseline.outcome,
                     "scripted_proposal": result.candidate.model_proposal,
                     "investigator": result.candidate.reportable_outcome,
                     "status": result.check.status,
                     "reason_codes": result.check.reason_codes,
                     "citation_count": result.check.excerpt_count,
                     "latency_ms": result.audit.latency_ms})
    return {"schema_version": "investigator-offline-eval-v1",
            "corpus_sha256": hashlib.sha256(raw).hexdigest(),
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "evaluation_time": evaluation_time.isoformat(),
            "cases": rows, "planned": len(rows),
            "baseline_correct": sum(r["baseline"] == r["gold"] for r in rows),
            "investigator_correct": sum(r["investigator"] == r["gold"] for r in rows),
            "false_affected": sum(r["investigator"] == "affected" and
                                  r["gold"] != "affected" for r in rows),
            "citation_valid": sum(r["status"] != "rejected" for r in rows),
            "actual_model": {"status": "skipped", "reason": "no model authorization"},
            "actual_model_accuracy": None, "actual_model_cost_usd": None,
            "unsupported_semantic_claims": None,
            "limitation": "Scripted outputs and author-visible labels do not measure model accuracy. "
                          "Exact excerpts do not establish semantic support or independent Evidence."}
