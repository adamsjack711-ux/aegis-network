"""Reproducible labeled comparison; scripted provider results are not model evidence."""

import json
import hashlib
from pathlib import Path

from .baseline import assess, normalize
from .feeds import snapshot
from .models import Asset
from .research import FixtureProvider, JSONProvider, research


def evaluate(corpus: Path, provider: JSONProvider | None = None) -> dict:
    raw_corpus = corpus.read_bytes()
    cases = json.loads(raw_corpus)
    manifest_path = corpus.with_name(corpus.name.replace("_cases.json", "_manifest.json"))
    raw_manifest = manifest_path.read_bytes()
    manifest = json.loads(raw_manifest)
    if manifest["corpus_sha256"] != hashlib.sha256(raw_corpus).hexdigest() or len(manifest["cases"]) != len(cases):
        raise ValueError("corpus manifest mismatch")
    rows = []
    for case, declared in zip(cases, manifest["cases"], strict=True):
        if declared["id"] != case["id"] or declared["gold"] != case["gold"]:
            raise ValueError("corpus label mismatch")
        sources = [snapshot(item["kind"], item["uri"],
                            json.dumps(item["body"], sort_keys=True, separators=(",", ":")).encode(),
                            retrieved_at=__import__("datetime").datetime.fromisoformat(item["retrieved_at"]))
                   for item in case["sources"]]
        if [source.sha256 for source in sources] != declared["source_sha256"]:
            raise ValueError("corpus source digest mismatch")
        claims = tuple(claim for source in sources for claim in normalize(source))
        asset = Asset.model_validate(case["asset"])
        baseline = assess(asset, claims, case["vulnerability_id"])
        result = research(asset, claims, case["vulnerability_id"], provider or FixtureProvider(case["fixture_response"]),
                          input_usd_per_million=case.get("input_usd_per_million", 0),
                          output_usd_per_million=case.get("output_usd_per_million", 0))
        rows.append({"id": case["id"], "gold": case["gold"], "baseline": baseline.outcome,
                     "ai": result.candidate_outcome, "latency_ms": result.latency_ms,
                     "input_tokens": result.usage.input_tokens, "output_tokens": result.usage.output_tokens,
                     "estimated_cost_usd": result.estimated_cost_usd,
                     "citation_valid": all(fact in result.citations for point in
                                           (*result.points, *result.ambiguities, *result.prerequisites,
                                            result.local_explanation) for fact in point.fact_ids),
                     "unsupported_claims": case.get("fixture_unsupported_claims", 0) if provider is None else None})

    def metrics(field):
        binary = [row for row in rows if row["gold"] in {"affected", "unaffected"}]
        tp = sum(row["gold"] == "affected" and row[field] == "affected" for row in binary)
        tn = sum(row["gold"] == "unaffected" and row[field] == "unaffected" for row in binary)
        fp = sum(row["gold"] == "unaffected" and row[field] == "affected" for row in binary)
        fn = sum(row["gold"] == "affected" and row[field] == "unaffected" for row in binary)
        conclusive = sum(row[field] in {"affected", "unaffected"} for row in rows)
        return {"correct": sum(row[field] == row["gold"] for row in rows),
                "true_positive": tp, "true_negative": tn,
                "eligible_binary": len(binary), "coverage": conclusive / len(rows),
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
                "false_positive": fp,
                "false_negative": fn,
                "correct_abstention": sum(row["gold"] in {"unknown", "conflicting"}
                                          and row[field] == row["gold"] for row in rows),
                "version_range_accuracy": {"correct": sum(row[field] == row["gold"] for row in binary),
                                           "denominator": len(binary)}}
    base, ai = metrics("baseline"), metrics("ai")
    latencies = sorted(row["latency_ms"] for row in rows)
    def percentile(percent):
        index = (len(latencies) - 1) * percent
        lower = int(index)
        upper = min(lower + 1, len(latencies) - 1)
        return round(latencies[lower] + (latencies[upper] - latencies[lower]) * (index - lower), 3)
    return {"schema_version": "phase5a-eval-v1", "corpus_sha256": hashlib.sha256(raw_corpus).hexdigest(),
            "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
            "provider": "scripted-fixture" if provider is None else "external-model",
            "cases": rows, "baseline": base, "ai": ai,
            "improvement_correct_cases": ai["correct"] - base["correct"],
            "unsupported_claims": sum(row["unsupported_claims"] for row in rows) if provider is None else None,
            "citation_valid": sum(row["citation_valid"] for row in rows),
            "citation_total": len(rows),
            "latency_ms_total": round(sum(row["latency_ms"] for row in rows), 3),
            "latency_ms_p50": percentile(0.5), "latency_ms_p95": percentile(0.95),
            "tokens": {"input": sum(row["input_tokens"] for row in rows),
                       "output": sum(row["output_tokens"] for row in rows)},
            "estimated_cost_usd": round(sum(row["estimated_cost_usd"] or 0 for row in rows), 8),
            "limitation": ("Scripted fixture output tests controls, not real model accuracy. "
                           "Unsupported-claim labels are manual." if provider is None else
                           "Model prose requires independent human adjudication for unsupported claims; "
                           "no automatic unsupported-claim score is asserted.")}
