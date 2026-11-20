"""Offline-first comparison of deterministic, raw hypothesis, and checked outcomes."""

import hashlib
import json
import time
from datetime import datetime
from pathlib import Path

from .baseline import assess, normalize
from .feeds import snapshot
from .models import Asset
from .research import FixtureProvider, INSTRUCTIONS, JSONProvider, research


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _score(rows: list[dict], key: str) -> dict:
    eligible = [r for r in rows if r["gold"] in {"affected", "unaffected"}]
    tp = sum(r["gold"] == "affected" and r.get(key) == "affected" for r in eligible)
    fp = sum(r["gold"] != "affected" and r.get(key) == "affected" for r in rows)
    fn = sum(r["gold"] == "affected" and r.get(key) != "affected" for r in rows)
    abstain = sum(r.get(key) in {"unknown", "conflicting"} for r in rows)
    missing = sum(r.get(key) is None for r in rows)
    return {"denominator": len(rows), "correct": sum(r.get(key) == r["gold"] for r in rows),
            "affected_gold": sum(r["gold"] == "affected" for r in rows),
            "true_positive": tp, "false_positive": fp, "false_negative_including_abstention": fn,
            "abstentions": abstain, "failures_without_outcome": missing,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall_including_abstention": tp / (tp + fn) if tp + fn else None,
            "exact_accuracy": sum(r.get(key) == r["gold"] for r in rows) / len(rows) if rows else None}


def _latency(values: list[float]) -> dict:
    values = sorted(values)
    if not values:
        return {"count": 0, "p50_ms": None, "p95_ms": None}
    def quantile(q):
        p = (len(values) - 1) * q
        i = int(p)
        return round(values[i] + (values[min(i + 1, len(values) - 1)] - values[i]) * (p - i), 3)
    return {"count": len(values), "p50_ms": quantile(.5), "p95_ms": quantile(.95)}


def evaluate_model(corpus: Path, *, mode: str = "deterministic",
                   provider: JSONProvider | None = None,
                   input_usd_per_million: float | None = None,
                   output_usd_per_million: float | None = None) -> dict:
    if mode not in {"deterministic", "scripted", "model"} or (mode == "model") != (provider is not None):
        raise ValueError("invalid evaluation mode or provider")
    if mode == "model" and (input_usd_per_million is None or output_usd_per_million is None or
                            input_usd_per_million < 0 or output_usd_per_million < 0):
        raise ValueError("model run requires explicit nonnegative token prices")
    raw = corpus.read_bytes()
    cases = json.loads(raw)
    manifest_bytes = corpus.with_name(corpus.name.replace("_cases.json", "_manifest.json")).read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest["corpus_sha256"] != _digest(raw) or len(cases) != len(manifest["cases"]):
        raise ValueError("corpus manifest mismatch")
    now = datetime.fromisoformat(manifest["evaluation_at"])
    rows = []
    for case, label in zip(cases, manifest["cases"], strict=True):
        if case["id"] != label["id"] or case["gold"] != label["gold"]:
            raise ValueError("corpus label mismatch")
        sources = tuple(snapshot(item["kind"], item["uri"],
                                 json.dumps(item["body"], sort_keys=True, separators=(",", ":")).encode(),
                                 retrieved_at=datetime.fromisoformat(item["retrieved_at"]))
                        for item in case["sources"])
        if [s.sha256 for s in sources] != label["source_sha256"]:
            raise ValueError("corpus source digest mismatch")
        claims = tuple(claim for source in sources for claim in normalize(source))
        asset = Asset.model_validate(case["asset"])
        start = time.perf_counter()
        baseline = assess(asset, claims, case["vulnerability_id"], now=now)
        row = {"id": case["id"], "gold": case["gold"], "label_owner": label["label_owner"],
               "baseline": baseline.outcome, "baseline_latency_ms": round((time.perf_counter() - start) * 1000, 3),
               "raw_model": None, "checked": None, "model_error": None,
               "model_latency_ms": None, "input_tokens": None, "output_tokens": None,
               "estimated_cost_usd": None, "point_count": None, "positive_points_unchecked": None,
               "source_binding": None, "disposition": None}
        if mode != "deterministic":
            selected = provider if provider is not None else FixtureProvider(case["fixture_response"])
            try:
                result = research(asset, claims, case["vulnerability_id"], selected,
                                  source_snapshots=sources, now=now,
                                  input_usd_per_million=input_usd_per_million,
                                  output_usd_per_million=output_usd_per_million)
                points = result.check.point_support
                row.update(raw_model=result.model_candidate_outcome, checked=result.candidate_outcome,
                           model_latency_ms=result.latency_ms, input_tokens=result.usage.input_tokens,
                           output_tokens=result.usage.output_tokens,
                           estimated_cost_usd=result.estimated_cost_usd,
                           point_count=len(points),
                           positive_points_unchecked=len(points) if result.model_candidate_outcome == "affected" else 0,
                           source_binding=result.check.source_binding,
                           disposition=result.check.disposition,
                           provider=result.provider, model=result.model,
                           provider_version=result.provider_version,
                           reason_codes=list(result.check.reason_codes))
            except (ValueError, TypeError, PermissionError, TimeoutError) as exc:
                row["model_error"] = type(exc).__name__ + ": " + str(exc)
        rows.append(row)
    baseline = _score(rows, "baseline")
    raw_model = _score(rows, "raw_model") if mode != "deterministic" else None
    checked = _score(rows, "checked") if mode != "deterministic" else None
    return {"schema_version": "phase5a-model-eval-v1", "mode": mode,
            "real_model_inference_executed": mode == "model" and all(r["model_error"] is None for r in rows),
            "real_model_evaluation_verified": False,
            "corpus_sha256": _digest(raw), "manifest_sha256": _digest(manifest_bytes),
            "prompt_sha256": _digest(INSTRUCTIONS.encode()), "prompt_instructions": INSTRUCTIONS,
            "prompt_version": "2", "payload_template_revision": "2",
            "research_code_sha256": _digest(Path(__file__).with_name("research.py").read_bytes()),
            "evaluation_at": manifest["evaluation_at"],
            "configuration": {"max_input_bytes": 10000, "max_output_tokens": 700,
                              "max_source_age_days": 7,
                              "input_usd_per_million": input_usd_per_million,
                              "output_usd_per_million": output_usd_per_million},
            "cases": rows, "baseline": baseline, "raw_model": raw_model, "checked": checked,
            "raw_delta_correct_cases": raw_model["correct"] - baseline["correct"] if raw_model else None,
            "checked_delta_correct_cases": checked["correct"] - baseline["correct"] if checked else None,
            "raw_unsupported_positive_outcomes": raw_model["false_positive"] if raw_model else None,
            "baseline_latency": _latency([r["baseline_latency_ms"] for r in rows]),
            "model_latency": _latency([r["model_latency_ms"] for r in rows if r["model_latency_ms"] is not None]),
            "usage": {"input_tokens": sum(r["input_tokens"] or 0 for r in rows),
                      "output_tokens": sum(r["output_tokens"] or 0 for r in rows),
                      "estimated_cost_usd": round(sum(r["estimated_cost_usd"] or 0 for r in rows), 8)
                      if mode == "model" else None},
            "unsupported_assertions_adjudicated": None,
            "positive_points_unchecked": sum(r["positive_points_unchecked"] or 0 for r in rows),
            "model_errors": sum(r["model_error"] is not None for r in rows),
            "meaningful_improvement_verified": False,
            "limitations": ("All model prose remains unchecked. Citation IDs do not establish semantic support. "
                            "Author labels need independent review; scripted output is not real inference. "
                            "Model cost is estimated from configured rates, not provider billing.")}
