"""Private offline evaluation; synthetic sources cannot grant defense authority."""

from __future__ import annotations

import hashlib
import json
import random
import resource
import sys
import time
from pathlib import Path

from .alpha_eval import (_percentile, _source_decision, evaluate_alpha,
                         OfflineBudget, ScriptedStressProvider)
from .source_claim import build_atomic_claim, exact_source_bytes


V_CORPUS = "benchmarks/phase-next-r-validation/5a-r/retained-v01-v12.json"
V_SHA256 = "d7a728ba657920e6adffbf26004c39fccaefa16ab55053df5a399692113c2f5f"
ORDER_SEED = 501


def _load_v(root: Path) -> list[dict]:
    raw = (root / V_CORPUS).read_bytes()
    if hashlib.sha256(raw).hexdigest() != V_SHA256:
        raise ValueError("independent V corpus bytes changed")
    cases = json.loads(raw)["cases"]
    if len(cases) != 12 or len({case["id"] for case in cases}) != 12:
        raise ValueError("independent V denominator changed")
    return cases


def _one_v(root: Path, case: dict, provider: ScriptedStressProvider,
           budget: OfflineBudget, *, order: str, repeat: int) -> dict:
    started, cpu_started = time.perf_counter_ns(), time.process_time_ns()
    decisions, source_rows = [], []
    for source in case["sources"]:
        decision, reason = _source_decision(source["text"], case["asset"])
        claim, error = None, None
        raw, acquisition = exact_source_bytes(root, source)
        if decision in {"affected", "unaffected"}:
            try:
                claim = build_atomic_claim(root, source, case["asset"],
                                           polarity=decision, predicate=reason).model_dump(mode="json")
                decisions.append(decision)
            except ValueError as exc:
                error = f"{type(exc).__name__}: {exc}"
        source_rows.append({"id": source["id"], "decision": decision, "reason": reason,
                            "sha256": hashlib.sha256(raw).hexdigest(), "acquisition": acquisition,
                            "atomic_claim_attempted": decision in {"affected", "unaffected"},
                            "atomic_claim_emitted": claim is not None,
                            "claim_error": error,
                            "claim": claim})
    observed = "unknown" if len(set(decisions)) != 1 else decisions[0]
    inconclusive = any(source["reason"] == "unsupported-debian-epoch" for source in source_rows)
    baseline_wall_ms = (time.perf_counter_ns() - started) / 1_000_000
    baseline_cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
    payload = json.dumps({"asset": case["asset"], "sources": case["sources"]},
                         sort_keys=True, separators=(",", ":")).encode()
    provider_started, provider_cpu_started = time.perf_counter_ns(), time.process_time_ns()
    try:
        response = provider.complete_json(payload, budget=budget)
        if (time.perf_counter_ns() - provider_started) / 1_000_000 > budget.timeout_ms:
            raise TimeoutError("scripted provider deadline")
        draft = json.loads(response)
        if (set(draft) != {"candidate_outcome", "point", "citations", "support"} or
                draft["candidate_outcome"] not in {"affected", "unaffected", "unknown"} or
                draft["support"] != "unchecked" or
                not set(draft["citations"]).issubset({s["id"] for s in case["sources"]})):
            raise ValueError("invalid scripted research schema")
        scripted_status = "completed"
        scripted_raw = draft["candidate_outcome"]
        scripted_checked = observed if observed == scripted_raw and not inconclusive else "unknown"
        raw_point = {"text": draft["point"], "citations": draft["citations"],
                     "support": "unchecked", "reportable": False}
        point_attempted, point_emitted = 1, 0
        scripted_error = None
    except (ValueError, TimeoutError) as exc:
        scripted_status, scripted_raw, scripted_checked = "failed", None, None
        raw_point, point_attempted, point_emitted = None, 0, 0
        scripted_error = f"{type(exc).__name__}: {exc}"
    return {"id": case["id"], "order": order, "repeat": repeat,
            "expected": case["expected"], "observed": observed,
            "status": "inconclusive" if inconclusive else "completed",
            "exact": observed == case["expected"], "sources": source_rows,
            "baseline_wall_ms": round(baseline_wall_ms, 6),
            "baseline_cpu_ms": round(baseline_cpu_ms, 6),
            "scripted_status": scripted_status, "scripted_raw": scripted_raw,
            "scripted_checked": scripted_checked, "scripted_error": scripted_error,
            "raw_point": raw_point,
            "point_attempted": point_attempted, "point_emitted": point_emitted,
            "scripted_wall_ms": round((time.perf_counter_ns() - provider_started) / 1_000_000, 6),
            "scripted_cpu_ms": round((time.process_time_ns() - provider_cpu_started) / 1_000_000, 6)}


def _summary(rows: list[dict]) -> dict:
    eligible = [row for row in rows if row["status"] == "completed"]
    completed_scripted = [row for row in rows if row["scripted_status"] == "completed"]
    return {"planned": len(rows), "attempted": len(rows), "eligible": len(eligible),
            "inconclusive": len(rows) - len(eligible),
            "exact_all_planned": sum(row["exact"] for row in rows),
            "exact_eligible": sum(row["exact"] for row in eligible),
            "false_affected": sum(row["observed"] == "affected" and row["expected"] != "affected"
                                  for row in rows),
            "abstentions": sum(row["observed"] == "unknown" for row in rows),
            "scripted_completed": len(completed_scripted),
            "scripted_failed": len(rows) - len(completed_scripted),
            "scripted_raw_false_affected": sum(row["scripted_raw"] == "affected" and
                                                row["expected"] != "affected"
                                                for row in completed_scripted),
            "scripted_checked_false_affected": sum(row["scripted_checked"] == "affected" and
                                                    row["expected"] != "affected"
                                                    for row in completed_scripted),
            "scripted_checked_exact_eligible": sum(row["scripted_checked"] == row["expected"]
                                                    for row in eligible),
            "atomic_claims_attempted": sum(s["atomic_claim_attempted"] for r in rows for s in r["sources"]),
            "atomic_claims_emitted": sum(s["atomic_claim_emitted"] for r in rows for s in r["sources"]),
            "atomic_claim_errors": sum(bool(s["claim_error"]) for r in rows for s in r["sources"]),
            "source_byte_bound_emitted": sum(s["atomic_claim_emitted"] for r in rows for s in r["sources"]),
            "independently_semantic_adjudicated": 0,
            "authenticated_real_advisory": 0,
            "scripted_points_attempted": sum(row["point_attempted"] for row in rows),
            "scripted_points_emitted": sum(row["point_emitted"] for row in rows),
            "scripted_points_independently_adjudicated": 0,
            "unsupported_positive_points_emitted": 0,
            "baseline_latency_ms": {name: _percentile([r["baseline_wall_ms"] for r in rows], q)
                                    for name, q in (("p50", .5), ("p95", .95), ("p99", .99))},
            "scripted_latency_ms": {name: _percentile([r["scripted_wall_ms"] for r in rows], q)
                                    for name, q in (("p50", .5), ("p95", .95), ("p99", .99))},
            "baseline_cpu_ms": round(sum(r["baseline_cpu_ms"] for r in rows), 4),
            "scripted_cpu_ms": round(sum(r["scripted_cpu_ms"] for r in rows), 4)}


def evaluate_phase5a1(root: Path) -> dict:
    """Run frozen V and visible36 separately; never call a network/model provider."""
    root = root.resolve()
    cases = _load_v(root)
    provider, budget = ScriptedStressProvider(), OfflineBudget()
    start_wall, start_cpu = time.perf_counter_ns(), time.process_time_ns()
    v_trials = []
    for order in ("fixed", "seeded-shuffled"):
        for repeat in range(3):
            selected = list(cases)
            if order == "seeded-shuffled":
                random.Random(ORDER_SEED + repeat).shuffle(selected)
            rows = [_one_v(root, case, provider, budget, order=order, repeat=repeat + 1)
                    for case in selected]
            v_trials.append({"order": order, "repeat": repeat + 1,
                             "rows": rows, "summary": _summary(rows)})
    visible_trials = [evaluate_alpha(root) for _ in range(3)]
    return {"schema_version": "phase5a1-offline-eval-v1", "source_scope": "synthetic-local-only",
            "v_corpus_sha256": V_SHA256, "order_seed": ORDER_SEED,
            "v_trials": v_trials, "v_total": _summary([r for trial in v_trials for r in trial["rows"]]),
            "visible36_trials": visible_trials,
            "real_model": {"status": "skipped", "planned_units": 72, "attempted_units": 0,
                           "reason": "no separately approved endpoint/model, export scope, credential or billing oracle",
                           "billed_tokens": None, "usd_cost": None},
            "run_wall_ms": round((time.perf_counter_ns() - start_wall) / 1_000_000, 4),
            "run_cpu_ms": round((time.process_time_ns() - start_cpu) / 1_000_000, 4),
            "process_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (
                1 if sys.platform == "darwin" else 1024),
            "methodology": ("V candidate parser: 12 cases, three fixed and three seeded-shuffled repeats; "
                            "visible 36: three separate trials. Monotonic process-local wall and process CPU. "
                            "Scripted point is inert and always unchecked; no model/network/feed call. "
                            "Synthetic source roles are not authenticated; independent semantic adjudication is absent.")}
