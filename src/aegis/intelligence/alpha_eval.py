"""Offline, synthetic advisory holdout evaluation. No authority or network path."""

from __future__ import annotations

import hashlib
import json
import re
import resource
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


_OUTCOMES = {"affected", "unaffected", "unknown"}
_IDENTITY = re.compile(r"\b(npm|pypi|debian|maven)(?:\s+package|\s+source\s+package)?\s+([a-z0-9_.:@-]+)", re.I)
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_RANGE = re.compile(r"(>=|<=|<|>)\s*([0-9]+(?:\.[0-9]+)*)")
_THROUGH = re.compile(r"versions?\s+([0-9]+(?:\.[0-9]+)*)\s+through\s+([0-9]+(?:\.[0-9]+)*)", re.I)
_SEALED_MANIFEST_SHA256 = "20a3a37da8f941f17e6db514d1437d8d6575140e2e3bde61fc2cad9c6d4a234b"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (pos - low), 3)


def _version_tuple(value: str) -> tuple[int, ...] | None:
    return tuple(map(int, value.split("."))) if _VERSION.fullmatch(value) else None


def _compare(left: str, right: str) -> int | None:
    a, b = _version_tuple(left), _version_tuple(right)
    if a is None or b is None:
        return None
    size = max(len(a), len(b))
    a, b = a + (0,) * (size - len(a)), b + (0,) * (size - len(b))
    return (a > b) - (a < b)


def _clean_text(text: str) -> str:
    """Ignore only explicitly identified instruction/data tails in fixture prose."""
    for marker in ("Untrusted source note:", "IGNORE PRIOR RULES", "Embedded attacker data:"):
        text = text.split(marker, 1)[0]
    return text


def _source_decision(text: str, asset: dict) -> tuple[str, str]:
    clean = _clean_text(text)
    identity = _IDENTITY.search(clean)
    if not identity:
        return "unknown", "no-explicit-product-identity"
    ecosystem = {"debian": "deb"}.get(identity.group(1).lower(), identity.group(1).lower())
    # The regex admits dots inside package names; sentence punctuation is not
    # part of the package identity. Keep internal dots and namespace colons.
    name = identity.group(2).lower().rstrip(".,;")
    if ecosystem != asset["ecosystem"].lower() or name != asset["name"].lower():
        if asset["ecosystem"].lower() != "unknown" and (
            "unrelated" in clean.lower() or "distinct product" in clean.lower()
        ):
            return "unaffected", "explicit-unrelated-product"
        return "unknown", "identity-unresolved"
    lower = clean.lower()
    if "withdrawn" in lower or "no affected versions" in lower or "under investigation" in lower:
        return "unknown", "withdrawn-or-unconfirmed"
    if "only when" in lower or "configuration unknown" in lower:
        return "unknown", "configuration-unverified"
    version = asset["version"]
    if ":" in version and ecosystem == "deb":
        return "unknown", "unsupported-debian-epoch"
    if re.search(r"(?:rc|alpha|beta|pre)[0-9]*", version, re.I) and (
        "pre-release builds" in lower or "pre-release" in lower and "not assessed" in lower
    ):
        return "unknown", "unassessed-prerelease"
    token = re.compile(r"(?<![a-zA-Z0-9.])" + re.escape(version) + r"(?![a-zA-Z0-9.])", re.I)
    explicit_version = bool(token.search(clean))
    if explicit_version and re.search(r"\b(?:is|was)\s+(?:the\s+)?fixed\b|\bis\s+unaffected\b|\bis\s+outside\b", clean, re.I):
        return "unaffected", "explicit-fixed-or-unaffected"
    if explicit_version and (re.search(r"\b(?:is|remains)\s+affected\b", clean, re.I) or
                             re.search(r"\blists\b.*\bas affected\b", clean, re.I)):
        return "affected", "explicit-affected-version"
    if ":" in version or not _VERSION.fullmatch(version):
        return "unknown", "unsupported-version-syntax"
    clauses = _RANGE.findall(clean)
    if clauses and ("affects" in lower or "affected" in lower or "concerns" in lower):
        passed = []
        for op, bound in clauses:
            cmp = _compare(version, bound)
            if cmp is None:
                return "unknown", "unsupported-range"
            passed.append({"<": cmp < 0, "<=": cmp <= 0, ">": cmp > 0, ">=": cmp >= 0}[op])
        return ("affected" if all(passed) else "unaffected"), "explicit-numeric-range"
    through = _THROUGH.search(clean)
    if through and ("affects" in lower or "affected" in lower):
        start, end = through.groups()
        return ("affected" if _compare(version, start) >= 0 and _compare(version, end) <= 0
                else "unaffected"), "explicit-inclusive-range"
    through_upper = re.search(r"versions?\s+through\s+([0-9]+(?:\.[0-9]+)*)", clean, re.I)
    if through_upper and "affected" in lower:
        return ("affected" if _compare(version, through_upper.group(1)) <= 0 else "unaffected"), \
            "explicit-inclusive-upper-bound"
    before = re.search(r"\bbefore\s+([0-9]+(?:\.[0-9]+)*)", clean, re.I)
    if before and ("affects" in lower or "affected" in lower):
        return ("affected" if _compare(version, before.group(1)) < 0 else "unaffected"), "explicit-before-range"
    return "unknown", "no-supported-version-predicate"


class OfflineBudget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    max_input_bytes: int = Field(default=16_384, ge=1, le=65_536)
    max_output_bytes: int = Field(default=2_048, ge=1, le=8_192)
    max_output_tokens: int = Field(default=512, ge=1, le=1_024)
    timeout_ms: int = Field(default=500, ge=1, le=5_000)
    max_inflight: Literal[1] = 1


class OfflineProvider(Protocol):
    def complete_json(self, payload: bytes, *, budget: OfflineBudget) -> bytes: ...


class ScriptedStressProvider:
    """Inert fixed response. It never imports a transport or calls a model."""

    def __init__(self):
        self._gate = threading.BoundedSemaphore(1)

    def complete_json(self, payload: bytes, *, budget: OfflineBudget) -> bytes:
        if len(payload) > budget.max_input_bytes:
            raise ValueError("provider input byte limit")
        if not self._gate.acquire(timeout=budget.timeout_ms / 1000):
            raise TimeoutError("provider concurrency limit")
        try:
            try:
                input_record = json.loads(payload)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError("invalid provider input") from exc
            if not isinstance(input_record, dict) or not isinstance(input_record.get("sources"), list):
                raise ValueError("invalid provider input")
            citations = [source["id"] for source in input_record["sources"]]
            response = json.dumps({"candidate_outcome": "affected",
                                   "point": "Confirmed affected with remote execution.",
                                   "citations": citations, "support": "unchecked"}, sort_keys=True).encode()
            if len(response) > budget.max_output_bytes or (len(response) + 3) // 4 > budget.max_output_tokens:
                raise ValueError("provider output budget")
            return response
        finally:
            self._gate.release()


def _verified_cases(root: Path) -> tuple[list[dict], dict]:
    old_path = root / "fixtures/phase-next-ai-holdout-v1.json"
    new_path = root / "fixtures/phase-next-alpha-ai/holdout-v1.json"
    manifest_path = root / "fixtures/phase-next-alpha-ai/seal-manifest.json"
    old_raw, new_raw, manifest_raw = old_path.read_bytes(), new_path.read_bytes(), manifest_path.read_bytes()
    if _sha(manifest_raw) != _SEALED_MANIFEST_SHA256:
        raise ValueError("seal manifest digest mismatch")
    manifest = json.loads(manifest_raw)
    if _sha(old_raw) != manifest["existing_corpus_sha256"] or _sha(new_raw) != manifest["corpus_sha256"]:
        raise ValueError("sealed corpus digest mismatch")
    old, new = json.loads(old_raw)["cases"], json.loads(new_raw)["cases"]
    if len(old) != 12 or len(new) != manifest["case_count"] or len(old) + len(new) != manifest["combined_case_count"]:
        raise ValueError("sealed corpus denominator mismatch")
    sources = {item["id"]: item for item in manifest["sources"]}
    for case in new:
        for source in case["sources"]:
            entry = sources[source["id"]]
            path = (root / source["raw_path"]).resolve()
            if not path.is_relative_to((root / "fixtures/phase-next-alpha-ai/sources").resolve()):
                raise ValueError("source path escapes sealed fixture root")
            raw = path.read_bytes()
            if (len(raw) != entry["bytes"] or len(raw) != source["bytes"] or
                    _sha(raw) != entry["sha256"] or _sha(raw) != source["sha256"] or
                    raw.decode().rstrip("\n") != source["text"]):
                raise ValueError("sealed source bytes mismatch")
    if len({case["id"] for case in old + new}) != len(old) + len(new):
        raise ValueError("duplicate sealed case ID")
    return old + new, {"prior_sha256": _sha(old_raw), "new_sha256": _sha(new_raw),
                       "manifest_sha256": _sha(manifest_raw), "new_source_count": len(sources)}


def _score(rows: list[dict], key: str) -> dict:
    completed = [r for r in rows if r["status"] == "completed"]
    affected = [r for r in completed if r["expected"] == "affected"]
    positives = [r for r in completed if r[key] == "affected"]
    tp = sum(r["expected"] == "affected" for r in positives)
    fp = len(positives) - tp
    fn = sum(r[key] != "affected" for r in affected)
    return {"planned": len(rows), "completed": len(completed),
            "inconclusive": sum(r["status"] == "inconclusive" for r in rows),
            "correct": sum(r[key] == r["expected"] for r in completed),
            "gold_affected": len(affected), "true_positive": tp, "false_positive": fp,
            "false_negative_including_abstention": fn,
            "abstentions": sum(r[key] == "unknown" for r in completed),
            "precision": tp / len(positives) if positives else None,
            "recall": tp / len(affected) if affected else None}


def evaluate_alpha(root: Path, *, scripted: bool = True, budget: OfflineBudget | None = None) -> dict:
    """Run identical sealed inputs through deterministic and inert scripted arms."""
    run_started = time.perf_counter_ns()
    run_cpu_started = time.process_time_ns()
    root = root.resolve()
    cases, seal = _verified_cases(root)
    seal_validation_ms = (time.perf_counter_ns() - run_started) / 1_000_000
    budget = budget or OfflineBudget()
    provider = ScriptedStressProvider() if scripted else None
    rows = []
    for case in cases:
        started = time.perf_counter_ns()
        cpu_started = time.process_time_ns()
        reasons = []
        decisions = []
        citations = []
        for source in case["sources"]:
            role = source.get("role", "unknown")
            if role == "unverified-blog":
                reasons.append("unverified-source")
                continue
            stamp = source.get("retrieved_at")
            if stamp and datetime.fromisoformat(stamp.replace("Z", "+00:00")) < datetime(2026, 11, 13, tzinfo=timezone.utc):
                reasons.append("stale-source")
                continue
            decision, reason = _source_decision(source["text"], case["asset"])
            reasons.append(reason)
            if decision in {"affected", "unaffected"}:
                decisions.append(decision)
                citations.append(source["id"])
        if len(set(decisions)) > 1:
            outcome, status = "unknown", "completed"
            reasons.append("contradictory-source-claims")
            citations = [s["id"] for s in case["sources"]]
        elif decisions:
            outcome, status = decisions[0], "completed"
        else:
            outcome = "unknown"
            status = "inconclusive" if "unsupported-debian-epoch" in reasons else "completed"
        baseline_ms = (time.perf_counter_ns() - started) / 1_000_000
        baseline_cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
        row = {"id": case["id"], "stratum": case["stratum"], "expected": case["expected"],
               "status": status, "baseline": outcome, "reasons": reasons,
               "citations": citations, "source_ids": [s["id"] for s in case["sources"]],
               "baseline_wall_ms": round(baseline_ms, 4), "baseline_cpu_ms": round(baseline_cpu_ms, 4),
               "expected_impact": case.get("expected_impact"),
               "supported_impact": "availability degradation" if outcome == "affected" and any(
                   s["id"] in citations and
                   "availability degradation" in _clean_text(s["text"]).lower() for s in case["sources"]
               ) else None}
        if scripted:
            payload = json.dumps({"asset": case["asset"], "sources": case["sources"]},
                                 sort_keys=True, separators=(",", ":")).encode()
            provider_started = time.perf_counter_ns()
            provider_cpu_started = time.process_time_ns()
            try:
                raw = provider.complete_json(payload, budget=budget)
                elapsed = (time.perf_counter_ns() - provider_started) / 1_000_000
                if elapsed > budget.timeout_ms:
                    raise TimeoutError("scripted provider deadline")
                draft = json.loads(raw)
                if set(draft) != {"candidate_outcome", "point", "citations", "support"} or (
                    draft["candidate_outcome"] not in _OUTCOMES or draft["support"] != "unchecked"
                    or not set(draft["citations"]).issubset(row["source_ids"])
                ):
                    raise ValueError("invalid scripted research schema")
                cited = [s for s in case["sources"] if s["id"] in draft["citations"]]
                effect_phrase_present = any("remote execution" in _clean_text(s["text"]).lower()
                                            for s in cited)
                row.update(raw_hypothesis=draft["candidate_outcome"],
                           raw_point={"text": draft["point"], "support": "unchecked",
                                      "citations": draft["citations"],
                                      "effect_phrase_in_cited_source": effect_phrase_present,
                                      "source_entailment": "needs-human-review" if effect_phrase_present
                                      else "unsupported"},
                           checked=outcome if outcome == draft["candidate_outcome"] and status == "completed"
                           else "unknown", scripted_status="completed",
                           input_bytes=len(payload), output_bytes=len(raw),
                           synthetic_token_estimate=(len(payload) + len(raw) + 3) // 4,
                           provider_wall_ms=round(elapsed, 4),
                           provider_cpu_ms=round((time.process_time_ns() - provider_cpu_started) / 1_000_000, 4),
                           positive_points_attempted=1, positive_points_emitted=0,
                           positive_points_source_supported=0,
                           positive_points_unsupported_attempted=0 if effect_phrase_present else 1,
                           unsupported_positive_points_emitted=0)
            except (ValueError, TimeoutError) as exc:
                row.update(raw_hypothesis=None, checked=None, scripted_status="failed",
                           scripted_error=type(exc).__name__ + ": " + str(exc),
                           positive_points_attempted=0, positive_points_emitted=0,
                           positive_points_source_supported=0,
                           positive_points_unsupported_attempted=0,
                           unsupported_positive_points_emitted=0)
        rows.append(row)
    completed_scripted = [r for r in rows if r.get("scripted_status") == "completed"]
    return {"schema_version": "phase5a-alpha-eval-v1", "mode": "offline-scripted-stress" if scripted else "deterministic",
            "seal": seal, "planned_cases": len(rows), "new_cases": 24, "prior_cases": 12,
            "rows": rows, "baseline": _score(rows, "baseline"),
            "raw_scripted": _score([r for r in rows if r.get("scripted_status") == "completed"],
                                   "raw_hypothesis") if scripted else {"status": "skipped"},
            "checked_scripted": _score([r for r in rows if r.get("scripted_status") == "completed"], "checked")
            if scripted else {"status": "skipped"},
            "scripted_provider": {"status": "executed" if scripted else "skipped",
                                  "completed": len(completed_scripted),
                                  "failed": sum(r.get("scripted_status") == "failed" for r in rows),
                                  "positive_points_attempted": sum(r.get("positive_points_attempted", 0) for r in rows),
                                  "positive_points_emitted": 0,
                                  "positive_points_unsupported_attempted": sum(
                                      r.get("positive_points_unsupported_attempted", 0) for r in rows),
                                  "unsupported_positive_points_emitted": 0,
                                  "synthetic_token_estimate": sum(r.get("synthetic_token_estimate", 0) for r in rows),
                                  "billed_tokens": None, "usd_cost": None},
            "real_model": {"status": "skipped", "reason": "no authorized enrolled local model"},
            "baseline_latency_ms": {q: _percentile([r["baseline_wall_ms"] for r in rows], p)
                                    for q, p in (("p50", .5), ("p95", .95), ("p99", .99))},
            "scripted_latency_ms": {q: _percentile([r["provider_wall_ms"] for r in completed_scripted], p)
                                    for q, p in (("p50", .5), ("p95", .95), ("p99", .99))},
            "cpu_ms": {"baseline_total": round(sum(r["baseline_cpu_ms"] for r in rows), 4),
                       "scripted_total": round(sum(r.get("provider_cpu_ms", 0) for r in rows), 4),
                       "process_total": round((time.process_time_ns() - run_cpu_started) / 1_000_000, 4)},
            "wall_ms": {"seal_validation": round(seal_validation_ms, 4),
                        "process_total": round((time.perf_counter_ns() - run_started) / 1_000_000, 4)},
            "process_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (
                1 if sys.platform == "darwin" else 1024),
            "limitations": ["Synthetic fixture roles are not source authentication.",
                            "Raw scripted prose is unchecked and never reportable.",
                            "Phrase absence is a negative source check; phrase presence would need human entailment review.",
                            "No real model, billed tokens, provider cost, or model advantage measured.",
                            "Timeout checks cannot preempt arbitrary blocking providers; only the inert local adapter is executed.",
                            "Process peak RSS is cumulative for this run, not a per-case measurement."]}
