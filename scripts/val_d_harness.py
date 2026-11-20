"""Independent VAL-D provenance, withdrawal and research evidence scorer.

The scorer never imports candidate code. It does not infer semantic support from
matching citation IDs or call a fixture provider a real model.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys


BASELINE = "3bfd2abea430bc8036105ce85adfdc78706d367d"
LIMIT_MS = 5000.0


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def pin(root, expected):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip()
    return {"path": str(Path(root).resolve()), "head": head, "expected": expected,
            "dirty": bool(dirty), "status": "pass" if head == expected and not dirty else "fail"}


def originals(root):
    manifest_path = Path(root) / "benchmarks/phase-next-alpha-validation/original-copies-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    rows = []
    for item in manifest["files"]:
        source = Path(root) / item["original_path"]
        copy = Path(root) / item["copy_path"]
        observed = {"original": digest(source), "copy": digest(copy)}
        rows.append({"path": item["original_path"], "expected": item["sha256"],
                     **observed, "status": "pass" if observed["original"] ==
                     observed["copy"] == item["sha256"] else "fail"})
    return {"baseline": manifest["baseline_commit"], "manifest_sha256": digest(manifest_path),
            "files": rows, "status": "pass" if manifest["baseline_commit"] == BASELINE
            and all(row["status"] == "pass" for row in rows) else "fail"}


def withdrawal(paths, expected_pin):
    rows = []
    for path in paths:
        raw = json.loads(Path(path).read_text())
        source = raw.get("source", {}).get("head")
        stages = raw.get("recovery_stages", {})
        actor_ids = stages.get("enrolled_agent_ids", [])
        expected_pairs = stages.get("targeted_agent_withdrawal_pairs")
        denials = raw.get("effective_denials_from_read_only_sqlite", [])
        timings = {name: raw.get(name + "_withdrawal_ms", {}) for name in ("independent", "mixed")}
        observed_pairs = sum("submit_to_durable_audit_ms" in item for item in timings.values())
        elapsed = {name: item.get("submit_to_durable_audit_ms") for name, item in timings.items()}
        admitted_ids = {row.get("event_id") for row in raw.get("queued_journal_order", [])
                        if row.get("sent_at") is None}
        pre_restart_admitted = {raw.get("independent_withdrawal_id"),
                                raw.get("mixed_withdrawal_id")}.issubset(admitted_ids)
        admission_lower_bound = {name: item.get("restart_request_to_durable_audit_ms")
                                 for name, item in timings.items()}
        missing = (source != expected_pin or expected_pairs != 2 * len(actor_ids)
                   or len(denials) != expected_pairs or observed_pairs != expected_pairs
                   or not pre_restart_admitted or any(value is None for value in admission_lower_bound.values()))
        ceiling_breach = any(value is not None and value > LIMIT_MS
                             for value in admission_lower_bound.values())
        status = "inconclusive" if missing else "fail" if ceiling_breach else "pass"
        rows.append({"file": str(path), "sha256": digest(path), "source_pin": source,
                     "enrolled_agents": len(actor_ids), "targeted_pairs": expected_pairs,
                     "durable_denials": len(denials), "timed_pairs": observed_pairs,
                     "ordinary_enqueued": raw.get("ordinary_enqueued"),
                     "submission_to_durable_denial_ms": elapsed,
                     "pre_restart_durable_admission_witness": pre_restart_admitted,
                     "admission_to_denial_lower_bound_ms": admission_lower_bound,
                     "admission_to_denial_exact_ms": "not recorded by this legacy driver",
                     "physical_target_hold": "not observed; dry-run agent audit only",
                     "status": status})
    return {"source_pin": expected_pin, "five_second_limit_ms": LIMIT_MS,
            "trials": rows, "attempted_trials": len(rows),
            "eligible_pairs": sum(r["targeted_pairs"] or 0 for r in rows),
            "observed_pairs": sum(r["timed_pairs"] for r in rows),
            "status": "fail" if any(r["status"] == "fail" for r in rows) else
            "inconclusive" if any(r["status"] == "inconclusive" for r in rows) else "pass"}


def ai(corpus_path, evaluation_path):
    corpus = json.loads(Path(corpus_path).read_text())
    evaluation = json.loads(Path(evaluation_path).read_text())
    cases = {case["id"]: case for case in corpus["cases"]}
    result = {"corpus_sha256": digest(corpus_path), "evaluation_sha256": digest(evaluation_path),
              "eligible_cases": len(cases), "arms": {}}
    if evaluation.get("corpus_sha256") != result["corpus_sha256"]:
        raise ValueError("evaluation used different corpus bytes")
    for name, arm in evaluation.get("arms", {}).items():
        if arm.get("status") != "executed":
            result["arms"][name] = {"status": "skipped", "reason": arm.get("reason", "not executed")}
            continue
        rows = arm.get("cases", [])
        if {row.get("id") for row in rows} != set(cases) or len(rows) != len(cases):
            raise ValueError("case denominator changed")
        unsupported_positive = 0
        emitted_claims = 0
        pending_support = 0
        for row in rows:
            response = row.get("raw", {}).get("response", {})
            claims = response.get("claims", [])
            emitted_claims += len(claims)
            pending_support += len(claims)  # independent byte-level adjudication is required
            if row.get("score", {}).get("observed") == "affected" and cases[row["id"]]["expected"] != "affected":
                unsupported_positive += 1
        summary = arm.get("summary", {})
        is_real = name == "model" and arm.get("provider_kind") == "real-model" and bool(arm.get("billing_evidence"))
        result["arms"][name] = {"status": "evaluated", "pin": arm.get("pin"),
            "case_count": len(rows), "correct": summary.get("correct"),
            "abstentions": sum(row.get("score", {}).get("observed") == "unknown" for row in rows),
            "false_positive_decisions": unsupported_positive,
            "emitted_claims": emitted_claims, "claim_support_pending_independent_review": pending_support,
            "real_model_performance_evidence": is_real,
            "latency_ms_p95": summary.get("p95_latency_ms"),
            "reported_cost_usd": summary.get("total_reported_cost_usd") if is_real else None}
    has_real_model = any(x.get("real_model_performance_evidence")
                         for x in result["arms"].values())
    result["research_release_status"] = "REVIEW-REQUIRED" if has_real_model else "NO-GO"
    return result


def cli(probe_path, resource_paths, source_pin, image_digest):
    probe = json.loads(Path(probe_path).read_text())
    defaults = ("status_no_feed", "findings_no_feed", "findings_missing_trust", "inventory")
    default_rows = {name: {"created": probe[name]["created"],
                           "status": "pass" if not probe[name]["created"] else "fail"}
                    for name in defaults}
    explicit = probe["inventory_explicit_state"]["created"]
    explicit_ok = explicit == ["chosen", "chosen/identity.json"]
    resource_rows = []
    for path in resource_paths:
        data = json.loads(Path(path).read_text())
        n = data["rows"]
        runs = data["runs"]
        complete = len(runs) == 3 and all(r["reported_count"] == n and
                                           r["inventory_complete"] for r in runs)
        budget = all(r["wall_ms"] <= 5000 and r["cpu_ms"] <= 5000 and
                     r["peak_rss_kib_at_least"] <= 256 * 1024 for r in runs) if n == 100000 else True
        resource_rows.append({"rows": n, "file": str(path), "sha256": digest(path),
                              "runs": len(runs), "complete": complete, "budget": budget,
                              "max_wall_ms": max(r["wall_ms"] for r in runs),
                              "max_cpu_ms": max(r["cpu_ms"] for r in runs),
                              "max_peak_rss_kib_at_least": max(r["peak_rss_kib_at_least"] for r in runs),
                              "status": "pass" if complete and budget else "fail"})
    source_checks = all(row["status"] == "pass" for row in default_rows.values()) and explicit_ok
    resource_checks = ({row["rows"] for row in resource_rows} == {100, 10000, 100000}
                       and all(row["status"] == "pass" for row in resource_rows))
    return {"source_pin": source_pin, "image_digest": image_digest,
            "probe_sha256": digest(probe_path), "default_cases": default_rows,
            "default_pass": sum(row["status"] == "pass" for row in default_rows.values()),
            "default_denominator": len(defaults),
            "explicit_state_control": "pass" if explicit_ok else "fail",
            "resource_cases": resource_rows,
            "source_level_status": "pass" if source_checks and resource_checks else "fail",
            "wheel_install_uninstall": "skipped: no offline built wheel at this clean pin",
            "syscall_observer": "skipped: no tracer in cached image",
            "platform_matrix": "incomplete: synthetic Debian os-release on cached Kali only",
            "cli_alpha_release_status": "NO-GO"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("verify-originals")
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--output", type=Path)
    p = subs.add_parser("pin")
    p.add_argument("root", type=Path)
    p.add_argument("expected")
    p.add_argument("--output", type=Path)
    p = subs.add_parser("score-withdrawal")
    p.add_argument("--source-pin", required=True)
    p.add_argument("inputs", type=Path, nargs="+")
    p.add_argument("--output", type=Path)
    p = subs.add_parser("score-ai")
    p.add_argument("--corpus", type=Path, required=True)
    p.add_argument("evaluation", type=Path)
    p.add_argument("--output", type=Path)
    p = subs.add_parser("score-cli")
    p.add_argument("--source-pin", required=True)
    p.add_argument("--image-digest", required=True)
    p.add_argument("--probe", type=Path, required=True)
    p.add_argument("resources", type=Path, nargs="+")
    p.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "verify-originals":
        result = originals(args.root)
    elif args.command == "pin":
        result = pin(args.root, args.expected)
    elif args.command == "score-withdrawal":
        result = withdrawal(args.inputs, args.source_pin)
    elif args.command == "score-ai":
        result = ai(args.corpus, args.evaluation)
    else:
        result = cli(args.probe, args.resources, args.source_pin, args.image_digest)
    if args.output:
        write(args.output, result)
    print(json.dumps(result, sort_keys=True))
    if result.get("status") == "fail":
        sys.exit(1)


if __name__ == "__main__":
    main()
