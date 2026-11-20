"""Score native observer-order traces using committed state, never HTTP alone."""

import argparse
from hashlib import sha256
import json
from pathlib import Path


def entry(trace, name):
    return next((row for row in trace if row.get("event") == name), None)


def held(snapshot, baseline):
    if not snapshot or not baseline:
        return False
    before = {target: fence for target, fence, _ in baseline["targets"]}
    return (
        set(before) == {target for target, _, _ in snapshot["targets"]}
        and all(mode == "quarantined" and fence > before[target]
                for target, fence, mode in snapshot["targets"])
        and snapshot["rollout"][0] in {"recovery_required", "safe_hold"}
        and any(row[2] == "quarantined" for row in snapshot["audit"])
    )


def score(trial):
    trace = trial.get("trace", [])
    scenario = trial.get("scenario", "unknown")
    if scenario in {"stale_approval", "interrupted_transaction", "revoked_evidence", "stale_trust_cut"}:
        before = entry(trace, "before_negative_write")
        after = entry(trace, "after_negative_write")
        attempted = entry(trace, "negative_write_result")
        if not before or not after or not attempted:
            return {"scenario": scenario, "status": "inconclusive", "reason": "negative write observation missing"}
        safe = attempted.get("outcome") == "denied" and before.get("result") == after.get("result")
        if scenario == "interrupted_transaction":
            safe = safe and trial.get("status_checks") == 2
        return {"scenario": scenario, "status": "pass" if safe else "fail",
                "write_outcome": attempted.get("outcome"), "durable_state_unchanged":
                before.get("result") == after.get("result"), "status_checks": trial.get("status_checks")}
    healthy = entry(trace, "healthy_disk")
    baseline = healthy and healthy.get("result")
    if scenario == "writer_lock":
        return {"scenario": scenario, "status": "inconclusive", "reason": "observer ordering is not exercised"}
    if not baseline or not all(mode == "restricted" for _, _, mode in baseline["targets"]):
        return {"scenario": scenario, "status": "inconclusive", "reason": "healthy protected control missing"}
    cut = entry(trace, "authority_cut_applied")
    if not cut:
        return {"scenario": scenario, "status": "inconclusive", "reason": "authority cut missing"}
    first = next((row for row in trace if row.get("event") == "internal_probe_start" and "disk" in row), None)
    if scenario.endswith("_idle") or scenario == "ownership_snapshot_race":
        first = entry(trace, "pre_external_probe_disk")
        snapshot = first and first.get("result")
    else:
        snapshot = first and first.get("disk")
    if not first or first["at_ns"] < cut["at_ns"]:
        return {"scenario": scenario, "status": "inconclusive", "reason": "no post-cut pre-request read-only snapshot"}
    if scenario == "evidence_idle":
        deadline = entry(trace, "authority_deadline")
        if not deadline or first["at_ns"] < deadline["deadline_ns"]:
            return {"scenario": scenario, "status": "inconclusive",
                    "reason": "pre-request snapshot did not cross the authoritative freshness deadline",
                    "first_snapshot_ns": first["at_ns"],
                    "deadline_ns": deadline and deadline["deadline_ns"]}
    result = {"scenario": scenario, "status": "pass" if held(snapshot, baseline) else "fail",
              "first_snapshot_ns": first["at_ns"], "cut_ns": cut["at_ns"],
              "pre_request_phase": snapshot["rollout"][0],
              "pre_request_targets": snapshot["targets"]}
    if scenario == "ownership_snapshot_race":
        samples = [row for row in trace if row.get("event") == "concurrent_readonly_snapshot"]
        inconsistent = [row for row in samples if row["disk"]["generation"] !=
                        row["disk"]["rollout_generation"] and not held(row["disk"], baseline)]
        result["concurrent_sample_count"] = len(samples)
        result["inconsistent_sample_count"] = len(inconsistent)
        response_check = entry(trace, "stale_route_response_check")
        result["stale_route_response_permitted"] = response_check and response_check.get("permitted")
        if response_check is None and result["status"] == "pass":
            result["status"] = "inconclusive"
        elif response_check and response_check.get("permitted"):
            result["status"] = "fail"
    after = entry(trace, "durable_after_monitor_before_external_gets")
    if not after or not held(after.get("result"), baseline):
        result["status"] = "fail" if after else "inconclusive"
        result["reason"] = "durable post-recovery hold absent" if after else "post-recovery readback missing"
    probes = entry(trace, "separate_read_only_gets_after_hold")
    if probes and probes.get("result"):
        rows = probes["result"]
        expected_routes = {(target, route) for target, _, _ in baseline["targets"]
                           for route in ("/fixture-marker", "/health", "/ok")}
        result["complete_route_inventory"] = (
            len(rows) == len(expected_routes) and
            {(row.get("target"), row.get("path")) for row in rows} == expected_routes
        )
        result["protected_routes_denied"] = all(
            row.get("path") != "/fixture-marker" or row.get("status") in {403, 503}
            for row in rows
        )
        result["route_sample_count"] = len(rows)
        post_gets = entry(trace, "post_gets_disk")
        result["observer_did_not_mutate_target"] = bool(
            post_gets and after and post_gets.get("result") == after.get("result")
        )
        if not result["complete_route_inventory"] or not result["protected_routes_denied"] or not result["observer_did_not_mutate_target"]:
            result["status"] = "fail"
    else:
        result["protected_routes_denied"] = None
        result["status"] = "inconclusive" if result["status"] == "pass" else result["status"]
    if scenario.startswith("ownership"):
        old_attempt = entry(trace, "old_owner_reopen_attempt")
        new_attempt = entry(trace, "fresh_successor_reopen_attempt")
        post_attempts = entry(trace, "after_reopen_attempts_disk")
        if old_attempt and new_attempt and post_attempts and after:
            result["reopen_denied"] = (old_attempt.get("outcome") == "denied" and
                                       new_attempt.get("outcome") == "denied" and
                                       post_attempts.get("result", {}).get("targets") ==
                                       after.get("result", {}).get("targets"))
            if not result["reopen_denied"]:
                result["status"] = "fail"
        else:
            result["reopen_denied"] = None
            if result["status"] == "pass":
                result["status"] = "inconclusive"
    restart = entry(trace, "restart_disk")
    if restart:
        result["restart_hold"] = held(restart.get("result"), baseline)
        if not result["restart_hold"]:
            result["status"] = "fail"
        restart_probes = entry(trace, "read_only_gets_after_restart")
        if restart_probes:
            result["restart_routes_denied"] = all(
                row.get("path") != "/fixture-marker" or row.get("status") in {403, 503}
                for row in restart_probes.get("result", [])
            ) and len(restart_probes.get("result", [])) == 3 * len(baseline["targets"])
            if not result["restart_routes_denied"]:
                result["status"] = "fail"
        elif result["status"] == "pass":
            result["status"] = "inconclusive"
    elif result["status"] == "pass":
        result["status"] = "inconclusive"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--source-pin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.trace.read_bytes()
    doc = json.loads(raw)
    trials = [score(trial) for trial in doc["trials"]]
    result = {"source_pin": args.source_pin, "trace_sha256": sha256(raw).hexdigest(),
              "oracle": "committed target state before any post-cut request",
              "topology": "one-host fixture unless independently proven otherwise", "trials": trials}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"pass": sum(t["status"] == "pass" for t in trials),
                      "fail": sum(t["status"] == "fail" for t in trials),
                      "inconclusive": sum(t["status"] == "inconclusive" for t in trials)}))


if __name__ == "__main__":
    main()
