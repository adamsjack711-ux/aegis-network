"""Score exact durable withdrawal denials; transport milestones never pass the gate."""

import argparse
import json
from pathlib import Path


LIMIT_MS = 5_000


def score_trial(raw: dict) -> dict:
    stages = raw["recovery_stages"]
    agents = stages["enrolled_agent_ids"]
    withdrawals = (
        ("independent", raw["independent_withdrawal_id"], raw["independent_withdrawal_ms"]),
        ("mixed-sequence", raw["mixed_withdrawal_id"], raw["mixed_withdrawal_ms"]),
    )
    readback = raw.get("durable_denial_readback", {})
    # The retained one-agent fixture created these exact target findings first.
    target_ids = [row["event_id"] for row in raw["queued_journal_order"][:2]]
    setup_valid = (raw["ordinary_enqueued"] >= 1 and len(agents) >= 1
                   and len(target_ids) == 2 and target_ids[0] != target_ids[1]
                   and withdrawals[0][1] != withdrawals[1][1])
    final_denials = set(raw["effective_denials_from_read_only_sqlite"])
    pairs = []
    for agent in agents:
        for index, (kind, withdrawal_id, timing) in enumerate(withdrawals):
            exact_readback = readback.get(withdrawal_id)
            target = (exact_readback or {}).get(
                "target_finding_id", target_ids[index] if index < len(target_ids) else None)
            observed_ms = (exact_readback or {}).get("submit_to_first_present_ms")
            committed_ms = timing["submit_to_durable_audit_ms"] if len(agents) == 1 else None
            final_confirmed = target in final_denials if len(agents) == 1 else False
            if not final_confirmed:
                outcome = "fail"
                reason = "exact durable denial absent from final read-only state"
            elif observed_ms is not None:
                outcome = "pass" if observed_ms <= LIMIT_MS else "fail"
                reason = "independent read-only denial upper bound"
            elif committed_ms is not None and committed_ms > LIMIT_MS:
                outcome = "fail"
                reason = "reported commit already exceeds limit; later readback cannot pass"
            else:
                outcome = "inconclusive"
                reason = "no timed independent read-only denial observation"
            pairs.append({
                "agent_id": agent, "withdrawal_type": kind, "withdrawal_id": withdrawal_id,
                "target_finding_id": target, "eligible_after_restoration": True,
                "outcome": outcome, "reason": reason,
                "submit_to_worker_commit_ms": committed_ms,
                "submit_to_read_only_denial_upper_ms": observed_ms,
                "restart_request_to_worker_commit_ms": timing["restart_request_to_durable_audit_ms"],
                "submit_to_broker_ack_ms_observational": timing["submit_to_confirmed_ack_ms"],
            })
    return {
        "agent_sigkill": raw["agent_sigkill"],
        "ordinary_enqueued": raw["ordinary_enqueued"],
        "enrolled_agents": agents,
        "declared_pairs": stages["targeted_agent_withdrawal_pairs"],
        "acceptance_setup_valid": setup_valid,
        "observed_pairs": pairs,
        "all_pairs_pass": setup_valid and len(pairs) == stages["targeted_agent_withdrawal_pairs"] and all(
            pair["outcome"] == "pass" for pair in pairs),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trials", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trials = [{"file": str(path), **score_trial(json.loads(path.read_text()))} for path in args.trials]
    report = {"limit_ms": LIMIT_MS, "trials": trials,
              "crash_gate_pass": sum(trial["agent_sigkill"] for trial in trials) >= 3 and all(
                  trial["all_pairs_pass"] for trial in trials if trial["agent_sigkill"])}
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return 0 if report["crash_gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
