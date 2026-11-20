"""Score retained Phase 4F lease diagnostics without changing the frozen oracle.

The inputs are historical one-agent dry-run traces. They are not native T4/T5
or target-protection results, and they never fill the 72+18 release matrix.
"""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path


TRACE_PATHS = (
    "benchmarks/phase-next-remediation/4f-sigkill-fault.json",
    "benchmarks/phase4f-withdrawal-recovery/sigkill-restart-1.json",
    "benchmarks/phase4f-withdrawal-recovery/sigkill-restart-2.json",
    "benchmarks/phase4f-withdrawal-recovery/sigkill-restart-3.json",
    "benchmarks/phase4f-kv-recovery/baseline-sigkill.json",
    "benchmarks/phase-next-remediation/4f-broker-control.json",
    "benchmarks/phase4f-withdrawal-recovery/broker-restart-no-kill.json",
)
DEADLINE_MS = 5_000


def score(root: Path) -> dict:
    trials = []
    for relative in TRACE_PATHS:
        raw = (root / relative).read_bytes()
        trace = json.loads(raw)
        stages = trace["recovery_stages"]
        counts = Counter((item["kind"], item.get("stage")) for item in stages["trace"])
        claims = [item for item in stages["trace"] if item.get("stage") == "claimed"]
        first_wire = next((item["from_restart_request_ms"] for item in stages["trace"]
                           if item.get("stage") == "critical_received"), None)
        intended = {item["event_id"] for item in trace["queued_journal_order"][:2]}
        observed = set(trace["effective_denials_from_read_only_sqlite"])
        pairs = []
        for kind in ("independent", "mixed"):
            timing = trace[f"{kind}_withdrawal_ms"]
            delay = timing["submit_to_durable_audit_ms"]
            pairs.append({
                "kind": kind,
                "withdrawal_id": trace[f"{kind}_withdrawal_id"],
                "submit_to_durable_dry_run_denial_ms": delay,
                "restart_to_durable_dry_run_denial_ms": timing["restart_request_to_durable_audit_ms"],
                "submit_to_confirmed_ack_ms": timing["submit_to_confirmed_ack_ms"],
                "within_5000_ms": delay <= DEADLINE_MS,
            })
        trials.append({
            "file": relative,
            "sha256": sha256(raw).hexdigest(),
            "source_pin": trace["source"]["head"],
            "pre_intake_sigkill": trace["agent_sigkill"],
            "ordinary_pending": trace["ordinary_capacity_isolation"]["ordinary_outbox_rows_still_pending"],
            "read_only_denial_matches_findings": observed == intended,
            "broker_start_return_ms": stages["broker_start_duration_ms"],
            "busy_kv_claims": counts["claim_stage", "busy"],
            "claim_from_restart_ms": claims[0]["from_restart_request_ms"] if len(claims) == 1 else None,
            "first_critical_wire_from_restart_ms": first_wire,
            "pairs": pairs,
        })
    crash = [pair for trial in trials if trial["pre_intake_sigkill"] for pair in trial["pairs"]]
    healthy = [pair for trial in trials if not trial["pre_intake_sigkill"] for pair in trial["pairs"]]
    if any(not trial["read_only_denial_matches_findings"] for trial in trials):
        raise ValueError("retained read-only denial IDs differ from intended finding IDs")
    return {
        "deadline_ms": DEADLINE_MS,
        "source": "retained one-host dry-run diagnostics; exact input bytes hashed per trial",
        "trials": trials,
        "diagnostic_denominator": {
            "crash_trials": sum(trial["pre_intake_sigkill"] for trial in trials),
            "crash_pairs": len(crash),
            "crash_pairs_over_5000_ms": sum(not pair["within_5000_ms"] for pair in crash),
            "healthy_trials": sum(not trial["pre_intake_sigkill"] for trial in trials),
            "healthy_pairs": len(healthy),
            "healthy_pairs_within_5000_ms": sum(pair["within_5000_ms"] for pair in healthy),
        },
        "frozen_release_matrix": {
            "required_fault_agent_pairs": 72,
            "required_healthy_agent_pairs": 18,
            "full_oracle_evaluable_fault_pairs": 0,
            "full_oracle_evaluable_healthy_pairs": 0,
            "ordinary_pending_required_per_fault_run": 1000,
            "status": "unrun; historical diagnostics cannot enter the numerator",
        },
        "unmeasured": ["native T4/T5 withdrawal acceptance", "target-side durable restriction",
                       "target generation/fence", "agent-owned native proof provenance",
                       "physical multi-host custody", "CPU/RSS"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(score(args.root), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
