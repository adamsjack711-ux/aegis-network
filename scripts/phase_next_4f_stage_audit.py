"""Independently score retained one-host withdrawal diagnostic traces."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("traces", type=Path, nargs="+")
    args = parser.parse_args()
    cases = []
    for path in args.traces:
        raw = path.read_bytes()
        run = json.loads(raw)
        stages = run["recovery_stages"]
        trace = stages["trace"]
        counts = Counter((item["kind"], item.get("stage")) for item in trace)
        from_restart = {f"{item['kind']}:{item.get('stage')}": item["from_restart_request_ms"]
                        for item in trace}
        claim_ms = from_restart.get("claim_stage:claimed")
        first_wire = next((item["from_restart_request_ms"] for item in trace
                           if item.get("stage") == "critical_received"), None)
        independent_ms = run["independent_withdrawal_ms"]["submit_to_durable_audit_ms"]
        mixed_ms = run["mixed_withdrawal_ms"]["submit_to_durable_audit_ms"]
        denied = set(run["effective_denials_from_read_only_sqlite"])
        # Effective denials are recorded against the two original finding IDs,
        # whereas withdrawal IDs identify the later revocation events.
        intended = {row["event_id"] for row in run["queued_journal_order"][:2]}
        withdrawal_ids = {run["independent_withdrawal_id"], run["mixed_withdrawal_id"]}
        journal_ids = {row["event_id"] for row in run["queued_journal_order"]}
        pending = run["ordinary_capacity_isolation"]["ordinary_outbox_rows_still_pending"]
        durable = (run["profile"] == "priority" and
                   stages["targeted_agent_withdrawal_pairs"] == 2 and denied == intended and
                   withdrawal_ids <= journal_ids and
                   run["all_logical_broker_acks"] == run["ordinary_enqueued"] + 4 and
                   pending == run["ordinary_enqueued"] + 2)
        killed = run["agent_sigkill"]
        stage_order = (claim_ms is not None and first_wire is not None and
                       stages["broker_start_duration_ms"] < claim_ms < first_wire <
                       run["independent_withdrawal_ms"]["restart_request_to_durable_audit_ms"])
        if killed:
            diagnostic = (stage_order and counts["claim_stage", "busy"] == 30 and
                          counts["claim_stage", "attempt"] == 31 and
                          counts["claim_stage", "claimed"] == 1 and
                          29_000 < claim_ms < 32_000 and first_wire - claim_ms < 100)
        else:
            diagnostic = (counts["claim_stage", "busy"] == 0 and
                          independent_ms < 5_000 and mixed_ms < 5_000)
        five_second = independent_ms <= 5_000 and mixed_ms <= 5_000
        cases.append({"file": str(path), "sha256": sha256(raw).hexdigest(),
                      "source_pin": run["source"]["head"], "agent_sigkill": killed,
                      "targeted_agent_withdrawal_pairs": 2,
                      "durable_denial_and_priority_control": "pass" if durable else "fail",
                      "stage_diagnostic": "pass" if diagnostic else "fail",
                      "five_second_submit_to_durable_denial": "pass" if five_second else "fail",
                      "broker_start_return_ms": stages["broker_start_duration_ms"],
                      "busy_attempts": counts["claim_stage", "busy"],
                      "claim_success_from_restart_ms": claim_ms,
                      "first_critical_receipt_from_restart_ms": first_wire,
                      "independent_submit_to_denial_ms": independent_ms,
                      "mixed_submit_to_denial_ms": mixed_ms})
    result = {"cases": cases,
              "denominator": {"trials": len(cases), "targeted_pairs": len(cases) * 2,
                              "sigkill_trials": sum(case["agent_sigkill"] for case in cases)},
              "diagnostic_pass": sum(case["stage_diagnostic"] == "pass" for case in cases),
              "five_second_fail": sum(case["five_second_submit_to_durable_denial"] == "fail"
                                      for case in cases),
              "limitations": "One host, one broker, one dry-run agent per trial; no native T4/T5 or target hold timestamp. Controller and child perf_counter_ns comparable only within one host."}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"diagnostic_pass": result["diagnostic_pass"],
                      "five_second_fail": result["five_second_fail"]}))


if __name__ == "__main__":
    main()
