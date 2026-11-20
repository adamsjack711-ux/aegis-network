"""Run sealed offline advisory comparison. No network or model provider is enrolled."""

import argparse
import json
import subprocess
from pathlib import Path

from aegis.intelligence.alpha_eval import evaluate_alpha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 10:
        raise ValueError("repeats must be 1-10")
    root = args.root.resolve()
    pin = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip():
        raise ValueError("offline benchmark requires a clean exact source checkout")
    trials = [evaluate_alpha(root) for _ in range(args.repeats)]
    report = {"schema_version": "phase5a-alpha-benchmark-v1", "source_pin": pin,
              "trials": trials, "real_model": {"status": "skipped", "reason": "no enrolled local model"},
              "trial_count": len(trials), "methodology": (
                  "Same 36 sealed synthetic advisory inputs per deterministic and inert scripted arm. "
                  "One process; wall uses perf_counter_ns and CPU uses process_time_ns. "
                  "The scripted fixed response is a stress control, not model inference. "
                  "Labels were visible during implementation; these scores are descriptive, "
                  "not an unbiased estimate of generalization.")}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    first = trials[0]
    print(f"{len(first['rows'])} planned; {first['baseline']['completed']} evaluable; "
          f"baseline {first['baseline']['correct']} exact; "
          f"scripted checked {first['checked_scripted']['correct']} exact; "
          f"real model skipped; {len(trials)} trials")


if __name__ == "__main__":
    main()
