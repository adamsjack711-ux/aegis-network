"""Reproduce the sealed, no-network Investigator comparison."""

import argparse
import json
from pathlib import Path

from aegis.intelligence.investigator_eval import evaluate_investigator


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path,
                        default=Path(__file__).resolve().parents[1] / "tests/fixtures/phase5a_cases.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate_investigator(args.corpus)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in
                      ("planned", "baseline_correct", "investigator_correct", "false_affected")},
                     sort_keys=True))


if __name__ == "__main__":
    main()
