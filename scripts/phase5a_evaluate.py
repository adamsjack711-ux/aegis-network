"""Offline Phase 5A benchmark. Writes JSON only to the selected local path."""

import argparse
import json
from pathlib import Path

from aegis.intelligence.evaluate import evaluate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=Path("tests/fixtures/phase5a_cases.json"))
    parser.add_argument("--output", type=Path, default=Path("benchmarks/phase5a-offline.json"))
    args = parser.parse_args()
    report = evaluate(args.corpus)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"{len(report['cases'])} cases; baseline={report['baseline']['correct']} "
          f"fixture={report['ai']['correct']}; delta={report['improvement_correct_cases']}")


if __name__ == "__main__":
    main()
