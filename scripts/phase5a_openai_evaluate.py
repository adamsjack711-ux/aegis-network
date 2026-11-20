"""Evaluate the sealed synthetic Phase 5A corpus; external inference requires approval."""

import argparse
import json
import os
from pathlib import Path

from aegis.intelligence.openai_eval import _verified_cases, approval_template, evaluate_openai


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("offline", "model"), default="offline")
    parser.add_argument("--approval-file", type=Path,
                        help="user-supplied, exact-scope approval JSON; required only for model mode")
    parser.add_argument("--approval-template", type=Path,
                        help="write a disabled approval template for review; makes no model calls")
    args = parser.parse_args()
    if args.approval_template:
        _, seal = _verified_cases(args.root.resolve())
        args.approval_template.write_text(json.dumps(approval_template(seal), indent=2, sort_keys=True) + "\n")
    if args.mode == "offline" and args.approval_file:
        parser.error("approval file is only valid in model mode")
    if args.mode == "model" and not args.approval_file:
        parser.error("model mode requires an explicit approval file")
    report = evaluate_openai(args.root, approval_path=args.approval_file,
                             api_key=os.environ.get("OPENAI_API_KEY") if args.mode == "model" else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"planned_cases": report["baseline"]["planned"],
                      "baseline_correct": report["baseline"]["correct"],
                      "baseline_inconclusive": report["baseline"]["inconclusive"],
                      "model_status": report["model_status"],
                      "model_benefit": report["model_benefit"]}, sort_keys=True))


if __name__ == "__main__":
    main()
