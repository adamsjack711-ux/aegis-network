"""Reproduce private Phase 5A-1 offline evaluation; never enroll a model or feed."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path

from aegis.intelligence.phase5a1_eval import evaluate_phase5a1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip():
        raise ValueError("benchmark requires clean source worktree")
    report = evaluate_phase5a1(root)
    report["source_pin"] = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                                    cwd=root, text=True).strip()
    report["environment"] = {"python": sys.version.split()[0], "platform": platform.platform(),
                             "machine": platform.machine()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"source_pin": report["source_pin"], "v_total": report["v_total"],
                      "visible_first": report["visible36_trials"][0]["baseline"],
                      "real_model": report["real_model"]}, sort_keys=True))


if __name__ == "__main__":
    main()
