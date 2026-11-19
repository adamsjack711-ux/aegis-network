"""Manually approved, disposable Phase 3B demonstration."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time

from .lab import Lab
from .observer import ObservationError
from .policy import Denied


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lease-ms", type=int, default=3000)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="aegis-phase3b-") as directory:
        with Lab(Path(directory) / "fixture.sqlite3") as lab:
            started_ns = time.monotonic_ns()
            try:
                plan = lab.controller.prepare(args.lease_ms)
                print(json.dumps(asdict(plan), indent=2))
                print(f"Exact plan digest {plan.digest}")
                approval = lab.operator.approve(plan, input("Paste the exact digest to approve this local lab plan. "))
                confirmed_ns = lab.execute(plan, approval)
            except (Denied, ObservationError, EOFError) as exc:
                parser.exit(1, f"Lab rollout declined. {exc}\n")
            elapsed_ms = (confirmed_ns - started_ns) / 1_000_000
            print(f"Confirmed protection across {len(plan.targets)} replicas in {elapsed_ms:.3f} ms including approval.")
            outcome = lab.controller.rollback("operator demo complete")
            print(f"Rollback outcome {outcome}")
            if outcome != "safe_hold":
                parser.exit(1)


if __name__ == "__main__":
    main()
