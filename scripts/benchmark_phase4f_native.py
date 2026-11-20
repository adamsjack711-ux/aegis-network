"""Disposable one-host native ownership-loss ordering measurements."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time

from test_native_enforcement import active_lab, confirm, snapshot, wait_for_hold


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=8)
    parser.add_argument("--fault", choices=("ownership", "status"), default="ownership")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    with TemporaryDirectory(prefix="aegis-phase4f-") as scratch:
        for index in range(args.trials):
            path = Path(scratch) / str(index)
            path.mkdir()
            status = {"current": True}
            lab, home, session = active_lab(path, status_current=lambda: status["current"])
            with lab:
                confirm(lab, session)
                cut_ns = time.monotonic_ns()
                if args.fault == "ownership":
                    home.fence(session.assignment.generation)
                else:
                    status["current"] = False
                fences = wait_for_hold(lab.store)
                hold_read_ns = time.monotonic_ns()
                before = snapshot(lab.store.path)
                observed = lab.observer.observe("quarantined", fences)
                observer_done_ns = time.monotonic_ns()
                rows.append({"trial": index + 1, "cut_to_hold_read_ms": (hold_read_ns - cut_ns) / 1e6,
                             "cut_to_observer_done_ms": (observer_done_ns - cut_ns) / 1e6,
                             "observer_started_after_hold_read": observed.started_ns >= hold_read_ns,
                             "observer_requests": observed.requests,
                             "observation_changed_database": snapshot(lab.store.path) != before,
                             "fences": fences})
    result = {"profile": "disposable native one-host SQLite and loopback HTTP",
              "fault": args.fault,
              "trials": rows, "source": "scripts/benchmark_phase4f_native.py"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"trials": len(rows), "all_holds_before_observer": all(
        row["observer_started_after_hold_read"] for row in rows), "max_hold_ms": max(
        row["cut_to_hold_read_ms"] for row in rows)}, sort_keys=True))


if __name__ == "__main__":
    main()
