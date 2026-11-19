"""Compare paired, preprovisioned legacy and Trust executions of the same fixture."""

import argparse
import json
from pathlib import Path
import platform
import resource
import statistics
from tempfile import TemporaryDirectory

from test_trust_composition import run_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=int, default=12)
    args = parser.parse_args()
    if args.pairs < 2:
        parser.error("at least two pairs are required")
    pairs = []
    for index in range(args.pairs):
        order = ("legacy", "trust") if index % 2 == 0 else ("trust", "legacy")
        pair = {"order": order}
        for arm in order:
            with TemporaryDirectory(prefix="aegis-phase4d-native-") as directory:
                timing = run_fixture(Path(directory), "none" if arm == "trust" else arm)
                pair[arm] = {key: value for key, value in timing.items() if key != "confirmed_ns"}
        pairs.append(pair)

    def percentiles(arm, stage):
        values = [pair[arm][stage] / 1e6 for pair in pairs]
        q = statistics.quantiles(values, n=100, method="inclusive")
        return {f"p{p}": round(q[p - 1], 3) for p in (50, 95, 99)}

    stages = pairs[0]["trust"]
    rss_scale = 1 if platform.system() == "Darwin" else 1024
    report = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "clock": "one host monotonic wall intervals plus process CPU, from plan request to probe confirmation",
        "confirmed_per_arm": len(pairs),
        "process_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * rss_scale,
        "percentiles_ms": {arm: {stage: percentiles(arm, stage) for stage in stages}
                           for arm in ("legacy", "trust")},
        "pairs_ns": pairs,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
