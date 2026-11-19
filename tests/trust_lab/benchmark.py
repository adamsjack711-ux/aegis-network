"""Measure full-prefix reconciliation with ephemeral stores and no network."""

import argparse
import json
import platform
import statistics
import tempfile
import time
from pathlib import Path

import cryptography

from aegis.evidence.records import digest
from aegis.trust_lab.history import Subject

from trust_fixtures import Scenario


def summarize(samples):
    ordered = sorted(samples)
    p95 = statistics.quantiles(ordered, n=100, method="inclusive")[94] if len(ordered) > 1 else ordered[0]
    return {label: round(value / 1e6, 3) for label, value in (
        ("median", statistics.median(ordered)), ("p95", p95), ("max", ordered[-1]),
    )}


def measure(event_count, repeats, warmup):
    with tempfile.TemporaryDirectory(prefix="aegis-trust-benchmark-") as tmp:
        lab = Scenario(Path(tmp))
        lab.seed()
        for index in range(event_count - 3):
            subject = Subject(finding=digest(f"fixture-{index}".encode()), evidence=lab.subject.evidence)
            lab.admit(lab.event(f"unrelated-{index}", "finding", "publisher", subject=subject))
        lab.clock.advance()
        samples = {name: [] for name in ("coverage", "status", "reconciliation", "commit", "total")}
        for trial in range(warmup + repeats):
            start = time.perf_counter_ns()
            challenge = lab.begin()
            cut = lab.cut(challenge, signers=("w0", "w1", "w2"))
            covered = time.perf_counter_ns()
            status = lab.status(cut)
            issued = time.perf_counter_ns()
            plan = lab.reconcile(challenge, cut, status=status)
            verified = time.perf_counter_ns()
            result = lab.apply(plan)
            finished = time.perf_counter_ns()
            assert result["fence"] == trial + 1
            if trial >= warmup:
                durations = (covered - start, issued - covered, verified - issued,
                             finished - verified, finished - start)
                for name, duration in zip(samples, durations, strict=True):
                    samples[name].append(duration)
        return {"events": event_count, "milliseconds": {name: summarize(values) for name, values in samples.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", nargs="+", type=int, default=[3, 32, 128])
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=3)
    args = parser.parse_args()
    if min(args.events) < 3 or args.repeats < 1 or args.warmup < 0:
        parser.error("use at least three events, one repeat, and zero or more warmups")
    print(json.dumps({
        "environment": platform.platform(), "python": platform.python_version(),
        "cryptography": cryptography.__version__, "repeats": args.repeats, "warmup": args.warmup,
        "runs": [measure(events, args.repeats, args.warmup) for events in args.events],
    }, indent=2))


if __name__ == "__main__":
    main()
