"""Compare isolated repeat verification to cohort-local shared verification."""

import argparse
import hashlib
import json
import platform
import random
import resource
import statistics
import time
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from aegis.evidence import Evidence, runner
from aegis.evidence.synthetic import create_lab

SCENARIOS = ("cold", "warm", "distinct", "cohorts", "one-per-ten")
FIXTURES = (
    ("feature-gate", True, True, "reproduced"),
    ("route-toggle", False, True, "not-reproduced"),
    ("service-access", True, False, "inconclusive"),
)


def cpu_seconds():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def workload(lab, deployments, scenario, seed):
    requests = []
    for index in range(deployments):
        family, marker, observer, truth = FIXTURES[index % len(FIXTURES)]
        cohort = "lab-green" if scenario == "cohorts" and index % 2 else "lab-blue"
        distinct = {
            "distinct": index,
            "one-per-ten": index // (10 * len(FIXTURES)),
        }.get(scenario, 0)
        bundle = lab.bundle(f"{family}-{distinct}", family=family, marker=marker, observer=observer, cohort=cohort)
        requests.append((bundle, cohort, truth))
    random.Random(seed).shuffle(requests)
    return requests


def measure(lab, requests, stages, shared):
    outcomes = Counter()
    worker_attempts = 0
    observed_cpu, elapsed = cpu_seconds(), time.perf_counter()
    real_run = runner.run

    def counted(*args):
        nonlocal worker_attempts
        worker_attempts += 1
        return real_run(*args)

    def observe(service, bundle, cohort, truth):
        result = service.verify(bundle, cohort=cohort)
        if result.reason == "worker-unavailable":
            raise RuntimeError("benchmark worker failure")
        # Both arms pay for independent local intake and signature appraisal.
        with Evidence(":memory:", lab.trust, clock=lambda: lab.now) as local:
            for wire in result.attestations:
                local.accept_attestation(bundle, wire, cohort=cohort)
            actual = local.assess(bundle, cohort=cohort).outcome
        if actual != truth or result.outcome != truth:
            raise RuntimeError(f"unexpected synthetic outcome: {actual} != {truth}")
        outcomes[actual] += 1

    stage_metrics = {}
    with patch.object(runner, "run", counted):
        with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: lab.now) as coordinator:
            for stage in stages:
                stage_cpu, stage_start, stage_attempts = cpu_seconds(), time.perf_counter(), worker_attempts
                for bundle, cohort, truth in requests:
                    if shared:
                        observe(coordinator, bundle, cohort, truth)
                    else:
                        with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: lab.now) as independent:
                            observe(independent, bundle, cohort, truth)
                stage_metrics[stage] = {
                    "cpu_seconds": round(cpu_seconds() - stage_cpu, 6),
                    "wall_seconds": round(time.perf_counter() - stage_start, 6),
                    "worker_attempts": worker_attempts - stage_attempts,
                }
    return {
        "cpu_seconds": round(cpu_seconds() - observed_cpu, 6),
        "wall_seconds": round(time.perf_counter() - elapsed, 6),
        "worker_attempts": worker_attempts,
        "outcomes": dict(outcomes),
        "stages": stage_metrics,
    }


def run_scenario(deployments, scenario, repetitions):
    samples = []
    for offset in range(repetitions):
        seed = 20261119 + offset
        lab = create_lab(1_800_000_000)
        requests = workload(lab, deployments, scenario, seed)
        stages = ("cold", "warm") if scenario == "warm" else ("cold",)
        order = ("repeated", "shared") if offset % 2 == 0 else ("shared", "repeated")
        arms = {arm: measure(lab, requests, stages, arm == "shared") for arm in order}
        unique_keys = len({(cohort, bundle.sha256) for bundle, cohort, _ in requests})
        if arms["repeated"]["worker_attempts"] != 2 * deployments * len(stages):
            raise RuntimeError("repeated arm skipped an independent verifier")
        if arms["shared"]["worker_attempts"] != 2 * unique_keys:
            raise RuntimeError("shared arm did not perform exactly two attempts per key")
        samples.append({
            "seed": seed, "order": order, "distinct_keys": unique_keys,
            **arms, "cpu_ratio": round(arms["repeated"]["cpu_seconds"] / arms["shared"]["cpu_seconds"], 4),
        })
    ratios = [sample["cpu_ratio"] for sample in samples]
    return {
        "deployments": deployments, "scenario": scenario, "pairs": samples,
        "paired_cpu_ratio_median": statistics.median(ratios), "paired_cpu_ratio_range": [min(ratios), max(ratios)],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployments", type=int, nargs="+", default=[10, 100])
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=["cold", "warm", "distinct"])
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if min(args.deployments) < 3 or args.repetitions < 1:
        parser.error("use at least three deployments and one repetition")
    root = Path(__file__).resolve().parent.parent
    source_files = sorted((root / "src/aegis/evidence").glob("*.py")) + [Path(__file__).resolve()]
    report = {
        "protocol": "phase3a-shared-versus-repeated-v1",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "worker_sha256": runner.WORKER_SHA256,
            "environment_sha256": runner.ENVIRONMENT_SHA256,
            "source_sha256": {
                str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files
            },
        },
        "scenarios": [
            run_scenario(size, scenario, args.repetitions) for size in args.deployments for scenario in args.scenarios
        ],
    }
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
