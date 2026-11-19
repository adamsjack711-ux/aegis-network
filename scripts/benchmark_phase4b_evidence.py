"""Compare four Phase 4B strategies with independently appraised synthetic evidence."""

import argparse
import json
import os
import platform
import random
import resource
import subprocess
import sys
import time
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from aegis.evidence import Bundle, Evidence, runner
from aegis.evidence.records import SignedAttestation, decode, digest
from aegis.evidence.synthetic import create_lab, portability_bundle

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "tests/fixtures/phase4b_portability.json"
PROFILES = frozenset(runner.PORTABILITY_PROFILES.values())
ARMS = ("independent", "exact-shared", "compatible-shared", "private-cohorts")
SCENARIOS = ("clustered", "heterogeneous")
SEED = 20261119
COHORTS = ("lab-blue", "lab-green")
NOW = 1_800_000_000


@dataclass(frozen=True)
class Request:
    target: Bundle
    candidate: Bundle
    cohort: str
    expected: str
    compatible_expected: bool


def workload(labs, size, scenario, seed):
    cases = json.loads(MATRIX.read_bytes())
    if scenario == "clustered":
        cases = [case for case in cases if case["id"] in {
            "original", "packaging-only", "configuration", "runtime-offline",
        }]
    randomizer = random.Random(seed)
    requests = []
    for index in range(size):
        case = cases[index % len(cases)]
        assigned_cohort = randomizer.choice(COHORTS)
        cohort = assigned_cohort if len(labs) > 1 else COHORTS[0]
        lab = labs[cohort]
        group = 0 if scenario == "clustered" else index // (4 * len(cases))
        claim = f"phase4b-marker-{group}"
        candidate = portability_bundle(lab, claim, cohort=cohort)
        target = candidate if case["id"] == "original" else portability_bundle(
            lab, claim, cohort=cohort, source_sha256=candidate.sha256, **case["changes"],
        )
        requests.append(Request(target, candidate, cohort, case["outcome"], case["compatible"]))
    randomizer.shuffle(requests)
    return requests


def rusage():
    parent = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = parent.ru_utime + parent.ru_stime + children.ru_utime + children.ru_stime
    rss_unit = 1 if sys.platform == "darwin" else 1024
    return cpu, parent.ru_maxrss * rss_unit, children.ru_maxrss * rss_unit


def quantiles(samples):
    if not samples:
        return None
    ordered = sorted(samples)
    return {f"p{p}_ms": round(ordered[(len(ordered) * p + 99) // 100 - 1] * 1000, 4)
            for p in (50, 95, 99)}


def measure(size, scenario, seed, arm):
    cohorts = COHORTS if arm == "private-cohorts" else COHORTS[:1]
    labs = {cohort: create_lab(NOW, cohorts=frozenset({cohort})) for cohort in cohorts}
    requests = workload(labs, size, scenario, seed)
    options = {"clock": lambda: NOW, "profiles": PROFILES}
    outcomes, counts = Counter(), Counter()
    assessed_latencies, finding_latencies = [], []
    first_finding = None
    attempts = 0
    real_run = runner.run

    def counted(*args):
        nonlocal attempts
        attempts += 1
        return real_run(*args)

    def assess(depot, local, request, seen):
        target, source, cohort = request.target, request.candidate, request.cohort
        # An untrusted cache index offers a candidate. A local relying deployment
        # rechecks it. Only already requested source scopes can be offered.
        if arm == "compatible-shared" and target.sha256 not in seen and source.sha256 in seen:
            candidate = depot.assess(source, cohort=cohort)
            for wire in candidate.attestations:
                local.accept_attestation(source, wire, cohort=cohort)
            match = local.assess_compatible(source, target, cohort=cohort)
            if match is not None:
                counts["compatibility_transfers"] += 1
                return match.source, match.target_sha256, True

        exact = depot.verify(target, cohort=cohort)
        for wire in exact.attestations:
            local.accept_attestation(target, wire, cohort=cohort)
        seen.add(target.sha256)
        return local.assess(target, cohort=cohort), exact.bundle_sha256, False

    cpu_start, _, _ = rusage()
    start = time.perf_counter()
    seen = set()
    with patch.object(runner, "run", counted), ExitStack() as ledgers:
        depots = {}
        if arm != "independent":
            depots = {cohort: ledgers.enter_context(Evidence(":memory:", lab.trust, lab.verifiers, **options))
                      for cohort, lab in labs.items()}
        for request in requests:
            before, attempt_start = time.perf_counter(), attempts
            lab = labs[request.cohort]
            with Evidence(":memory:", lab.trust, **options) as local:
                if arm == "independent":
                    with Evidence(":memory:", lab.trust, lab.verifiers, **options) as independent:
                        result, target_digest, transferred = assess(independent, local, request, seen)
                else:
                    result, target_digest, transferred = assess(depots[request.cohort], local, request, seen)

            hit = attempts == attempt_start and bool(result.attestations)
            anchor = request.candidate.sha256 if transferred else request.target.sha256
            scoped = (
                (not transferred or request.compatible_expected)
                and target_digest == request.target.sha256
                and result.bundle_sha256 == anchor
                and bool(result.attestations)
                and all(
                    (body := decode(SignedAttestation, wire).body).bundle_sha256 == anchor
                    and body.cohort == request.cohort for wire in result.attestations
                )
            )
            elapsed = time.perf_counter() - before
            assessed_latencies.append(elapsed)
            outcomes[result.outcome] += 1
            correct = scoped and result.outcome == request.expected
            if correct:
                counts["correct"] += 1
                if result.outcome != "inconclusive":
                    counts["correct_conclusive"] += 1
                if result.outcome == "reproduced":
                    finding_latencies.append(elapsed)
                    if first_finding is None:
                        first_finding = time.perf_counter() - start
            if hit:
                field = "inconclusive_cache_hits" if result.outcome == "inconclusive" else "conclusive_cache_hits"
                counts[field] += 1
                if not correct:
                    counts["incorrect_cache_reuse"] += 1

    wall = time.perf_counter() - start
    cpu_end, parent_rss, child_rss = rusage()
    cpu = cpu_end - cpu_start
    hits = counts["conclusive_cache_hits"] + counts["inconclusive_cache_hits"]
    return {
        "distinct_exact_scopes": len({r.target.sha256 for r in requests}),
        "worker_attempts": attempts,
        "cohorts": len(labs),
        "cpu_seconds": round(cpu, 6),
        "wall_seconds": round(wall, 6),
        "parent_peak_rss_bytes": parent_rss,
        "worker_peak_rss_bytes": child_rss,
        "aggregate_peak_rss_upper_bound_bytes": parent_rss + child_rss,
        "outcomes": {outcome: outcomes[outcome] for outcome in ("reproduced", "not-reproduced", "inconclusive")},
        "expected_outcomes": dict(Counter(request.expected for request in requests)),
        "correct_assessments": counts["correct"],
        "decision_accuracy": counts["correct"] / size,
        "accuracy_among_conclusive": counts["correct_conclusive"] / (size - outcomes["inconclusive"])
        if size > outcomes["inconclusive"] else None,
        "reproduction_rate": outcomes["reproduced"] / size,
        "inconclusive_rate": outcomes["inconclusive"] / size,
        "conclusive_cache_hits": counts["conclusive_cache_hits"],
        "inconclusive_cache_hits": counts["inconclusive_cache_hits"],
        "cache_hit_rate": hits / size,
        "incorrect_cache_reuse": counts["incorrect_cache_reuse"],
        "incorrect_reuse_per_hit": counts["incorrect_cache_reuse"] / hits if hits else None,
        "compatibility_transfers": counts["compatibility_transfers"],
        "time_to_assessment": quantiles(assessed_latencies),
        "time_to_verified_finding": quantiles(finding_latencies),
        "time_to_first_verified_finding_ms": round(first_finding * 1000, 4) if first_finding is not None else None,
        "cpu_ms_per_correctly_assessed_deployment": round(1000 * cpu / counts["correct"], 4)
        if counts["correct"] else None,
        "cpu_ms_per_correct_conclusive_deployment": round(1000 * cpu / counts["correct_conclusive"], 4)
        if counts["correct_conclusive"] else None,
    }


def run(args):
    source_files = sorted((ROOT / "src/aegis/evidence").glob("*.py")) + [MATRIX, Path(__file__).resolve()]
    experiment = {
        "protocol": "phase4b-evidence-portability-v1",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "logical_cpus": os.cpu_count(),
            "worker_profile": {name: vars(profile) for name, profile in runner.PORTABILITY_PROFILES.items()},
            "source_sha256": {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in source_files},
        },
        "runs": [],
    }
    for size in args.deployments:
        for scenario in args.scenarios:
            for repeat in range(args.repetitions):
                order = list(ARMS)
                random.Random(SEED + repeat).shuffle(order)
                result = {"deployments": size, "scenario": scenario, "seed": SEED + repeat, "order": order, "arms": {}}
                for arm in order:
                    # Fresh parent and worker RSS high-water counters for each arm.
                    command = [sys.executable, __file__, "--sample", str(size), scenario, str(SEED + repeat), arm]
                    sample = json.loads(subprocess.check_output(command, cwd=ROOT))
                    expected_jobs = size if arm == "independent" else sample["distinct_exact_scopes"]
                    if arm != "compatible-shared" and sample["worker_attempts"] != 2 * expected_jobs:
                        raise RuntimeError(f"{arm} diverged from the two-worker schedule")
                    result["arms"][arm] = sample
                experiment["runs"].append(result)
                print(f"{size} {scenario} seed {SEED + repeat} complete", file=sys.stderr, flush=True)
    report = json.dumps(experiment, indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
    else:
        print(report, end="")
    if any(arm["incorrect_cache_reuse"] or arm["decision_accuracy"] != 1
           for run in experiment["runs"] for arm in run["arms"].values()):
        raise SystemExit("A benchmark arm differed from the frozen oracle.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployments", type=int, nargs="+", default=[10, 100, 1000])
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=SCENARIOS)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sample", nargs=4, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.sample:
        size, scenario, seed, arm = args.sample
        print(json.dumps(measure(int(size), scenario, int(seed), arm)))
    else:
        if min(args.deployments) < 1 or args.repetitions < 1:
            parser.error("use at least one deployment and one repetition")
        run(args)


if __name__ == "__main__":
    main()
