"""Measure actual loopback protection and recovery in fresh Phase 3B labs."""

import argparse
from collections import Counter
from contextlib import contextmanager
from hashlib import sha256
from http.client import HTTPConnection, HTTPException
import json
import math
import os
from pathlib import Path
import platform
import sqlite3
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time

from aegis.mitigation.lab import Lab
from aegis.mitigation.observer import ObservationError
from aegis.mitigation.policy import Denied, MARKER_PATH, TARGETS


def elapsed_ms(start, end):
    return round((end - start) / 1_000_000, 3)


def percentiles(samples):
    if not samples:
        return {}
    ordered = sorted(samples)
    return {f"p{p}": ordered[math.ceil(len(ordered) * p / 100) - 1] for p in (50, 95, 99)}


@contextmanager
def background_requests(lab, enabled):
    stop = Event()
    counters = {target: Counter() for target in TARGETS}

    def send(target):
        while not stop.is_set():
            connection = HTTPConnection(*lab.endpoints[target], timeout=0.25)
            try:
                connection.request("GET", "/ok")
                response = connection.getresponse()
                expected = f"{target}:/ok".encode()
                outcome = "healthy" if (response.status, response.read(256)) == (200, expected) else "bad"
            except (OSError, HTTPException):
                outcome = "bad"
            finally:
                connection.close()
            counters[target][outcome] += 1
            stop.wait(0.01)

    workers = [Thread(target=send, args=(target,)) for target in TARGETS] if enabled else []
    for worker in workers:
        worker.start()
    try:
        yield counters
    finally:
        stop.set()
        for worker in workers:
            worker.join()


def marker_state(lab, target):
    connection = HTTPConnection(*lab.endpoints[target], timeout=0.25)
    try:
        connection.request("GET", MARKER_PATH)
        response = connection.getresponse()
        return response.status, response.read(256)
    finally:
        connection.close()


def protection_trial(lab, loaded):
    result = {"outcome": "inconclusive"}
    with background_requests(lab, loaded) as requests:
        started = time.monotonic_ns()
        try:
            plan = lab.controller.prepare(3000)
            reviewed = time.monotonic_ns()
            approval = lab.operator.approve(plan, plan.digest)
            approved = time.monotonic_ns()
            confirmed = lab.execute(plan, approval)
            events = {record["event"]: record for record in lab.store.history()}
            evidence = events["confirmed"]["detail"]
            result.update(
                outcome="confirmed",
                time_to_confirmed_ms=elapsed_ms(started, confirmed),
                plan_ms=elapsed_ms(started, reviewed),
                scripted_approval_ms=elapsed_ms(reviewed, approved),
                preflight_and_lease_ms=elapsed_ms(approved, events["leased"]["at_ns"]),
                lease_to_verified_canary_ms=elapsed_ms(events["leased"]["at_ns"], events["canary_verified"]["at_ns"]),
                verified_canary_to_confirmation_ms=elapsed_ms(events["canary_verified"]["at_ns"], confirmed),
                final_observation_requests=evidence["requests"],
                post_confirmation_marker_probes=0,
                post_confirmation_marker_escapes=0,
            )
            for _ in range(8):
                for target in TARGETS:
                    status, body = marker_state(lab, target)
                    result["post_confirmation_marker_probes"] += 1
                    if status == 200 or body == f"{target}:{MARKER_PATH}".encode():
                        result["post_confirmation_marker_escapes"] += 1
            lab.observer.observe("restricted", tuple((target, 1) for target in TARGETS))
            if result["post_confirmation_marker_escapes"]:
                result["outcome"] = "marker_escape"
        except (Denied, ObservationError, OSError, HTTPException, sqlite3.Error) as exc:
            result["outcome"] = "failed"
            result["reason"] = str(exc)
    result["load_requests"] = sum(counts.total() for counts in requests.values())
    result["bad_load_requests"] = sum(counts["bad"] for counts in requests.values())
    result["rollback"] = lab.controller.rollback("end of benchmark episode")
    return result


def recovery_trial(lab):
    plan = lab.controller.prepare(3000)
    lab.execute(plan, lab.operator.approve(plan, plan.digest))
    started = time.monotonic_ns()
    lab.upstreams["replica-a"].close()
    while time.monotonic_ns() - started < 2_000_000_000:
        if lab.store.status() == "safe_hold":
            finished = time.monotonic_ns()
            return {
                "outcome": "safe_hold",
                "outage_to_observed_safe_hold_ms": elapsed_ms(started, finished),
                "marker_paths_quarantined": sum(marker_state(lab, target)[0] == 503 for target in TARGETS),
            }
        time.sleep(0.005)
    return {"outcome": "timeout"}


def fresh_lab(trial, *args):
    try:
        with TemporaryDirectory(prefix="aegis-phase3b-bench-") as directory:
            with Lab(Path(directory) / "fixture.db") as lab:
                return trial(lab, *args)
    except (Denied, ObservationError, OSError, HTTPException, sqlite3.Error) as exc:
        return {"outcome": "failed", "reason": str(exc)}


def summarize(results, metric, expected):
    outcomes = Counter(row["outcome"] for row in results)
    successes = [row[metric] for row in results if row["outcome"] == expected]
    # A missing observation never improves the primary empirical percentiles.
    ranks = percentiles(successes + [float("inf")] * (len(results) - len(successes)))
    return {
        "attempts": len(results),
        "outcomes": dict(outcomes),
        "ms": {key: value if math.isfinite(value) else None for key, value in ranks.items()},
        "successful_only_ms": percentiles(successes),
        "trials": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--recovery-repetitions", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 500 or not 1 <= args.recovery_repetitions <= 100:
        parser.error("repetitions outside the benchmark bounds")

    idle, loaded = [], []
    for index in range(args.repetitions):
        arms = [(idle, False), (loaded, True)]
        if index % 2:
            arms.reverse()
        for results, enabled in arms:
            results.append(fresh_lab(protection_trial, enabled))
    recovery = [fresh_lab(recovery_trial) for _ in range(args.recovery_repetitions)]
    sources = sorted((Path(__file__).resolve().parents[1] / "src/aegis/mitigation").glob("*.py"))
    sources.append(Path(__file__).resolve())
    report = {
        "format": 1,
        "environment": {
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "source_sha256": {source.name: sha256(source.read_bytes()).hexdigest() for source in sources},
        },
        "protocol": {
            "clock": "time.monotonic_ns on the lab host",
            "start": "fresh local lab scenario handed to prepare, after fixture and proxies started",
            "stop": "recorder reads the clock immediately after SQLite confirmation commits",
            "approval": "scripted, exact-plan scoped; excludes human and remote delivery delays",
            "replicas": list(TARGETS),
            "lease_ms": 3000,
            "loaded_arm": "one benign client per replica, 10 ms pause after each response",
            "recovery": "stop an upstream after confirmation, then poll for independently verified safe hold",
            "percentiles": "nearest rank; null for a percentile reached by a non-completion",
        },
        "protection": {
            "idle": summarize(idle, "time_to_confirmed_ms", "confirmed"),
            "benign_load": summarize(loaded, "time_to_confirmed_ms", "confirmed"),
        },
        "recovery": summarize(recovery, "outage_to_observed_safe_hold_ms", "safe_hold"),
    }
    print(json.dumps(report, indent=2))
    passed = all(
        row["outcome"] == "confirmed"
        and row["rollback"] == "safe_hold"
        and row["post_confirmation_marker_escapes"] == 0
        and row["bad_load_requests"] == 0
        for row in idle + loaded
    ) and all(row["outcome"] == "safe_hold" and row["marker_paths_quarantined"] == len(TARGETS) for row in recovery)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
