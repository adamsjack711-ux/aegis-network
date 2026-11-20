"""Measure phase-specific loss and hold timing in the disposable localhost identity lab."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns, sleep, time_ns

ROOT = Path(__file__).resolve().parents[1]


def observe():
    # This process receives only the observer credential and scoped target endpoints.
    from aegis.identity_lab.transport import Client, Credentials, Endpoint

    config = json.load(sys.stdin)
    client = Client(Credentials(Path(config["credentials"])))
    trials = []
    for data in config["targets"]:
        endpoint = Endpoint(**data)
        request_ns = monotonic_ns()
        result = client.call(endpoint, "/read")
        trials.append({"target": endpoint.name, "request_ns": request_ns,
                       "denial_observed_ns": monotonic_ns(), "result": result})
    json.dump(trials, sys.stdout)


def readback(lab):
    from test_fencing import disk_state

    samples = {}
    deadline = monotonic_ns() + 3_000_000_000
    while len(samples) < len(lab.targets) and monotonic_ns() < deadline:
        for target in lab.targets:
            if target in samples:
                continue
            started = monotonic_ns()
            state = disk_state(lab, target)
            if state["fence"]["held"]:
                samples[target] = {"sql_started_ns": started, "sql_confirmed_ns": monotonic_ns(),
                                   "state": state}
        if len(samples) < len(lab.targets):
            sleep(0.002)
    assert len(samples) == len(lab.targets), samples
    return samples


def reports(lab, name, kind, count):
    deadline = monotonic_ns() + 2_000_000_000
    while monotonic_ns() < deadline:
        lines = (lab.root / name / "service.log").read_text().splitlines()
        events = [json.loads(line) for line in lines if line.startswith('{"event": "' + kind + '"')]
        if len(events) == count:
            return events
        sleep(0.002)
    raise RuntimeError(f"did not receive {count} reports of type {kind} on {name}")


def run(directory, mode):
    from conftest import Lab, running
    from test_fencing import claim, disk_state, plan, recover

    lease = 2_000_000_000 if mode == "expiry" else 30_000_000_000
    with running(Lab(directory, lease_ns=lease)) as lab:
        assignment = claim(lab)
        writes = {}
        for target in lab.targets:
            request = plan(lab, assignment, target)
            start = monotonic_ns()
            response = lab.call("agent-a", "broker-a", "/write", request)
            writes[target] = {"request_ns": start, "reply_ns": monotonic_ns(), "response": response}
            assert disk_state(lab, target)["marker"] == "observing"
        if mode == "anchor-loss":
            lab.stop("broker-a")
            started = monotonic_ns()
            lab.stop("anchor")
            loss = {"fault_start_ns": started, "fault_confirmed_ns": monotonic_ns(),
                    "former_broker_offline": True}
        elif mode == "retirement":
            started = monotonic_ns()
            state = recover(lab)
            loss = {"request_start_ns": started, "retired_confirmed_ns": monotonic_ns(),
                    "retired_floor": state["generation"]}
        else:
            wall_before, monotonic_now, wall_after = time_ns(), monotonic_ns(), time_ns()
            loss = {"lease_expires_wall_ns": assignment.expires_ns,
                    "wall_before_ns": wall_before, "sample_monotonic_ns": monotonic_now,
                    "wall_after_ns": wall_after,
                    "earliest_projected_expiry_ns": monotonic_now + assignment.expires_ns - wall_after,
                    "latest_projected_expiry_ns": monotonic_now + assignment.expires_ns - wall_before}
            sleep(max(0, (assignment.expires_ns - time_ns()) / 1e9))
        durable = readback(lab)
        observer_args = {"credentials": str(directory / "observer"),
                         "targets": [vars(lab.endpoints[target]) for target in lab.targets]}
        observed = json.loads(subprocess.check_output(
            [sys.executable, str(Path(__file__).resolve()), "--observer"], text=True,
            input=json.dumps(observer_args),
            env={"PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"}, timeout=5,
        ))
        serving = {row["target"]: row for row in observed}
        assert min(sample["request_ns"] for sample in observed) > max(
            row["sql_confirmed_ns"] for row in durable.values())
        for target, row in durable.items():
            assert row["state"]["marker"] == "quarantined"
            assert row["state"]["receipts"] == [(assignment.generation, "observing")]
            assert serving[target]["result"]["effective"] == "quarantined"
            assert disk_state(lab, target) == row["state"]
            row["report"] = reports(lab, target, "durable-hold", 1)[0]
            row["report_collected_ns"] = monotonic_ns()
        acknowledgments = reports(lab, "home", "retirement-ack", len(lab.targets)) if mode == "retirement" else []
        assert all(row["commit_observed_ns"] <= row["report_ns"] for row in
                   (sample["report"] for sample in durable.values()))
        return {"mode": mode, "assignment_generation": assignment.generation,
                "lease_ns": lease, "loss": loss, "writes_before_loss": writes,
                "durable_hold": durable, "serving_denial": serving, "target_retirement_acks": acknowledgments,
                "broker_ack_ns": None}


def main():
    if sys.argv[1:] == ["--observer"]:
        observe()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--anchor-samples", type=int, default=8)
    parser.add_argument("--expiry-samples", type=int, default=4)
    parser.add_argument("--retirement-samples", type=int, default=6)
    args = parser.parse_args()
    if os.getenv("AEGIS_PHASE4E_LIVE") != "1":
        parser.error("set AEGIS_PHASE4E_LIVE=1 to opt in to disposable fixture credentials")
    sizes = {"anchor-loss": args.anchor_samples, "expiry": args.expiry_samples,
             "retirement": args.retirement_samples}
    if min(sizes.values()) <= 0:
        parser.error("sample counts must be positive")
    sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/identity_lab")]
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    environment = {"source_commit": source, "when_utc": datetime.now(timezone.utc).isoformat(),
                   "project": "disposable loopback mTLS", "clock": "one host monotonic clock",
                   "host": platform.platform(), "python": platform.python_version()}
    trials = []
    for mode, count in sizes.items():
        for _ in range(count):
            with TemporaryDirectory(prefix="phase4e-watchdog-") as directory:
                trials.append(run(Path(directory), mode))
    args.output.write_text(json.dumps({"environment": environment, "trials": trials}, indent=2) + "\n")


if __name__ == "__main__":
    main()
