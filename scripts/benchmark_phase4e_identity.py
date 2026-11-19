"""Collect raw Phase 4E results using disposable credentials and an internal Docker bridge."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "identity_lab"))

from conftest import running
from docker_lab import DockerLab
from test_fencing import offer, plan, raw_receipts, read

from aegis.identity_lab.protocol import Assignment, SessionRequest, Stamp
from aegis.identity_lab.transport import Endpoint


def measured(lab, caller, service, route, body=None, *, expect="ok"):
    trial = lab.measure(caller, lab.endpoints[service], route, body)
    if trial["outcomes"] != [expect]:
        raise RuntimeError(f"{caller} {service}{route}: {trial}")
    return trial


def retire(lab):
    stamp = measured(lab, "operator", "anchor", "/stamp")
    retired = measured(lab, "operator", "home", "/recover", Stamp.model_validate(stamp["result"]))
    return retired["result"]["generation"], stamp["samples_ns"][0], retired["samples_ns"][0]


def acquire(lab, agent, broker, generation):
    proof = offer(lab, agent, broker, generation)
    trial = measured(lab, agent, broker, "/claim", proof)
    return Assignment.model_validate(trial["result"]), trial["samples_ns"][0]


def round_trips(lab, count):
    endpoint = lab.endpoints["target-a"]
    loopback = Endpoint("127.0.0.1", endpoint.port, endpoint.name)
    control = lab.driver("observer-control", credential="observer",
                         network="container:" + lab.container(endpoint.name))
    samples = {}
    for label, address, runner in (("bridge", endpoint, None), ("loopback", loopback, control)):
        results = lab.measure("observer", address, "/ping", count=count + 5, driver=runner)
        if any(outcome != "ok" for outcome in results["outcomes"]):
            raise RuntimeError(f"transport trial failed: {results}")
        samples[label] = {"warmup_ns": results["samples_ns"][:5], "samples_ns": results["samples_ns"][5:]}
    return samples


def exercise(lab, samples):
    for role in (*lab.agents, "operator", "observer", "lookalike", "expired", "rotated"):
        lab.driver(role)
    assigned, _ = acquire(lab, "agent-a", "broker-a", 0)
    transfers = []
    decisions = []

    def record_case(label, caller, service, route, body, expected):
        sample = measured(lab, caller, service, route, body, expect=expected)
        decisions.append({"case": label, "outcome": sample["outcome"], "expected": expected,
                          "elapsed_ns": sample["samples_ns"][0]})
        return sample

    for _ in range(samples):
        former = assigned
        next_agent = "agent-b" if former.agent == "agent-a" else "agent-a"
        next_broker = "broker-b" if former.broker == "broker-a" else "broker-a"
        started = monotonic_ns()
        generation, stamp_ns, retire_ns = retire(lab)
        assigned, claim_ns = acquire(lab, next_agent, next_broker, generation)
        transfer = {"generation": assigned.generation, "wall_ns": monotonic_ns() - started,
                    "stamp_ns": stamp_ns, "retire_ns": retire_ns, "claim_ns": claim_ns}
        session = SessionRequest(agent=next_agent)
        record_case("current-session", next_agent, next_broker, "/session", session, "ok")
        transfer["reconnect_ns"] = decisions[-1]["elapsed_ns"]
        record_case("old-broker-session", next_agent, former.broker, "/session", session, "Denied")
        record_case("expired-certificate", "expired", next_broker, "/session",
                    SessionRequest(agent="agent-a"), "AuthenticationFailed")
        record_case("unlisted-key-same-uri", "lookalike", next_broker, "/session",
                    SessionRequest(agent="agent-a"), "Denied")
        record_case("approved-write", next_agent, next_broker, "/write", plan(lab, assigned), "ok")
        transfers.append(transfer)

    former = assigned
    old_write = plan(lab, former)
    next_agent = "agent-b" if former.agent == "agent-a" else "agent-a"
    next_broker = "broker-b" if former.broker == "broker-a" else "broker-a"
    stale_candidate = offer(lab, next_agent, next_broker, former.generation)
    before = len(raw_receipts(lab))
    partition_started = monotonic_ns()
    lab.partition(former.broker)
    detected = monotonic_ns()
    unavailable = record_case("partitioned-broker", former.agent, former.broker, "/session",
                              SessionRequest(agent=former.agent), "Unavailable")
    record_case("overlapping-claim", next_agent, next_broker, "/claim", stale_candidate, "Denied")
    generation, _, _ = retire(lab)
    assigned, _ = acquire(lab, next_agent, next_broker, generation)
    activated = monotonic_ns()
    lab.heal(former.broker)
    healed = monotonic_ns()
    slot = read(lab)
    record_case("former-owner-at-writer", former.broker, "target-a", "/write", old_write, "Denied")
    record_case("former-owner-after-reconnect", former.agent, former.broker, "/session",
                SessionRequest(agent=former.agent), "Denied")
    assert read(lab) == slot and len(raw_receipts(lab)) == before
    record_case("successor-after-partition", assigned.agent, assigned.broker, "/write",
                plan(lab, assigned), "ok")
    complete = monotonic_ns()
    committed = raw_receipts(lab)
    assert len(committed) == before + 1 and committed[-1][0] == assigned.generation

    receipts = [json.loads(line) for line in lab.logs("home") if line.startswith('{"event": "fence-receipt"')]
    return {
        "transfers": transfers,
        "target_fence_receipts": receipts,
        "attempts": decisions,
        "outcome_counts": dict(Counter(item["outcome"] for item in decisions)),
        "partition": {
            "former_generation": former.generation, "successor_generation": assigned.generation,
            "disconnect_ns": detected - partition_started,
            "observed_unavailable_ns": unavailable["samples_ns"][0],
            "active_after_disconnect_ns": activated - detected,
            "reattach_ns": healed - activated, "first_confirmed_successor_write_ns": complete - detected,
            "stale_writes": len(committed) - before - 1, "successor_writes": 1,
            "target_floors": {target: read(lab, target)["generation"] for target in lab.targets},
            "fault": "Docker network disconnect/connect, former broker process stayed running",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=12)
    parser.add_argument("--pings", type=int, default=60)
    args = parser.parse_args()
    if os.getenv("AEGIS_PHASE4E_LIVE") != "1":
        parser.error("set AEGIS_PHASE4E_LIVE=1 to opt in to disposable fixture credentials")
    if args.samples <= 0 or args.pings <= 0:
        parser.error("sample counts must be positive")

    scratch = ROOT / ".venv"
    scratch.mkdir(exist_ok=True)
    with TemporaryDirectory(dir=scratch, prefix="identity-benchmark-") as directory:
        with running(DockerLab(Path(directory))) as lab:
            info = {
                "when_utc": datetime.now(timezone.utc).isoformat(),
                "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "host": platform.platform(),
                "docker": lab.docker("info", "--format", "{{.ServerVersion}} {{.KernelVersion}} {{.Architecture}}"),
                "image": lab.docker("image", "inspect", lab.image, "--format", "{{.Id}}"),
                "worker": lab.docker("exec", lab.container("home"), "python", "-c",
                                     "import ssl,sys; print(sys.version.split()[0], ssl.OPENSSL_VERSION)"),
                "network": "single Docker VM, internal bridge, no published ports, one namespace per role",
            }
            data = {"environment": info, "ping": round_trips(lab, args.pings)} | exercise(lab, args.samples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
