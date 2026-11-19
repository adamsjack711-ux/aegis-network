"""Measure witnessed history and Phase 4A replay on identical signed Mesh input."""

import argparse
import asyncio
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import platform
import sqlite3
from statistics import median
import subprocess
import tempfile
import time
from uuid import UUID

import httpx
from cryptography import __version__ as cryptography_version
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence, Finding, Revocation, Software, sign, sign_revocation
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.journal.client import ArchiveSource, JournalClient, UNINITIALIZED, finding_target
from aegis.journal.protocol import Clock, Leaf, Policy, canonical
from aegis.journal.storage import EMPTY_CHAIN, SQLitePin
from aegis.journal.witness import Archive, Witness, WitnessHeads, collect_receipt
from aegis.recovery import reconcile
from aegis.storage import SqliteAudit
from aegis.trust import PublisherGrant, TrustStore


class BindingLease:
    async def ensure(self):
        return None


def elapsed(start):
    return round((time.perf_counter() - start) * 1000, 3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[100, 1000, 5000])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if any(size < 5 for size in args.sizes) or args.repeats < 1:
        parser.error("each size must be at least five and repeats must be positive")
    data = {}
    for size in args.sizes:
        trials = []
        for _ in range(args.repeats):
            with tempfile.TemporaryDirectory(prefix="aegis-phase4d-") as directory:
                trials.append(asyncio.run(measure(Path(directory), size)))
        fields = trials[0].keys()
        data[size] = {"trials": trials,
                      "median": {field: median(trial[field] for trial in trials) for field in fields}}
    revision = subprocess.run(["git", "rev-parse", "HEAD"], check=False, capture_output=True,
                              text=True, cwd=Path(__file__).resolve().parents[1])
    report = {
        "code_revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "environment": {"platform": platform.platform(), "python": platform.python_version(),
                        "cryptography": cryptography_version, "sqlite": sqlite3.sqlite_version},
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "method": "single-host SQLite and in-process archives; legacy HTTPX mock, same signed events and page size",
        "operators": 4, "quorum": 3, "page_size": 128, "initial_prefix_fraction": 0.8,
        "units": {"timing": "milliseconds", "storage_and_payload": "bytes"},
        "sizes": data,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")


async def measure(directory: Path, count: int):
    initial = count * 4 // 5
    clock = [float(int(time.time() // 30) * 30 + 2)]
    now = datetime.fromtimestamp(clock[0], timezone.utc)

    def new_clock():
        return Clock(lambda: clock[0])

    author, reviewer, coordinator = (Ed25519PrivateKey.generate() for _ in range(3))
    keys = {f"w{index}": Ed25519PrivateKey.generate() for index in range(4)}
    trust = TrustStore([
        PublisherGrant("bench-author", "default", author.public_key(), frozenset({"finding"}),
                       now - timedelta(hours=1), now + timedelta(hours=1)),
        PublisherGrant("bench-review", "default", reviewer.public_key(), frozenset({"revocation"}),
                       now - timedelta(hours=1), now + timedelta(hours=1),
                       revocation_publishers=frozenset({"bench-author"})),
    ])
    policy = Policy("bench-mesh", "lab-blue", coordinator.public_key(),
                    {name: key.public_key() for name, key in keys.items()}, 3, 1, 30, 15, 90, trust)
    validity = {"issued_at": now - timedelta(minutes=2), "expires_at": now + timedelta(minutes=15)}
    events = [
        sign(Finding(schema_version="1.0", artifact_id=UUID(int=index), publisher_id="bench-author",
                     sequence=index, vulnerability_id="BENCHMARK-SYNTHETIC",
                     software=Software(purl="pkg:generic/bench", affected_versions=["1.0"]),
                     evidence=[Evidence(uri="urn:bench", sha256="0" * 64, method="lab-reproduction")],
                     applicability="authorized-lab", mitigation_template="observe-only", **validity), author)
        for index in range(1, count)
    ]
    target = events[0]
    publisher, identity, body = finding_target(target)
    events.append(sign_revocation(
        Revocation(schema_version="1.1", revocation_id=UUID(int=count), publisher_id="bench-review",
                   sequence=1, target_artifact_id=identity, target_sha256=body, target_publisher_id=publisher,
                   reason="withdrawn", **validity), reviewer, "default"))
    legacy_input = [
        {"position": index, "envelope": envelope.model_dump(mode="json")}
        for index, envelope in enumerate(events, 1)
    ]
    legacy_head = initial
    legacy_bytes = 0

    def legacy_response(request):
        nonlocal legacy_bytes
        start = int(request.url.params["after"])
        body = canonical({"events": legacy_input[start:min(start + 128, legacy_head)], "head": legacy_head})
        legacy_bytes += len(body)
        return httpx.Response(200, content=body)

    def pin(name, seed):
        result = SQLitePin(directory / f"{name}-pin.db", name)
        result.provision(seed)
        return result

    def size(name):
        return (directory / name).stat().st_size

    with ExitStack() as resources:
        archive = Archive(directory / "archive.db", policy)
        resources.callback(archive.close)
        witnesses = []
        for name, key in keys.items():
            witness = Witness(name, key, policy, directory / f"{name}.db", pin(name, EMPTY_CHAIN), new_clock())
            resources.callback(witness.close)
            witnesses.append(witness)

        def add(batch):
            start = time.perf_counter()
            for event in batch:
                receipt = collect_receipt(policy, (witness.admit(event) for witness in witnesses[:3]))
                archive.append(Leaf(receipt=receipt, envelope=event))
            return elapsed(start)

        def cut():
            epoch = int(clock[0] // 30)
            clock[0] = policy.cutoff(epoch) + 1
            start = time.perf_counter()
            signed = archive.propose(coordinator, epoch)
            for witness in witnesses[:3]:
                witness.cosign(signed, archive)
            return elapsed(start)

        class MeasuredProof(ArchiveSource):
            payload = 0

            async def consistency(self, before, head):
                response = await super().consistency(before, head)
                self.payload += len(canonical(response))
                return response

            async def page(self, head, start, limit):
                response = await super().page(head, start, limit)
                self.payload += len(canonical([entry.model_dump(mode="json") for entry in response]))
                return response

        class MeasuredHeads(WitnessHeads):
            payload = 0

            async def latest(self):
                response = await super().latest()
                self.payload += len(canonical(response))
                return response

        heads = MeasuredHeads(policy, witnesses)
        proofs = MeasuredProof(archive)
        agent_pin = pin("agent", UNINITIALIZED)
        cache = directory / "agent.db"
        agent = JournalClient(policy, heads, (proofs,), agent_pin, cache, new_clock())
        audit = SqliteAudit(directory / "legacy.db")
        resources.callback(audit.db.close)
        rapid = LocalAgent(LocalPolicy(trust, frozenset({"observe-only"}), True),
                           [InventoryItem("pkg:generic/bench", "1.0")], audit)
        timings = {}
        timings["witnessed_intake_initial_ms"] = add(events[:initial])
        timings["witnessed_seal_initial_ms"] = cut()
        async with httpx.AsyncClient(base_url="http://legacy.invalid", transport=httpx.MockTransport(
                legacy_response)) as legacy:
            start = time.perf_counter()
            await reconcile(rapid, audit, legacy, BindingLease(), page_size=128)
            timings["legacy_replay_initial_ms"] = elapsed(start)
            start = time.perf_counter()
            binding, _ = await agent.refresh()
            timings["witnessed_replay_initial_ms"] = elapsed(start)
            assert agent.current(target, binding)

            legacy_head = count
            timings["witnessed_intake_tail_ms"] = add(events[initial:])
            timings["witnessed_seal_tail_ms"] = cut()
            start = time.perf_counter()
            await reconcile(rapid, audit, legacy, BindingLease(), page_size=128)
            timings["legacy_replay_tail_ms"] = elapsed(start)
            start = time.perf_counter()
            binding, _ = await agent.refresh()
            timings["witnessed_replay_tail_ms"] = elapsed(start)
            assert finding_target(target) in agent.replay.denials and not agent.current(target, binding)
            assert audit.is_revoked(*finding_target(target))

        wire_total = heads.payload + proofs.payload
        # Measure opening the local sealed prefix after process restart.
        start = time.perf_counter()
        restarted = JournalClient(policy, heads, (proofs,), agent_pin, cache, new_clock())
        binding, _ = await restarted.refresh()
        timings["witnessed_restart_verified_cache_ms"] = elapsed(start)
        assert not restarted.current(target, binding)
        return {
            **timings,
            "witnessed_app_payload_bytes": wire_total,
            "legacy_app_payload_bytes": legacy_bytes,
            "legacy_agent_audit_bytes": size("legacy.db"),
            "witnessed_agent_cache_bytes": size("agent.db"),
            "witnessed_agent_pin_bytes": size("agent-pin.db"),
            "coordinator_archive_bytes": size("archive.db"),
            "one_witness_state_bytes": size("w0.db"),
            "one_witness_pin_bytes": size("w0-pin.db"),
            "inclusion_path_at_midpoint_bytes": len(archive.tree.inclusion(count // 2, count)) * 32,
            "consistency_path_initial_to_full_bytes": len(archive.tree.consistency(initial, count)) * 32,
        }


if __name__ == "__main__":
    main()
