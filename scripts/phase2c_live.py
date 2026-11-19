"""Isolated local Compose integration and dry-run fanout benchmark.

Start Compose first with host-only coordinator, NATS, and PostgreSQL ports.
This script never executes a mitigation or contacts a production service.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import math
import resource
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import nats
import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy

from aegis.api import (
    DEAD_LETTER_STREAM, DEAD_LETTER_SUBJECT, FINDING_RETENTION_SECONDS,
    STREAM, STREAM_MAX_BYTES, SUBJECT,
)
from aegis.agent_runtime import durable_name, process_message
from aegis.artifact import (
    Evidence, Finding, Revocation, Software, canonical_bytes, sign,
    sign_revocation,
)
from aegis.config import load_local
from aegis.core import LocalAgent
from aegis.identity import IdentityInUse, IdentityLease
from aegis.storage import SqliteAudit


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = math.floor(position)
    high = math.ceil(position)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def finding(key: Ed25519PrivateKey, sequence: int):
    now = datetime.now(timezone.utc)
    return sign(Finding(
        schema_version="1.0", artifact_id=uuid4(), publisher_id="lab-publisher",
        sequence=sequence, issued_at=now - timedelta(seconds=2),
        expires_at=now + timedelta(hours=1), vulnerability_id="AEGIS-PHASE2C-SYNTHETIC",
        software=Software(purl="pkg:generic/aegis-demo", affected_versions=["1.0.0"]),
        evidence=[Evidence(uri="urn:aegis:phase2c:synthetic",
                           sha256=hashlib.sha256(b"synthetic only").hexdigest(),
                           method="lab-reproduction")],
        applicability="authorized-lab", mitigation_template="observe-only",
    ), key)


def revocation(key: Ed25519PrivateKey, target, sequence: int, target_publisher=None):
    now = datetime.now(timezone.utc)
    return sign_revocation(Revocation(
        schema_version="1.1", revocation_id=uuid4(), publisher_id="lab-revoker",
        sequence=sequence, issued_at=now - timedelta(seconds=2),
        expires_at=now + timedelta(hours=1),
        target_artifact_id=target.finding.artifact_id,
        target_sha256=hashlib.sha256(canonical_bytes(target.finding)).hexdigest(),
        target_publisher_id=target_publisher or target.finding.publisher_id,
        reason="withdrawn",
    ), key, "revoker")


class Lab:
    def __init__(self, args):
        self.args = args
        self.key = Ed25519PrivateKey.from_private_bytes(Path(args.key).read_bytes())
        self.revoker_key = Ed25519PrivateKey.from_private_bytes(Path(args.revoker_key).read_bytes())
        self.sequence = time.time_ns() // 1000
        self.compose_base = ["docker", "compose", "-p", args.project, "-f", "compose.yaml",
                             "-f", args.override]

    def next_sequence(self) -> int:
        self.sequence += 1
        return self.sequence

    def compose(self, *command: str) -> None:
        subprocess.run([*self.compose_base, *command], check=True, stdout=subprocess.DEVNULL)

    def outbox(self, event_id: str) -> bool | None:
        with psycopg.connect(self.args.postgres) as db:
            row = db.execute("SELECT sent_at IS NOT NULL FROM mesh_outbox WHERE event_id=%s",
                             (event_id,)).fetchone()
        return row[0] if row else None

    def audit(self, service: str) -> dict:
        code = (
            "import json,sqlite3; "
            "db=sqlite3.connect('/audit/agent.db'); "
            "print(json.dumps({'identity':db.execute('select agent_id from audit_identity').fetchone()[0],"
            "'decisions':db.execute('select artifact_id,outcome,reason_code from decisions order by rowid').fetchall(),"
            "'revocations':db.execute('select event_id,reason_code from revocation_decisions order by rowid').fetchall(),"
            "'ledger':db.execute('select artifact_id,digest from revoked_targets order by rowid').fetchall()}))"
        )
        result = subprocess.run([*self.compose_base, "exec", "-T", service, "python", "-c", code],
                                capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    async def post(self, path: str, envelope) -> dict:
        async with httpx.AsyncClient(base_url=self.args.http, timeout=10) as client:
            response = await client.post(path, json=envelope.model_dump(mode="json"))
        response.raise_for_status()
        return response.json()

    async def wait(self, condition, label: str, timeout: float = 45) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if condition():
                    return
            except (subprocess.CalledProcessError, psycopg.OperationalError):
                pass
            await asyncio.sleep(0.25)
        raise AssertionError(f"timed out waiting for {label}")

    async def integration(self, js) -> dict:
        first = finding(self.key, self.next_sequence())
        first_id = str(first.finding.artifact_id)
        assert (await self.post("/v1/findings", first))["accepted"] is True
        await self.wait(lambda: all(any(row[0] == first_id and row[2] == "EXACT_MATCH_ALLOWED"
                                        for row in self.audit(service)["decisions"])
                                    for service in ("agent", "agent_b")), "two signed decisions")
        assert (await self.post("/v1/findings", first))["accepted"] is False

        # Force a second JetStream delivery with a distinct broker message ID.
        await js.publish(SUBJECT, first.model_dump_json().encode(),
                         headers={"Nats-Msg-Id": str(uuid4())})
        await asyncio.sleep(1)
        assert all(sum(row[0] == first_id for row in self.audit(s)["decisions"]) == 1
                   for s in ("agent", "agent_b"))

        forged = first.model_copy(update={"signature": base64.b64encode(b"x" * 64).decode()})
        async with httpx.AsyncClient(base_url=self.args.http) as client:
            rejected = await client.post("/v1/findings", json=forged.model_dump(mode="json"))
        assert rejected.status_code == 400

        self.compose("stop", "agent_b", "nats")
        outage = finding(self.key, self.next_sequence())
        outage_id = str(outage.finding.artifact_id)
        assert (await self.post("/v1/findings", outage))["accepted"] is True
        assert self.outbox(outage_id) is False
        self.compose("start", "nats", "agent_b")
        await self.wait(lambda: self.outbox(outage_id) is True, "outbox dispatch recovery")
        await self.wait(lambda: all(any(row[0] == outage_id for row in self.audit(s)["decisions"])
                                    for s in ("agent", "agent_b")), "agent catch-up")

        revoke = revocation(self.revoker_key, outage, self.next_sequence())
        revoke_id = str(revoke.revocation.revocation_id)
        assert (await self.post("/v1/revocations", revoke))["accepted"] is True
        await self.wait(lambda: all(any(row[0] == revoke_id and row[1] == "REVOCATION_ACCEPTED"
                                        for row in self.audit(s)["revocations"])
                                    for s in ("agent", "agent_b")), "signed revocation")
        assert (await self.post("/v1/revocations", revoke))["accepted"] is False
        assert (await self.post("/v1/findings", outage))["accepted"] is False

        # Prove a target digest remains denied when its revocation arrived first.
        future = finding(self.key, self.next_sequence())
        future_revoke = revocation(self.revoker_key, future, self.next_sequence())
        future_id = str(future.finding.artifact_id)
        assert (await self.post("/v1/revocations", future_revoke))["accepted"] is True
        await self.wait(lambda: all(any(row[0] == future_id for row in self.audit(s)["ledger"])
                                    for s in ("agent", "agent_b")), "revocation before finding")
        assert (await self.post("/v1/findings", future))["accepted"] is True
        await self.wait(lambda: all(any(row[0] == future_id and row[2] == "FINDING_REVOKED"
                                        for row in self.audit(s)["decisions"])
                                    for s in ("agent", "agent_b")), "denied future finding")

        before_restart = {s: self.audit(s) for s in ("agent", "agent_b")}
        self.compose("restart", "agent", "agent_b")
        await self.wait(lambda: all(self.audit(s) == before_restart[s] for s in before_restart),
                        "persisted audit after restart")
        return {"agents": {s: {"identity": before_restart[s]["identity"],
                                "finding_rows": len(before_restart[s]["decisions"]),
                                "revocation_rows": len(before_restart[s]["revocations"]),
                                "ledger_rows": len(before_restart[s]["ledger"])}
                            for s in before_restart},
                "duplicate_logical_rows": 0, "invalid_http_status": rejected.status_code,
                "outage_pending_before_restart": True, "outage_sent_after_restart": True,
                "audit_persisted_after_restart": True}

    async def hardening(self, js) -> dict:
        stream = await js.stream_info(STREAM)
        dead_stream = await js.stream_info(DEAD_LETTER_STREAM)
        assert stream.config.max_age == FINDING_RETENTION_SECONDS
        assert stream.config.max_bytes == STREAM_MAX_BYTES
        assert dead_stream.config.max_age == 7 * FINDING_RETENTION_SECONDS
        assert dead_stream.config.max_bytes == STREAM_MAX_BYTES
        assert str(stream.config.discard).lower().endswith("new")
        assert str(dead_stream.config.discard).lower().endswith("new")

        # The broker lease rejects a second live process using the same UUID.
        active_id = self.audit("agent")["identity"]
        consumer = await js.consumer_info(STREAM, f"aegis-{active_id}")
        assert consumer.config.max_deliver == -1
        try:
            await IdentityLease.claim(js, active_id)
        except IdentityInUse:
            duplicate_blocked = True
        else:
            raise AssertionError("duplicate agent identity acquired a lease")

        target = finding(self.key, self.next_sequence())
        outside_scope = revocation(self.revoker_key, target, self.next_sequence(),
                                   target_publisher="other-publisher")
        async with httpx.AsyncClient(base_url=self.args.http) as client:
            denied = await client.post("/v1/revocations", json=outside_scope.model_dump(mode="json"))
        assert denied.status_code == 400

        # A lower publisher sequence is refused by the coordinator transaction.
        current = finding(self.key, self.next_sequence())
        assert (await self.post("/v1/findings", current))["accepted"]
        lower = finding(self.key, current.finding.sequence - 1)
        async with httpx.AsyncClient(base_url=self.args.http) as client:
            stale = await client.post("/v1/findings", json=lower.model_dump(mode="json"))
        assert stale.status_code == 409

        # Lose the entire broker stream while agent_b is offline. PostgreSQL
        # journal replay must restore its missed dry-run decision on restart.
        self.compose("stop", "agent_b")
        missed = finding(self.key, self.next_sequence())
        missed_id = str(missed.finding.artifact_id)
        assert (await self.post("/v1/findings", missed))["accepted"]
        missed_revoke = revocation(self.revoker_key, missed, self.next_sequence())
        missed_revoke_id = str(missed_revoke.revocation.revocation_id)
        assert (await self.post("/v1/revocations", missed_revoke))["accepted"]
        await self.wait(lambda: self.outbox(missed_id) is True, "missed outbox publish")
        await self.wait(lambda: self.outbox(missed_revoke_id) is True, "missed revocation publish")
        await self.wait(lambda: any(row[0] == missed_id for row in self.audit("agent")["decisions"]),
                        "first agent before stream purge")
        await self.wait(lambda: any(row[0] == missed_id for row in self.audit("agent")["ledger"]),
                        "first agent revocation before stream purge")
        await js.purge_stream(STREAM)
        assert (await js.stream_info(STREAM)).state.messages == 0
        self.compose("start", "agent_b")
        await self.wait(lambda: any(row[0] == missed_id and row[2] == "EXACT_MATCH_ALLOWED"
                                    for row in self.audit("agent_b")["decisions"]),
                        "journal recovery beyond stream retention", timeout=60)
        await self.wait(lambda: any(row[0] == missed_id for row in self.audit("agent_b")["ledger"]),
                        "revocation recovery beyond stream retention", timeout=60)

        # Every durable sends malformed broker input to the bounded DLQ before term.
        await js.publish(SUBJECT, b"[]", headers={"Nats-Msg-Id": str(uuid4())})
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if (await js.stream_info(DEAD_LETTER_STREAM)).state.messages >= 2:
                break
            await asyncio.sleep(0.25)
        else:
            raise AssertionError("both agents did not dead-letter malformed input")
        dlq = await js.pull_subscribe(DEAD_LETTER_SUBJECT, durable=f"review-{uuid4().hex[:8]}",
                                      stream=DEAD_LETTER_STREAM)
        messages = await dlq.fetch(2, timeout=5)
        records = [json.loads(message.data) for message in messages]
        assert len(records) == 2
        assert {record["agent_id"] for record in records} == {
            self.audit("agent")["identity"], self.audit("agent_b")["identity"]}
        assert all(base64.b64decode(record["body_base64"]) == b"[]" for record in records)
        for message in messages:
            await message.ack_sync()
        return {"duplicate_identity_blocked": duplicate_blocked,
                "out_of_scope_http_status": denied.status_code,
                "stale_sequence_http_status": stale.status_code,
                "purged_finding_and_revocation_recovered": True,
                "dead_letter_records": len(records),
                "stream_max_age_s": stream.config.max_age,
                "stream_max_bytes": stream.config.max_bytes}

    async def benchmark(self, js, count: int, samples: int, path: Path) -> dict:
        policy, inventory = load_local(self.args.local_config)
        agents = []
        leases = []
        subscribers = []
        try:
            for _ in range(count):
                agent_id = str(uuid4())
                audit = SqliteAudit(path / f"{agent_id}.db", agent_id=agent_id)
                agents.append(LocalAgent(policy, inventory, audit))
                leases.append(await IdentityLease.claim(js, agent_id))
                subscription = await js.pull_subscribe(
                    "aegis.>", durable=durable_name(agent_id), stream=STREAM,
                    config=ConsumerConfig(max_deliver=-1, ack_wait=10,
                                          ack_policy=AckPolicy.EXPLICIT,
                                          deliver_policy=DeliverPolicy.NEW),
                )
                subscribers.append(subscription)
            return await self.measure_fanout(js, agents, leases, subscribers, samples)
        finally:
            for lease in leases:
                await lease.release()
            for agent in agents:
                agent.audit.db.close()
            for agent in agents[:len(subscribers)]:
                await js.delete_consumer(STREAM, durable_name(agent.audit.agent_id))

    async def measure_fanout(self, js, agents, leases, subscribers, samples: int) -> dict:
        count = len(agents)
        signed = [finding(self.key, self.next_sequence()) for _ in range(samples)]
        expected_ids = {str(item.finding.artifact_id) for item in signed}
        starts = {}
        observed = [set() for _ in agents]
        errors = []
        durations = {name: [] for name in
                     ("http", "receipt", "lease", "evaluation", "audit", "broker_ack", "ack_total")}
        last_ack_ns = 0
        redeliveries = 0

        def record(decision, received, lease_checked, committed, acked, index):
            nonlocal last_ack_ns, redeliveries
            eid = decision.event_id
            if eid not in expected_ids:
                return
            if eid in observed[index]:
                redeliveries += 1
                return
            if decision.outcome != "allow_dry_run":
                errors.append((index, eid, decision.reason_code))
            observed[index].add(eid)
            last_ack_ns = max(acked, last_ack_ns)
            for name, ns in (("receipt", received - starts[eid]),
                             ("lease", lease_checked - received),
                             ("evaluation", committed - lease_checked),
                             ("audit", committed - starts[eid]),
                             ("broker_ack", acked - committed),
                             ("ack_total", acked - starts[eid])):
                durations[name].append(ns / 1e6)

        async def consume(index: int):
            def observe(*observation):
                record(*observation, index)

            while len(observed[index]) < samples:
                try:
                    messages = await subscribers[index].fetch(10, timeout=1)
                except TimeoutError:
                    continue
                for message in messages:
                    await process_message(message, agents[index], js, leases[index], observe=observe)

        cpu_start = time.process_time_ns()
        wall_start = time.perf_counter_ns()
        async with asyncio.timeout(120), asyncio.TaskGroup() as group:
            for index in range(count):
                group.create_task(consume(index))
            async with httpx.AsyncClient(base_url=self.args.http, timeout=15) as client:
                for envelope in signed:
                    eid = str(envelope.finding.artifact_id)
                    starts[eid] = time.perf_counter_ns()
                    response = await client.post("/v1/findings", json=envelope.model_dump(mode="json"))
                    durations["http"].append((time.perf_counter_ns() - starts[eid]) / 1e6)
                    response.raise_for_status()
                    assert response.json()["accepted"] is True
        elapsed = (last_ack_ns - wall_start) / 1e9
        observed_count = sum(len(ids) for ids in observed)
        rows = sum(agent.audit.db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
                   for agent in agents)
        result = {
            "agents": count, "findings": samples, "expected_deliveries": count * samples,
            "committed_decisions": rows, "coverage": observed_count / (count * samples),
            "duplicate_logical_rows": rows - observed_count, "observed_redeliveries": redeliveries,
            "unexpected_denials": len(errors), "elapsed_s": round(elapsed, 3),
            "decisions_per_s": round(rows / elapsed, 2),
            "cpu_s": round((time.process_time_ns() - cpu_start) / 1e9, 3),
            "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "stages_ms": {name: {f"p{int(q * 100)}": round(percentile(values, q), 3)
                                  for q in (.50, .95, .99)}
                          for name, values in durations.items()},
        }
        if result["coverage"] != 1 or result["duplicate_logical_rows"] or errors:
            raise AssertionError(result)
        return result


async def run(args):
    lab = Lab(args)
    nc = await nats.connect(args.nats)
    js = nc.jetstream()
    try:
        if not args.benchmark_only and not args.skip_integration:
            integration = await lab.integration(js)
            print(json.dumps({"integration": integration}, sort_keys=True), flush=True)
        if not args.benchmark_only:
            hardening = await lab.hardening(js)
            print(json.dumps({"hardening": hardening}, sort_keys=True), flush=True)
        if args.integration_only:
            return
        with tempfile.TemporaryDirectory(prefix="aegis-phase2c-bench-") as directory:
            config = json.loads(Path(args.local_config).read_text())
            config["publishers_file"] = str(Path("lab-config/publishers.json").resolve())
            host_config = Path(directory) / "agent-host.json"
            host_config.write_text(json.dumps(config))
            args.local_config = str(host_config)
            for repeat in range(1, args.repeats + 1):
                for count in (3, 10, 100):
                    result = await lab.benchmark(js, count, args.samples, Path(directory))
                    print(json.dumps({"repeat": repeat, "benchmark": result}, sort_keys=True), flush=True)
    finally:
        await nc.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--override", required=True)
    parser.add_argument("--http", default="http://127.0.0.1:18080")
    parser.add_argument("--nats", default="nats://127.0.0.1:14222")
    parser.add_argument("--postgres", default="postgresql://aegis:local-phase2c@127.0.0.1:15432/aegis")
    parser.add_argument("--key", default="lab-config/publisher.key")
    parser.add_argument("--revoker-key", default="lab-config/revoker.key")
    parser.add_argument("--local-config", default="lab-config/agent.json")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--skip-integration", action="store_true")
    parser.add_argument("--repeats", type=int, default=1)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--benchmark-only", action="store_true")
    mode.add_argument("--integration-only", action="store_true")
    asyncio.run(run(parser.parse_args()))
