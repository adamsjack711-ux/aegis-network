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

from aegis.api import STREAM, SUBJECT
from aegis.artifact import (
    Evidence, Finding, Revocation, Software, canonical_bytes, parse_event, sign,
    sign_revocation,
)
from aegis.config import load_local
from aegis.core import LocalAgent
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


def revocation(key: Ed25519PrivateKey, target, sequence: int):
    now = datetime.now(timezone.utc)
    return sign_revocation(Revocation(
        schema_version="1.0", revocation_id=uuid4(), publisher_id="lab-publisher",
        sequence=sequence, issued_at=now - timedelta(seconds=2),
        expires_at=now + timedelta(hours=1),
        target_artifact_id=target.finding.artifact_id,
        target_sha256=hashlib.sha256(canonical_bytes(target.finding)).hexdigest(),
        reason="withdrawn",
    ), key, "default")


class Lab:
    def __init__(self, args):
        self.args = args
        self.key = Ed25519PrivateKey.from_private_bytes(Path(args.key).read_bytes())
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
            "'ledger':db.execute('select artifact_id,digest from revoked_artifacts order by rowid').fetchall()}))"
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

        revoke = revocation(self.key, outage, self.next_sequence())
        revoke_id = str(revoke.revocation.revocation_id)
        assert (await self.post("/v1/revocations", revoke))["accepted"] is True
        await self.wait(lambda: all(any(row[0] == revoke_id and row[1] == "REVOCATION_ACCEPTED"
                                        for row in self.audit(s)["revocations"])
                                    for s in ("agent", "agent_b")), "signed revocation")
        assert (await self.post("/v1/revocations", revoke))["accepted"] is False
        assert (await self.post("/v1/findings", outage))["accepted"] is False

        # Prove a target digest remains denied when its revocation arrived first.
        future = finding(self.key, self.next_sequence())
        future_revoke = revocation(self.key, future, self.next_sequence())
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

    async def benchmark(self, js, count: int, samples: int, path: Path) -> dict:
        policy, inventory = load_local(self.args.local_config)
        agents = []
        subscribers = []
        token = uuid4().hex[:8]
        for index in range(count):
            agent_id = f"phase2c-{count}-{token}-{index}"
            audit = SqliteAudit(path / f"{agent_id}.db", agent_id=agent_id)
            agents.append((LocalAgent(policy, inventory, audit), audit))
            subscription = await js.pull_subscribe(
                "aegis.>", durable=f"aegis-{agent_id}", stream=STREAM,
                config=ConsumerConfig(max_deliver=5, ack_wait=30,
                                      ack_policy=AckPolicy.EXPLICIT,
                                      deliver_policy=DeliverPolicy.NEW),
            )
            subscribers.append(subscription)
        signed = [finding(self.key, self.next_sequence()) for _ in range(samples)]
        expected_ids = {str(item.finding.artifact_id) for item in signed}
        starts: dict[str, float] = {}
        latencies: list[float] = []
        observed = [set() for _ in range(count)]
        errors = []
        cpu_start = time.process_time()
        wall_start = time.monotonic()

        async def consume(index: int):
            while len(observed[index]) < samples:
                if time.monotonic() - wall_start > 120:
                    return
                try:
                    messages = await subscribers[index].fetch(20, timeout=1)
                except TimeoutError:
                    continue
                for message in messages:
                    envelope = parse_event(message.data)
                    event_id = str(envelope.finding.artifact_id)
                    if event_id in expected_ids:
                        decision = agents[index][0].evaluate_event(envelope)
                        if decision.outcome != "allow_dry_run":
                            errors.append((index, event_id, decision.reason_code))
                        if event_id not in observed[index]:
                            observed[index].add(event_id)
                            latencies.append((time.monotonic() - starts[event_id]) * 1000)
                    await message.ack_sync()

        tasks = [asyncio.create_task(consume(index)) for index in range(count)]
        async with httpx.AsyncClient(base_url=self.args.http, timeout=15) as client:
            for envelope in signed:
                event_id = str(envelope.finding.artifact_id)
                starts[event_id] = time.monotonic()
                response = await client.post("/v1/findings", json=envelope.model_dump(mode="json"))
                response.raise_for_status()
                assert response.json()["accepted"] is True
        await asyncio.gather(*tasks)
        elapsed = time.monotonic() - wall_start
        rows = [audit.db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
                for _, audit in agents]
        result = {
            "agents": count, "findings": samples, "expected_deliveries": count * samples,
            "committed_decisions": sum(rows), "coverage": sum(len(ids) for ids in observed) / (count * samples),
            "duplicate_logical_rows": sum(rows) - sum(len(ids) for ids in observed),
            "invalid_allow_decisions": len(errors), "elapsed_s": round(elapsed, 3),
            "cpu_s": round(time.process_time() - cpu_start, 3),
            "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "p50_ms": round(percentile(latencies, 0.50), 3) if latencies else None,
            "p95_ms": round(percentile(latencies, 0.95), 3) if latencies else None,
            "p99_ms": round(percentile(latencies, 0.99), 3) if latencies else None,
        }
        for _, audit in agents:
            audit.db.close()
        if result["coverage"] != 1 or result["duplicate_logical_rows"] or errors:
            raise AssertionError(result)
        return result


async def run(args):
    lab = Lab(args)
    nc = await nats.connect(args.nats)
    js = nc.jetstream()
    try:
        integration = await lab.integration(js)
        print(json.dumps({"integration": integration}, sort_keys=True), flush=True)
        with tempfile.TemporaryDirectory(prefix="aegis-phase2c-bench-") as directory:
            config = json.loads(Path(args.local_config).read_text())
            config["publishers_file"] = str(Path("lab-config/publishers.json").resolve())
            host_config = Path(directory) / "agent-host.json"
            host_config.write_text(json.dumps(config))
            args.local_config = str(host_config)
            for count in (3, 10, 100):
                result = await lab.benchmark(js, count, args.samples, Path(directory))
                print(json.dumps({"benchmark": result}, sort_keys=True), flush=True)
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
    parser.add_argument("--local-config", default="lab-config/agent.json")
    parser.add_argument("--samples", type=int, default=20)
    asyncio.run(run(parser.parse_args()))
