"""Run the Phase 3C pipeline with the disposable loopback-only Compose lab."""

import argparse
import asyncio
from contextlib import AsyncExitStack, ExitStack
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import platform
import tempfile
import time
from uuid import uuid4

import httpx
import nats
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence as FindingEvidence, Finding, Software
from aegis.config import load_publishers
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.synthetic import create_lab
from aegis.mitigation.policy import Denied
from aegis.phase3c import (EvidenceGate, MESH_TEMPLATE, MeshIntake, PACKAGE, VERSION,
                           VerifiedLab, publishable_finding)
from aegis.storage import SqliteAudit


def finding():
    now = datetime.now(timezone.utc)
    return Finding(schema_version="1.0", artifact_id=uuid4(), publisher_id="lab-publisher",
                   sequence=time.time_ns() // 1_000, issued_at=now - timedelta(seconds=1),
                   expires_at=now + timedelta(minutes=3), vulnerability_id="AEGIS-3C-SYNTHETIC",
                   software=Software(purl=PACKAGE, affected_versions=[VERSION]),
                   evidence=[FindingEvidence(uri="urn:unused", sha256="0" * 64,
                                             method="lab-reproduction")],
                   applicability="authorized-lab", mitigation_template=MESH_TEMPLATE)


async def local_review(plan, scripted):
    if scripted:
        return plan.digest
    print(json.dumps({"plan": asdict(plan), "digest": plan.digest}, indent=2), flush=True)
    return await asyncio.to_thread(input, "Enter the reviewed plan digest to approve this fixture: ")


async def episode(args, js, client, path, count, eligible, *, after_confirmed=None):
    researcher = create_lab()
    trust = load_publishers("lab-config/publishers.json")
    key = Ed25519PrivateKey.from_private_bytes(Path("lab-config/publisher.key").read_bytes())
    stage_start = time.monotonic_ns()
    async with AsyncExitStack() as subscriptions:
        with ExitStack() as resources:
            collector = resources.enter_context(Evidence(path / "collector.db", researcher.trust,
                                                         researcher.verifiers))
            receivers = []
            for index in range(count):
                agent_id = str(uuid4())
                audit = SqliteAudit(path / f"{agent_id}.sqlite", agent_id)
                resources.callback(audit.db.close)
                inventory = [InventoryItem(PACKAGE, VERSION if index < eligible else "2.0.0")]
                agent = LocalAgent(LocalPolicy(trust, frozenset({MESH_TEMPLATE}), True), inventory, audit)
                receivers.append(await subscriptions.enter_async_context(MeshIntake(agent, js, client).connect()))
            workers_start = time.monotonic_ns()
            envelope, bundle, result = await asyncio.to_thread(
                publishable_finding, finding(), key, researcher, collector,
            )
            verified = time.monotonic_ns()
            response = await client.post("/v1/findings", json=envelope.model_dump(mode="json"))
            response.raise_for_status()
            if response.json().get("accepted") is not True:
                raise Denied("Mesh did not accept the finding")
            http_committed = time.monotonic_ns()
            event_id = str(envelope.finding.artifact_id)
            async with asyncio.TaskGroup() as group:
                receipts = [group.create_task(receiver.receive(event_id)) for receiver in receivers]
            delivered = [receipt.result() for receipt in receipts]

            rows = []
            defenses = []
            for index, (receiver, received) in enumerate(zip(receivers, delivered, strict=True)):
                received_envelope, decision, recv_ns, committed_ns, acked_ns = received
                audit = receiver.agent.audit
                assert len(audit.all_decisions()) == 1
                row = {"agent_id": audit.agent_id, "eligible": index < eligible,
                       "rapid": decision.reason_code, "verified_to_receipt_ms": (recv_ns - verified) / 1e6,
                       "rapid_audit_ms": (committed_ns - recv_ns) / 1e6,
                       "broker_ack_ms": (acked_ns - committed_ns) / 1e6,
                       "status": "ineligible"}
                rows.append(row)
                if index >= eligible:
                    assert decision.outcome == "deny"
                    continue
                if decision.outcome != "allow_dry_run":
                    raise Denied(f"expected eligible deployment was denied: {decision.reason_code}")
                appraisal_start = time.monotonic_ns()
                evidence = resources.enter_context(Evidence(path / f"{audit.agent_id}-evidence.db",
                                                            researcher.trust))
                gate = EvidenceGate(received_envelope, bundle, result, receiver, collector, evidence)
                defense = VerifiedLab(gate, path / f"{audit.agent_id}-fixture.db")
                resources.enter_context(defense.lab)
                row["local_appraisal_and_fixture_start_ms"] = (time.monotonic_ns() - appraisal_start) / 1e6
                defenses.append((defense, row))

            async def rollout(defense, row):
                plan = await defense.prepare(args.lease_ms)
                review_start = time.monotonic_ns()
                approval = await local_review(plan, args.scripted_approval)
                row["review_ms"] = (time.monotonic_ns() - review_start) / 1e6
                milestones = await defense.execute(plan, approval)
                confirmed = milestones.pop("confirmed_ns")
                row["verified_to_protection_ms"] = (confirmed - verified) / 1e6
                row["rollout_ms"] = {k: v / 1e6 for k, v in milestones.items()}
                if not args.scripted_approval:
                    print(f"Confirmed local fixture protection at {row['verified_to_protection_ms']:.3f} ms.",
                          flush=True)
                try:
                    # Repeat independent HTTP checks from the enrollment scope.
                    expected = tuple(zip(plan.targets, (f + 1 for f in plan.expected_fences), strict=True))
                    observation = await asyncio.to_thread(defense.lab.observer.observe, "restricted", expected)
                    history = defense.lab.store.history()
                    assert any(entry["event"] == "confirmed" and entry["plan"] == plan.digest for entry in history)
                    assert any(entry["event"] == "leased"
                               and entry["detail"]["evidence_binding"] == defense.gate.binding for entry in history)
                    row.update(status="confirmed", post_confirmation_probes=observation.requests,
                               marker_escapes=0, unexpected_benign_failures=0,
                               audit_binding=defense.gate.binding)
                    if after_confirmed is not None:
                        await after_confirmed(defense, plan)
                    hold_ms = getattr(args, "hold_ms", 0)
                    if hold_ms:
                        try:
                            async with asyncio.timeout(hold_ms / 1000):
                                status = await defense.monitor(plan)
                            row["monitor_status"] = status
                        except TimeoutError:
                            row["monitor_status"] = "operator window ended"
                finally:
                    recovery_start = time.monotonic_ns()
                    recovery = await asyncio.to_thread(defense.lab.controller.rollback, "local lab stop")
                    row.update(recovery=recovery, recovery_ms=(time.monotonic_ns() - recovery_start) / 1e6)
                    assert recovery == "safe_hold"

            async with asyncio.TaskGroup() as group:
                for defense, row in defenses:
                    group.create_task(rollout(defense, row))
            return {"agents": count, "expected_eligible": eligible, "event_id": event_id,
                    "verified_at_ns": verified, "fixture_setup_ms": (workers_start - stage_start) / 1e6,
                    "evidence_and_sign_ms": (verified - workers_start) / 1e6,
                    "http_submit_ms": (http_committed - verified) / 1e6, "deployments": rows}


async def run(args):
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    nc = await nats.connect(f"nats://127.0.0.1:{args.broker_port}", connect_timeout=2)
    results = []
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{args.coordinator_port}",
                                    trust_env=False, timeout=5) as client:
            for count in args.agents:
                for repeat in range(args.repeats):
                    path = Path(tempfile.mkdtemp(prefix=f"{count}-{repeat}-", dir=args.directory))
                    results.append(await episode(args, nc.jetstream(), client, path, count, args.eligible))
    finally:
        await nc.close()
    report = {"measured_at": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
              "python": platform.python_version(), "scripted_approval": args.scripted_approval,
              "lease_ms": args.lease_ms, "runs": results}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"episodes": len(results), "confirmed": sum(
        row["status"] == "confirmed" for run in results for row in run["deployments"]
    )}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agents", type=int, nargs="+", default=[3])
    parser.add_argument("--eligible", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--lease-ms", type=int, default=3000)
    parser.add_argument("--hold-ms", type=int, default=0)
    parser.add_argument("--scripted-approval", action="store_true", help="Only for synthetic benchmarks")
    parser.add_argument("--broker-port", type=int, default=14222)
    parser.add_argument("--coordinator-port", type=int, default=18080)
    parser.add_argument("--directory", type=Path, required=True, help="Private local directory for audit databases")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if (not 1 <= args.eligible <= 3 or not 1 <= args.repeats <= 30
            or any(not args.eligible <= count <= 100 for count in args.agents)):
        parser.error("enroll 1–3 local fixtures and at most 100 logical agents per episode")
    if not 0 <= args.hold_ms <= args.lease_ms:
        parser.error("observation hold must fit within the requested lease")
    if not args.scripted_approval and args.eligible != 1:
        parser.error("interactive use requires one fixture per invocation")
    asyncio.run(run(args))
