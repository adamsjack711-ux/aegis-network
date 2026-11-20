"""Exercise all three trust inputs against one explicitly approved disposable writer."""

import asyncio
from contextlib import ExitStack, closing
from datetime import datetime, timedelta, timezone
import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.agent_runtime import process_message
from aegis.artifact import sign_revocation
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.records import Withdrawal, digest, sign_record
from aegis.evidence.status import RelyingStatus, StatusProof, StatusWitness
from aegis.evidence.status_protocol import StatusPolicy, WitnessGrant, observe
from aegis.evidence.synthetic import create_lab
from aegis.journal.protocol import JournalBlocked
from aegis.mitigation.policy import Denied, LocalOperator
from aegis.mitigation.store import TargetStore
from aegis.ownership import IdentitySession, lease_proof
from aegis.phase3c import (
    COHORT, EvidenceGate, MESH_TEMPLATE, MeshIntake, PACKAGE, VERSION, VerifiedLab, publishable_finding,
)
from aegis.storage import SqliteAudit
from aegis.trust_lab.native_evidence import NativeEvidenceStatus
from test_journal import Network


@pytest.mark.parametrize("fault", ["legacy", "none", "journal-withdrawal", "evidence-withdrawal",
                                  "stale-ownership", "offline-status", "missing-audit",
                                  "critical-ack-unavailable", "offline-witness-pending"])
def test_native_trust_rechecks_each_peer_write(tmp_path, fault):
    run_fixture(tmp_path, fault)


def run_fixture(tmp_path, fault):
    async def exercise():
        with ExitStack() as stack:
            network = Network(tmp_path, stack)
            researcher = create_lab()
            collector = stack.enter_context(Evidence(tmp_path / "collector.sqlite", researcher.trust,
                                                     researcher.verifiers))
            relying = stack.enter_context(Evidence(tmp_path / "evidence.sqlite", researcher.trust))
            proposal = network.finding()
            # Witness cutoffs advance under a synthetic clock. The same signed
            # finding also has to be current under Rapid's real UTC clock.
            issued = min(proposal.issued_at, datetime.now(timezone.utc) - timedelta(seconds=1))
            proposal = proposal.model_copy(update={"issued_at": issued})
            finding, bundle, appraisal = publishable_finding(proposal, network.author, researcher, collector)
            network.archive.append(network.receive(finding))
            network.publish(network.seal())
            journal = network.client()
            audit = SqliteAudit(tmp_path / "rapid.sqlite", str(uuid4()))
            stack.enter_context(closing(audit.db))
            agent = LocalAgent(LocalPolicy(network.trust, frozenset({MESH_TEMPLATE}), True),
                               [InventoryItem(PACKAGE, VERSION)], audit)
            if fault != "missing-audit":
                assert agent.evaluate_event(finding).outcome == "allow_dry_run"

            keys = tuple(Ed25519PrivateKey.generate() for _ in range(2))
            grants = tuple(WitnessGrant(f"status-{index}", f"status-org-{index}", key.public_key())
                           for index, key in enumerate(keys))
            policy = StatusPolicy("phase4d-native", COHORT, "research-org", "local-operator",
                                  researcher.trust, grants)
            witnesses = tuple(StatusWitness(tmp_path / f"{grant.witness_id}.sqlite", policy, grant.witness_id,
                                            key, provision=True)
                              for grant, key in zip(grants, keys, strict=True))
            observations = tuple(observe(policy, verifier, bundle, clock=time.time)
                                 for verifier in researcher.verifiers)
            for witness in witnesses:
                for record in (bundle.manifest, *observations):
                    assert witness.admit(record) == digest(record)

            online = True

            def fetch(challenge):
                if not online:
                    return StatusProof((), ())
                left, right = (witness.endorse(challenge) for witness in witnesses)
                return StatusProof(left.endorsements + right.endorsements, left.records)

            reader = RelyingStatus(tmp_path / "status-reader.sqlite", policy, audit.agent_id, provision=True)
            appraiser = NativeEvidenceStatus(reader, fetch)

            key = Ed25519PrivateKey.generate()
            principal = "spiffe://aegis.lab/phase4d/holder"
            path = tmp_path / "target.sqlite"
            owner_store = TargetStore(path, LocalOperator())
            owner_store.create()
            home = owner_store.ownership
            home.enroll(audit.agent_id, principal, key.public_key(), ("broker-a", "broker-b"))
            assignment = home.accept(lease_proof("claim", home.candidate("broker-a"), key),
                                     peer_principal=principal, broker="broker-a")

            def coordinator(_):
                if fault == "legacy":
                    return httpx.Response(200, json={"head": 0, "events": []})
                pytest.fail("the native Trust fixture queried the coordinator replay")

            async with httpx.AsyncClient(base_url="http://coordinator.invalid",
                                         transport=httpx.MockTransport(coordinator)) as remote:
                legacy = fault == "legacy"
                intake = MeshIntake(agent, None, remote, journal=None if legacy else journal)
                intake.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0), require_live=lambda: None)
                if fault in {"critical-ack-unavailable", "offline-witness-pending", "offline-status"}:
                    intake.priority = True
                    intake.critical_task = asyncio.get_running_loop().create_future()
                    stack.callback(intake.critical_task.cancel)
                gate = EvidenceGate(finding, bundle, appraisal, intake, collector, relying,
                                    independent_evidence=None if legacy else appraiser)
                if legacy:
                    defense = VerifiedLab(gate, tmp_path / "legacy-target.sqlite")
                else:
                    with pytest.raises(Denied, match="requires identity"):
                        VerifiedLab(gate, path)
                    defense = VerifiedLab(gate, path, identity=IdentitySession(assignment, key))

                async def execute_healthy():
                    timing = await defense.execute(plan, plan.digest)
                    elapsed_ns = time.monotonic_ns() - started_ns
                    cpu_ns = time.process_time_ns() - started_cpu_ns
                    assert defense.lab.store.status() == "confirmed"
                    restricted = tuple((target, fence + 1) for target, fence
                                       in zip(plan.targets, plan.expected_fences, strict=True))
                    defense.lab.observer.observe("restricted", restricted)
                    return {"ready_to_confirmation_ns": elapsed_ns,
                            "prepare_ns": prepared_ns - started_ns, "cpu_ns": cpu_ns, **timing}

                with defense.lab:
                    if fault == "missing-audit":
                        with pytest.raises(Denied, match="exact durable Rapid decision"):
                            await defense.prepare(3_000)
                        assert defense.lab.store.history() == []
                        return None
                    started_ns = time.monotonic_ns()
                    started_cpu_ns = time.process_time_ns()
                    plan = await defense.prepare(3_000)
                    prepared_ns = time.monotonic_ns()
                    if legacy:
                        return await execute_healthy()
                    assert plan.ownership_binding == assignment.binding
                    assert "mesh_checkpoint_sha256" in gate.binding_context
                    assert "evidence_status_sha256" in gate.binding_context
                    controller = defense.lab.controller
                    if fault == "none":
                        return await execute_healthy()

                    approval = defense.lab.operator.approve(plan, plan.digest)
                    canary, peer, _ = plan.targets
                    await defense.transition(controller.start, plan, approval, action="begin")
                    await defense.transition(controller.restrict, plan, approval, canary,
                                             action="restrict", target=canary)
                    await defense.transition(controller.verify, plan, canary=True, action="verify-canary")

                    if fault == "journal-withdrawal":
                        network.archive.append(network.receive(network.withdrawal(finding)))
                        network.publish(network.seal())
                        reason = "withdrawn"
                    elif fault == "evidence-withdrawal":
                        now = int(time.time())
                        record = sign_record(Withdrawal(
                            kind="aegis.evidence.withdrawal.v1", issuer="review", key_id="lab-v1", cohort=COHORT,
                            record_id=uuid4().hex, issued_at=now, expires_at=now + 10, target_kind="bundle",
                            target_issuer="research", target_sha256=bundle.sha256, reason="invalid-evidence",
                        ), researcher.revoker)
                        assert witnesses[1].admit(record) == digest(record)
                        reason = "divergent-status"
                    elif fault == "critical-ack-unavailable":
                        assert gate.status_current()
                        withdrawal = network.withdrawal(finding)
                        issued_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                        withdrawal = sign_revocation(withdrawal.revocation.model_copy(update={
                            "issued_at": issued_at, "expires_at": issued_at + timedelta(seconds=8),
                        }), network.reviewer, "default")
                        ack_attempted = False
                        intake_ns = time.monotonic_ns()
                        cpu_intake_ns = time.process_time_ns()
                        timing = {}

                        async def no_ack():
                            nonlocal ack_attempted
                            # Separate SQLite observer and real HTTP probes run while
                            # the witnessed Mesh still considers this finding current.
                            assert journal.current(finding, intake.journal_binding)
                            assert not intake.withdrawal_clear(finding)
                            deadline = time.monotonic() + 2
                            while (any(state.mode != "quarantined" for state in
                                       defense.lab.store.inventory()[1].values()) and time.monotonic() < deadline):
                                await asyncio.sleep(.01)
                            assert all(state.mode == "quarantined" for state in
                                       defense.lab.store.inventory()[1].values())
                            fences = tuple((target, state.fence)
                                           for target, state in defense.lab.store.inventory()[1].items())
                            observation = await asyncio.to_thread(defense.lab.observer.observe, "quarantined", fences)
                            timing.update(readback_ns=observation.finished_ns - intake_ns,
                                          cpu_ns=time.process_time_ns() - cpu_intake_ns,
                                          observed_requests=observation.requests)
                            ack_attempted = True
                            raise ConnectionError("lost broker response after local denial")

                        await process_message(SimpleNamespace(data=withdrawal.model_dump_json().encode(),
                                                              ack_sync=no_ack),
                                              agent, lease=intake.lease, critical=True)
                        assert ack_attempted
                        reason = "exact durable Rapid decision"
                    elif fault == "offline-witness-pending":
                        network.archive.append(network.receive(network.withdrawal(finding)))

                        async def unavailable():
                            raise ConnectionError("witness quorum unavailable with pending withdrawal")

                        journal.heads = SimpleNamespace(latest=unavailable)
                        reason = "witnessed journal unavailable"
                    elif fault == "offline-status":
                        online = False
                        reason = "withheld-status"
                    else:
                        home.fence(assignment.generation)
                        home.accept(lease_proof("claim", home.candidate("broker-b"), key),
                                    peer_principal=principal, broker="broker-b")
                        reason = "assignment generation"

                    denied = JournalBlocked if fault == "offline-witness-pending" else Denied
                    with pytest.raises(denied, match=reason):
                        await defense.transition(controller.restrict, plan, approval, peer,
                                                 action="restrict", target=peer)
                    if fault == "offline-status":
                        online = True
                        with pytest.raises(Denied, match="Mesh status is not current"):
                            await defense.transition(controller.restrict, plan, approval, peer,
                                                     action="restrict", target=peer)
                    deadline = time.monotonic() + 2
                    while (any(state.mode != "quarantined" for state in
                               defense.lab.store.inventory()[1].values()) and time.monotonic() < deadline):
                        await asyncio.sleep(.01)
                    assert all(state.mode == "quarantined" for state in
                               defense.lab.store.inventory()[1].values())
                    before_recovery = tuple((target, state.fence)
                                            for target, state in defense.lab.store.inventory()[1].items())
                    defense.lab.observer.observe("quarantined", before_recovery)
                    assert controller.rollback("trust fixture interrupted") == "safe_hold"
                    rows = defense.lab.store.history()
                    assert [row["detail"]["target"] for row in rows if row["event"] == "restricted"] == [canary]
                    assert rows[-1]["event"] == "safe_hold"
                    after_recovery = tuple((target, state.fence)
                                           for target, state in defense.lab.store.inventory()[1].items())
                    defense.lab.observer.observe("quarantined", after_recovery)
                    return timing if fault == "critical-ack-unavailable" else None

    return asyncio.run(exercise())
