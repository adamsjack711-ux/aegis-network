"""Test the integrated gates against real signed records and the live HTTP fixture."""

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence as Reference, Finding, Software
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.records import (
    Observation, SignedAttestation, Withdrawal, decode, sign_record,
)
from aegis.evidence.synthetic import create_lab
from aegis.mitigation.policy import Denied
from aegis.phase3c import (
    COHORT, MESH_TEMPLATE, EvidenceGate, MeshIntake, PACKAGE, VERSION, VerifiedLab,
    publishable_finding,
)
from aegis.storage import SqliteAudit


@pytest.fixture
def enrolled(tmp_path):
    now = datetime.now(timezone.utc)
    author = Ed25519PrivateKey.generate()
    researcher = create_lab()
    finding = Finding(
        schema_version="1.0", artifact_id=uuid4(), publisher_id="lab-publisher", sequence=1,
        issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(minutes=2),
        vulnerability_id="PHASE3C-MARKER", software=Software(purl=PACKAGE, affected_versions=[VERSION]),
        evidence=[Reference(uri="urn:unused", sha256="0" * 64, method="lab-reproduction")],
        applicability="authorized-lab", mitigation_template=MESH_TEMPLATE,
    )
    with (Evidence(tmp_path / "collector.db", researcher.trust, researcher.verifiers) as collector,
          Evidence(tmp_path / "evidence.db", researcher.trust) as relying):
        envelope, bundle, assessment = publishable_finding(finding, author, researcher, collector)
        audit = SqliteAudit(tmp_path / "rapid.db", str(uuid4()))
        try:
            agent = LocalAgent(LocalPolicy({"lab-publisher": author.public_key()},
                                           frozenset({MESH_TEMPLATE}), True),
                               [InventoryItem(PACKAGE, VERSION)], audit)
            assert agent.evaluate_event(envelope).outcome == "allow_dry_run"
            yield SimpleNamespace(envelope=envelope, bundle=bundle, assessment=assessment, agent=agent,
                                  researcher=researcher, collector=collector, relying=relying)
        finally:
            audit.db.close()


def gate(enrolled, receiver):
    return EvidenceGate(enrolled.envelope, enrolled.bundle, enrolled.assessment,
                        receiver, enrolled.collector, enrolled.relying)


def test_reject_claim_rebinding_and_forged_or_unauthorized_attestation(enrolled):
    receiver = SimpleNamespace(agent=enrolled.agent)
    changed = enrolled.envelope.finding.model_copy(update={"artifact_id": uuid4()})
    with pytest.raises(Denied, match="exact enrolled"):
        EvidenceGate(enrolled.envelope.model_copy(update={"finding": changed}), enrolled.bundle,
                     enrolled.assessment, receiver, enrolled.collector, enrolled.relying)
    wire = enrolled.assessment.attestations[0]
    original = decode(SignedAttestation, wire).body
    key = Ed25519PrivateKey.generate()
    for body in (original, original.model_copy(update={"issuer": "not-enrolled"})):
        forged = replace(enrolled.assessment, attestations=(sign_record(body, key),))
        with pytest.raises(ValueError):
            EvidenceGate(enrolled.envelope, enrolled.bundle, forged, receiver,
                         enrolled.collector, enrolled.relying)


def test_contradiction_invalidates_exact_plan_even_with_cached_positive(enrolled, tmp_path):
    async def run():
        async with httpx.AsyncClient(base_url="http://127.0.0.1",
                                     transport=httpx.MockTransport(lambda req: httpx.Response(
                                         200, json={"head": 0, "events": []},
                                     ))) as client:
            receiver = MeshIntake(enrolled.agent, None, client)
            receiver.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
            defense = VerifiedLab(gate(enrolled, receiver), tmp_path / "fixture.db")
            with defense.lab:
                plan = await defense.prepare(3000)
                wire = enrolled.assessment.attestations[0]
                positive = decode(SignedAttestation, wire).body
                signer = next(v for v in enrolled.researcher.verifiers if v.issuer == positive.issuer)
                counter = positive.model_copy(update={"record_id": uuid4().hex,
                    "observation": Observation(outcome="not-reproduced", reason="marker-absent",
                                               positive_control=True, negative_control=True)})
                outcome = enrolled.collector.accept_attestation(
                    enrolled.bundle, sign_record(counter, signer.private_key), cohort=COHORT,
                )
                assert outcome.reason == "contested"
                with pytest.raises(Denied, match="contested"):
                    await defense.execute(plan, plan.digest)
                assert defense.lab.store.history() == []
    asyncio.run(run())


def test_partial_rollout_withdrawal_leaves_safe_hold_and_no_peer_writes(enrolled, tmp_path):
    async def run():
        async with httpx.AsyncClient(base_url="http://127.0.0.1",
                                     transport=httpx.MockTransport(lambda req: httpx.Response(
                                         200, json={"head": 0, "events": []},
                                     ))) as client:
            receiver = MeshIntake(enrolled.agent, None, client)
            receiver.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
            defense = VerifiedLab(gate(enrolled, receiver), tmp_path / "fixture.db")
            with defense.lab:
                plan = await defense.prepare(3000)
                controller = defense.lab.controller
                verify = controller.verify

                def withdraw_after_canary(plan, *, canary=False):
                    verify(plan, canary=canary)
                    if canary:
                        now = int(time.time())
                        withdrawal = Withdrawal(kind="aegis.evidence.withdrawal.v1", record_id=uuid4().hex,
                                                issuer="review", key_id="lab-v1", cohort=COHORT,
                                                issued_at=now, expires_at=now + 60,
                                                target_kind="bundle", target_issuer="research",
                                                target_sha256=enrolled.bundle.sha256, reason="withdrawn")
                        enrolled.collector.accept_withdrawal(
                            sign_record(withdrawal, enrolled.researcher.revoker), cohort=COHORT,
                        )
                controller.verify = withdraw_after_canary
                with pytest.raises(Denied, match="bundle-withdrawn"):
                    await defense.execute(plan, plan.digest)
                assert defense.lab.store.status() == "safe_hold"
                history = defense.lab.store.history()
                assert [r["detail"]["target"] for r in history if r["event"] == "restricted"] == ["canary"]
                assert not any(r["event"] == "confirmed" for r in history)
                _, targets = defense.lab.store.inventory()
                defense.lab.observer.observe("quarantined", tuple((key, target.fence)
                                                                  for key, target in targets.items()))
    asyncio.run(run())


def test_inexact_approval_and_stale_status_never_write(enrolled, tmp_path):
    async def run():
        async with httpx.AsyncClient(base_url="http://127.0.0.1",
                                     transport=httpx.MockTransport(lambda req: httpx.Response(
                                         200, json={"head": 0, "events": []},
                                     ))) as client:
            receiver = MeshIntake(enrolled.agent, None, client)
            receiver.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
            defense = VerifiedLab(gate(enrolled, receiver), tmp_path / "fixture.db")
            with defense.lab:
                plan = await defense.prepare(3000)
                with pytest.raises(Denied, match="exact reviewed"):
                    await defense.execute(plan, "0" * 64)
                approved = defense.lab.operator.approve(plan, plan.digest)
                defense.gate._fresh_until = 0
                with pytest.raises(Denied, match="not current"):
                    defense.lab.controller.start(plan, approved)
                assert defense.lab.store.history() == []
    asyncio.run(run())


@pytest.mark.parametrize("failover", [False, True], ids=["healthy", "failover-after-canary"])
def test_phase4d_ownership_with_real_evidence_and_target_readback(enrolled, tmp_path, failover):
    from aegis.mitigation.policy import LocalOperator
    from aegis.mitigation.store import TargetStore
    from aegis.ownership import IdentitySession, lease_proof

    async def run():
        async with httpx.AsyncClient(base_url="http://127.0.0.1",
                                     transport=httpx.MockTransport(lambda req: httpx.Response(
                                         200, json={"head": 0, "events": []},
                                     ))) as client:
            receiver = MeshIntake(enrolled.agent, None, client)
            receiver.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
            path = tmp_path / "fixture.db"
            provision = TargetStore(path, LocalOperator())
            provision.create()
            principal = "spiffe://aegis.test/workload/phase4d"
            key = Ed25519PrivateKey.generate()
            provision.ownership.enroll(enrolled.agent.audit.agent_id, principal, key.public_key(),
                                       ("broker-a", "broker-b"))

            def claim(broker):
                # Fixture-level trust adapter inputs. The test runs no TLS listener.
                home = provision.ownership
                return IdentitySession(home.accept(lease_proof("claim", home.candidate(broker), key),
                                                   peer_principal=principal, broker=broker), key)

            prior = claim("broker-a")
            defense = VerifiedLab(gate(enrolled, receiver), path, identity=prior)
            with defense.lab:
                plan = await defense.prepare(3000)
                assert plan.ownership_binding == prior.assignment.binding
                if not failover:
                    await defense.execute(plan, plan.digest)
                    assert defense.lab.store.status() == "confirmed"
                    defense.lab.observer.observe("restricted", tuple((t, 1) for t in plan.targets))
                    return

                approval = defense.lab.operator.approve(plan, plan.digest)
                controller = defense.lab.controller
                canary, peer, _ = plan.targets
                await defense.transition(controller.start, plan, approval, action="begin")
                await defense.transition(controller.restrict, plan, approval, canary,
                                         action="restrict", target=canary)
                await defense.transition(controller.verify, plan, canary=True, action="verify-canary")
                provision.ownership.fence(prior.assignment.generation)
                replacement = claim("broker-b")
                assert replacement.assignment.generation == prior.assignment.generation + 2

                # The target-owned watcher must commit before the first observer request.
                deadline = time.monotonic() + 2
                while (any(state.mode != "quarantined" for state in
                           defense.lab.store.inventory()[1].values()) and time.monotonic() < deadline):
                    await asyncio.sleep(.01)
                assert all(state.mode == "quarantined" for state in
                           defense.lab.store.inventory()[1].values())
                fences = tuple((target, state.fence)
                               for target, state in defense.lab.store.inventory()[1].items())
                defense.lab.observer.observe("quarantined", fences)
                with pytest.raises(Denied, match="stale"):
                    await defense.transition(controller.restrict, plan, approval, peer,
                                             action="restrict", target=peer)
                with pytest.raises(Denied, match="exact approved plan"):
                    controller.restrict(plan, approval, peer,
                                        command=replacement.command("restrict", plan.digest, peer))
                assert [row["event"] for row in defense.lab.store.history()] == [
                    "leased", "restricted", "canary_verified", "quarantined",
                ]
                assert tuple(state.fence for state in defense.lab.store.inventory()[1].values()) == (2, 1, 1)
                assert controller.rollback("ownership lost") == "safe_hold"
                defense.lab.observer.observe("quarantined",
                                             fences)

    asyncio.run(run())
