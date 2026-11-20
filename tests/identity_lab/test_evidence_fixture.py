"""One B target transaction with an independently appraised native T4/T5 cut."""

import asyncio
from contextlib import ExitStack, closing
from datetime import datetime, timedelta, timezone
import sqlite3
from time import monotonic_ns, time
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.records import digest
from aegis.evidence.status import RelyingStatus, StatusProof, StatusWitness
from aegis.evidence.status_protocol import StatusPolicy, WitnessGrant, observe
from aegis.evidence.synthetic import create_lab
from aegis.identity_lab import evidence_fixture
from aegis.identity_lab.evidence_fixture import (
    EvidenceApproval, EvidenceBoundTarget, NativeAppraisal, sign_evidence_approval,
)
from aegis.identity_lab.protocol import Denied, InstalledFence, principal
from aegis.identity_lab.services import Target
from aegis.identity_lab.transport import Peer
from aegis.mitigation.lab import Controller
from aegis.mitigation.policy import LocalOperator
from aegis.mitigation.store import TargetStore
from aegis.phase3c import (
    COHORT, MESH_TEMPLATE, PACKAGE, VERSION, EvidenceGate, MeshIntake, publishable_finding,
)
from aegis.storage import SqliteAudit
from aegis.trust_lab.native_evidence import NativeEvidenceStatus
from tests.phase4d.test_journal import Network

from test_fencing import claim, plan, recover


@pytest.fixture
def native_appraisal(lab, tmp_path):
    root = tmp_path / "native"
    root.mkdir()
    with ExitStack() as stack:
        network = Network(root, stack)
        researcher = create_lab()
        collector = stack.enter_context(Evidence(root / "collector.sqlite", researcher.trust,
                                                 researcher.verifiers))
        relying = stack.enter_context(Evidence(root / "evidence.sqlite", researcher.trust))
        proposal = network.finding()
        now = datetime.now(timezone.utc)
        proposal = proposal.model_copy(update={"issued_at": min(proposal.issued_at,
                                                               now - timedelta(seconds=1))})
        finding, bundle, appraisal = publishable_finding(proposal, network.author, researcher, collector)
        network.archive.append(network.receive(finding))
        network.publish(network.seal())
        journal = network.client()
        audit = SqliteAudit(root / "rapid.sqlite", lab.policy.deployment)
        stack.enter_context(closing(audit.db))
        agent = LocalAgent(LocalPolicy(network.trust, frozenset({MESH_TEMPLATE}), True),
                           [InventoryItem(PACKAGE, VERSION)], audit)
        assert agent.evaluate_event(finding).outcome == "allow_dry_run"

        keys = tuple(Ed25519PrivateKey.generate() for _ in range(2))
        grants = tuple(WitnessGrant(f"status-{i}", f"witness-{i}", key.public_key())
                       for i, key in enumerate(keys))
        policy = StatusPolicy("phase4e-b", COHORT, "research-org", "local-operator", researcher.trust, grants)
        witnesses = tuple(StatusWitness(root / f"status-{i}.sqlite", policy, grant.witness_id, key,
                                        provision=True)
                          for i, (grant, key) in enumerate(zip(grants, keys, strict=True)))
        observations = tuple(observe(policy, verifier, bundle, clock=time) for verifier in researcher.verifiers)
        for witness in witnesses:
            for record in (bundle.manifest, *observations):
                assert witness.admit(record) == digest(record)

        def fetch(challenge):
            first, second = (witness.endorse(challenge) for witness in witnesses)
            return StatusProof(first.endorsements + second.endorsements, first.records)

        def coordinator(_request):
            pytest.fail("the native appraisal queried the legacy coordinator")

        reader = RelyingStatus(root / "reader.sqlite", policy, audit.agent_id, provision=True)
        transport = httpx.MockTransport(coordinator)
        remote = httpx.AsyncClient(base_url="http://coordinator.invalid", transport=transport)
        stack.callback(lambda: asyncio.run(remote.aclose()))
        intake = MeshIntake(agent, None, remote, journal=journal)
        intake.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
        gate = EvidenceGate(finding, bundle, appraisal, intake, collector, relying,
                            independent_evidence=NativeEvidenceStatus(reader, fetch))
        asyncio.run(gate.refresh())
        operator = LocalOperator()
        store = TargetStore(root / "native-plan-fixture.sqlite", operator)
        store.create()
        native_plan = gate.prepare(Controller(store, operator, None), 3000)
        yield NativeAppraisal(gate, native_plan), network


def inspect(target_path):
    with closing(sqlite3.connect(target_path.as_uri() + "?mode=ro", uri=True)) as db:
        version, marker = db.execute("SELECT version,value FROM marker").fetchone()
        fence = InstalledFence.model_validate_json(db.execute("SELECT body FROM record").fetchone()[0])
        receipts = db.execute("SELECT generation,marker FROM receipts ORDER BY rowid").fetchall()
    return version, marker, receipts, fence


@pytest.mark.parametrize("fault, reason", [
    ("none", None),
    ("wrong-cut", "cut differs"),
    ("wrong-approval", "approval signature"),
    ("wrong-plan", "exact mutation and native plan"),
    ("wrong-target", "exact mutation and native plan"),
    ("stale-generation", "durable fence"),
    ("new-witness-cut", "native appraisal is unavailable"),
    ("expiry-after-owner", "exclusive deadline"),
    ("native-expiry-after-owner", "exclusive deadline"),
    ("expiry-during-status-read", "exclusive deadline"),
])
def test_exact_evidence_in_b_transaction(lab, native_appraisal, fault, reason, monkeypatch):
    native, network = native_appraisal
    assignment = claim(lab)
    request = plan(lab, assignment, "target-a")
    path = lab.database("target-a")
    _, _, _, first_fence = inspect(path)
    target = EvidenceBoundTarget("target-a", path, lab.policy, lab.client("target-a"), lab.endpoints,
                                 boot=first_fence.boot)
    peer = Peer(principal(assignment.broker), "0" * 64, assignment.expires_ns)
    key = lab.approval
    asyncio.run(native.gate.refresh())
    with native.verified_cut() as cut:
        body = EvidenceApproval(mutation=request.command.body.mutation, cut=cut,
                                native_plan_sha256=native.plan.digest, expires_ns=native.plan.expires_ns)
    if fault == "wrong-cut":
        body = body.model_copy(update={"cut": cut.model_copy(update={"evidence_status_sha256": "0" * 64})})
    elif fault == "wrong-target":
        body = body.model_copy(update={"mutation": body.mutation.model_copy(update={"target": "target-b"})})
    elif fault == "wrong-approval":
        key = lab.instances["agent-a"]
    elif fault == "wrong-plan":
        body = body.model_copy(update={"native_plan_sha256": "0" * 64})
    elif fault == "stale-generation":
        recover(lab)
        claim(lab, "agent-b", "broker-b")
    elif fault == "new-witness-cut":
        network.publish(network.seal())
        asyncio.run(native.gate.refresh())
    elif fault in {"expiry-after-owner", "expiry-during-status-read"}:
        body = body.model_copy(update={"expires_ns": native.plan.expires_ns - 1_000_000_000})
    elif fault == "native-expiry-after-owner":
        body = body.model_copy(update={"expires_ns": native.plan.expires_ns + 1_000_000_000})
    approval = sign_evidence_approval(body, key)
    before = inspect(path)

    if fault in {"expiry-after-owner", "native-expiry-after-owner", "expiry-during-status-read"}:
        base_apply = Target.apply
        base_current = Target.require_current
        base_status = native.gate.status_current
        staged = []
        checked_owner = []
        checked_status = []
        cutoff = min(body.expires_ns, native.plan.expires_ns)
        assert monotonic_ns() < cutoff

        def stage(writer, db, attempt):
            result = base_apply(writer, db, attempt)
            assert db.execute("SELECT COUNT(*) FROM receipts").fetchone() == (1,)
            staged.append(True)
            return result

        def final_owner(writer, offered):
            assert staged
            base_current(writer, offered)
            checked_owner.append(True)

        def final_status():
            result = base_status()
            if checked_owner:
                assert result
                checked_status.append(True)
            return result

        with monkeypatch.context() as patches:
            patches.setattr(Target, "apply", stage)
            patches.setattr(Target, "require_current", final_owner)
            if fault == "expiry-during-status-read":
                patches.setattr(native.gate, "status_current", final_status)
                expire_at = checked_status
            else:
                expire_at = checked_owner
            patches.setattr(evidence_fixture, "monotonic_ns", lambda: cutoff if expire_at else monotonic_ns())
            with pytest.raises(Denied, match=reason):
                target.write_verified(peer, request, approval, native)
        assert staged == checked_owner == [True]
        if fault == "expiry-during-status-read":
            assert checked_status == [True]
        assert inspect(path) == before
        # The requested write's nonce was rolled back with the marker update.
        asyncio.run(native.gate.refresh())
        target.write_verified(peer, request, approval, native)
        assert inspect(path)[0:3] == (before[0] + 1, "observing", [(assignment.generation, "observing")])
    elif reason:
        with pytest.raises(Denied, match=reason):
            target.write_verified(peer, request, approval, native)
        assert inspect(path) == before
    else:
        with pytest.raises(Denied, match="Evidence-bound entry point"):
            target.write(peer, request)
        assert inspect(path) == before
        target.write_verified(peer, request, approval, native)
        assert inspect(path)[0:3] == (before[0] + 1, "observing", [(assignment.generation, "observing")])
