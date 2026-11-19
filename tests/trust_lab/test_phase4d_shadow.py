"""Cross-readback tests with independent native and prototype trust stores."""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence as Reference, Finding, Software, canonical_bytes
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.records import Withdrawal, digest, sign_record
from aegis.evidence.status import RelyingStatus, StatusProof, StatusWitness
from aegis.evidence.status_protocol import StatusPolicy, WitnessGrant, observe
from aegis.evidence.synthetic import create_lab
from aegis.phase3c import (
    COHORT, EvidenceGate, MESH_TEMPLATE, MeshIntake, PACKAGE, VERSION, VerifiedLab,
    publishable_finding,
)
from aegis.mitigation.policy import Denied
from aegis.storage import SqliteAudit
from aegis.trust_lab.history import Subject
from aegis.trust_lab.identity import Hold
from aegis.trust_lab.native_evidence import NativeEvidenceStatus
from aegis.trust_lab.shadow import compare
from trust_fixtures import DEPLOYMENT, Scenario


class FixtureLease:
    async def ensure(self):
        return None


def assert_independent_withdrawal(gate, researcher, path):
    """Check direct admission against the same bundle the legacy gate appraises."""
    keys = tuple(Ed25519PrivateKey.generate() for _ in range(2))
    policy = StatusPolicy("phase4d-shadow", COHORT, "research-org", "operator-org", researcher.trust, tuple(
        WitnessGrant(f"witness-{index}", f"status-org-{index}", key.public_key())
        for index, key in enumerate(keys)))
    witnesses = tuple(StatusWitness(path / f"status-{index}.sqlite", policy, grant.witness_id, key,
                                    provision=True)
                      for index, (grant, key) in enumerate(zip(policy.witnesses, keys, strict=True)))
    reader = RelyingStatus(path / "status-reader.sqlite", policy, DEPLOYMENT, provision=True)
    observations = tuple(observe(policy, verifier, gate.bundle, clock=time.time)
                         for verifier in researcher.verifiers)
    for witness in witnesses:
        for record in (gate.bundle.manifest, *observations):
            assert witness.admit(record) == digest(record)

    def fetch(request):
        first, second = (witness.endorse(request) for witness in witnesses)
        return StatusProof(first.endorsements + second.endorsements, first.records)

    def evaluate(fetch_proof, audience=DEPLOYMENT):
        return NativeEvidenceStatus(reader, fetch_proof).require(gate.envelope.finding, gate.bundle, audience)

    assert evaluate(fetch).current()
    with pytest.raises(Denied, match="audience"):
        evaluate(fetch, "another-deployment")
    now = int(datetime.now(timezone.utc).timestamp())
    withdrawal = sign_record(Withdrawal(
        kind="aegis.evidence.withdrawal.v1", issuer="review", key_id="lab-v1", cohort=COHORT,
        record_id=uuid4().hex, issued_at=now, expires_at=now + 30, target_kind="bundle",
        target_issuer="research", target_sha256=gate.bundle.sha256, reason="invalid-evidence",
    ), researcher.revoker)
    assert witnesses[1].admit(withdrawal) == digest(withdrawal)
    with pytest.raises(Denied, match="withheld-status"):
        evaluate(witnesses[0].endorse)
    with pytest.raises(Denied, match="divergent-status"):
        evaluate(fetch)
    assert witnesses[0].admit(withdrawal) == digest(withdrawal)
    with pytest.raises(Denied, match="revoked"):
        evaluate(fetch)


@pytest.mark.parametrize("matched", [True, False])
def test_native_exact_bundle_and_prototype_cut_remain_non_executable(tmp_path: Path, matched):
    async def run():
        key = Ed25519PrivateKey.generate()
        researcher = create_lab()
        trust = Scenario(tmp_path)
        now = datetime.now(timezone.utc)
        native_finding = Finding(
            schema_version="1.0", artifact_id=DEPLOYMENT, publisher_id="lab-publisher", sequence=1,
            issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(minutes=2),
            vulnerability_id="AEGIS-4D-MARKER",
            software=Software(purl=PACKAGE, affected_versions=[VERSION]),
            evidence=[Reference(uri="urn:unused", sha256="0" * 64, method="lab-reproduction")],
            applicability="authorized-lab", mitigation_template=MESH_TEMPLATE,
        )
        audit = SqliteAudit(tmp_path / "rapid.sqlite", DEPLOYMENT)
        try:
            agent = LocalAgent(LocalPolicy({"lab-publisher": key.public_key()},
                                           frozenset({MESH_TEMPLATE}), True),
                               [InventoryItem(PACKAGE, VERSION)], audit)
            async with httpx.AsyncClient(base_url="http://127.0.0.1", transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"head": 0, "events": []}),
            )) as client:
                receiver = MeshIntake(agent, None, client)
                receiver.lease = FixtureLease()
                with (Evidence(tmp_path / "collector.sqlite", researcher.trust, researcher.verifiers) as collector,
                      Evidence(tmp_path / "relying.sqlite", researcher.trust) as relying):
                    envelope, bundle, assessment = publishable_finding(native_finding, key, researcher, collector)
                    assert agent.evaluate_event(envelope).outcome == "allow_dry_run"
                    gate = EvidenceGate(envelope, bundle, assessment, receiver, collector, relying)
                    if matched:
                        trust.subject = Subject(finding=digest(canonical_bytes(envelope.finding)),
                                                evidence=bundle.sha256)
                    trust.seed()
                    defense = VerifiedLab(gate, tmp_path / "native-fixture.sqlite")
                    with defense.lab:
                        plan = await defense.prepare(3000)
                        expected_fences = tuple(zip(plan.targets, plan.expected_fences, strict=True))
                        challenge = trust.begin()
                        cut = trust.cut(challenge)
                        proof = trust.sign(challenge.holder, "agent-proof", challenge)
                        status = trust.status(cut)
                        before = trust.target.snapshot()

                        if matched:
                            agreement = await compare(gate, plan, trust.evaluator, proof, cut, status, trust.chain)
                            assert (agreement.finding, agreement.evidence, agreement.native_binding) == (
                                trust.subject.finding, trust.subject.evidence, plan.evidence_binding)
                            assert not hasattr(agreement, "approval")
                            assert not hasattr(agreement, "apply")
                            assert_independent_withdrawal(gate, researcher, tmp_path)
                            # The coordinator omitted every withdrawal. The
                            # legacy view still treats this exact plan as fresh.
                            await gate.refresh()
                            with gate.authorize(plan) as legacy:
                                assert legacy["bundle_sha256"] == agreement.evidence
                        else:
                            with pytest.raises(Hold, match="disagreement"):
                                await compare(gate, plan, trust.evaluator, proof, cut, status, trust.chain)

                        # Read both state machines independently. Fresh preparation
                        # is necessary even for the prototype's synthetic writer.
                        assert trust.target.snapshot() == before
                        assert all(event[1] != "restrict" for event in trust.target.events())
                        with pytest.raises(Hold, match="fresh authenticated reconciliation"):
                            trust.evaluator.reconcile(proof, cut, status, trust.chain, trust.subject, "restrict")
                        assert defense.lab.store.history() == []
                        defense.lab.observer.observe("open", expected_fences)
        finally:
            audit.db.close()

    asyncio.run(run())
