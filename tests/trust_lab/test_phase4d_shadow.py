"""Cross-readback tests with independent native and prototype trust stores."""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence as Reference, Finding, Software, canonical_bytes
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.records import digest
from aegis.evidence.synthetic import create_lab
from aegis.phase3c import (
    EvidenceGate, MESH_TEMPLATE, MeshIntake, PACKAGE, VERSION, VerifiedLab, publishable_finding,
)
from aegis.storage import SqliteAudit
from aegis.trust_lab.history import Subject
from aegis.trust_lab.identity import Hold
from aegis.trust_lab.shadow import compare
from trust_fixtures import DEPLOYMENT, Scenario


class FixtureLease:
    async def ensure(self):
        return None


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
