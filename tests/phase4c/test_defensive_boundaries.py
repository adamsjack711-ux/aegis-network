"""Observe the integrated safety gates using only disposable fixtures."""

import asyncio
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
import json
import sqlite3
import time
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence as Reference
from aegis.artifact import Finding, Revocation, Software, sign, sign_revocation
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.synthetic import create_lab
from aegis.mitigation.policy import Denied
from aegis.phase3c import (
    COHORT, MESH_TEMPLATE, PACKAGE, VERSION, EvidenceGate, MeshIntake, VerifiedLab,
    claim_bytes, publishable_finding,
)
from aegis.storage import SqliteAudit
from aegis.trust import PublisherGrant, TrustStore


REPLICAS = ("canary", "replica-a", "replica-b")
ROUTES = ("/fixture-marker", "/health", "/ok")


class Journal:
    def __init__(self):
        self.events = []
        self.available = True

    def append(self, envelope):
        self.events.append({"position": len(self.events) + 1, "envelope": envelope.model_dump(mode="json")})

    def client(self):
        return httpx.AsyncClient(base_url="http://phase4c.invalid", transport=httpx.MockTransport(self.respond))

    def respond(self, request):
        assert request.method == "GET" and request.url.path == "/v1/events"
        if not self.available:
            return httpx.Response(503)
        after = int(request.url.params["after"])
        limit = int(request.url.params["limit"])
        return httpx.Response(200, json={"head": len(self.events), "events": self.events[after:after + limit]})


class AvailableLease:
    async def ensure(self):
        pass  # Broker lease behavior is covered by the Phase 2 hardening suite.


@pytest.fixture
def pipeline(tmp_path):
    now = datetime.now(timezone.utc)
    publisher = Ed25519PrivateKey.generate()
    revoker = Ed25519PrivateKey.generate()
    start, end = now - timedelta(hours=1), now + timedelta(hours=1)
    publisher_grant = PublisherGrant("phase4c-finder", "default", publisher.public_key(),
                                     frozenset({"finding"}), start, end)
    revoker_grant = PublisherGrant("phase4c-review", "default", revoker.public_key(),
                                   frozenset({"revocation"}), start, end,
                                   revocation_publishers=frozenset({"phase4c-finder"}))
    researcher = create_lab()
    finding = Finding(
        schema_version="1.0", artifact_id=uuid4(), publisher_id=publisher_grant.publisher_id, sequence=1,
        issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(minutes=5),
        vulnerability_id="PHASE4C-BENIGN-MARKER",
        software=Software(purl=PACKAGE, affected_versions=[VERSION]),
        evidence=[Reference(uri="urn:unbound", sha256="0" * 64, method="lab-reproduction")],
        applicability="authorized-lab", mitigation_template=MESH_TEMPLATE,
    )
    audit = SqliteAudit(tmp_path / "rapid.db", str(uuid4()))
    with (closing(audit.db),
          Evidence(tmp_path / "collector.db", researcher.trust, researcher.verifiers) as collector,
          Evidence(tmp_path / "relying.db", researcher.trust) as relying):
        envelope, bundle, assessment = publishable_finding(finding, publisher, researcher, collector)

        def enroll(client, grant=publisher_grant):
            policy = LocalPolicy(TrustStore([grant, revoker_grant]), frozenset({MESH_TEMPLATE}), True)
            agent = LocalAgent(policy, [InventoryItem(PACKAGE, VERSION)], audit)
            intake = MeshIntake(agent, None, client)
            intake.lease = AvailableLease()
            return intake

        def defense(intake):
            gate = EvidenceGate(envelope, bundle, assessment, intake, collector, relying)
            return VerifiedLab(gate, tmp_path / "fixture.db")

        yield {
            "envelope": envelope, "publisher": publisher, "enroll": enroll,
            "defense": defense, "publisher_grant": publisher_grant, "revoker": revoker,
            "revoker_grant": revoker_grant, "researcher": researcher, "collector": collector, "relying": relying,
        }


def read_rows(path, query):
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as db:
        return db.execute(query).fetchall()


def restrictions(path):
    return [
        json.loads(detail)["target"]
        for detail, in read_rows(path, "SELECT detail FROM audit WHERE event = 'restricted' ORDER BY seq")
    ]


def probe_all(lab, phase, fences):
    """Read the live routes directly, without calling the controller's observer."""
    assert set(lab.endpoints) == set(REPLICAS)
    for target, fence in zip(REPLICAS, fences, strict=True):
        host, port = lab.endpoints[target]
        assert host == "127.0.0.1"
        for route in ROUTES:
            with closing(HTTPConnection(host, port, timeout=1)) as conn:
                conn.request("GET", route)
                response = conn.getresponse()
                actual = (response.status, response.read())
                assert response.getheader("X-Lab-Target") == target
                assert response.getheader("X-Lab-Fence") == str(fence)
            if phase == "quarantined":
                expected = (503, b"fixture quarantined")
            elif phase == "restricted" and route == "/fixture-marker":
                expected = (403, b"fixture route restricted")
            else:
                expected = (200, f"{target}:{route}".encode())
            assert actual == expected, (target, route)


@pytest.mark.parametrize(("fault", "reason"), [
    ("wrong-signer", "INVALID_SIGNATURE"),
    ("wrong-role", "PUBLISHER_ROLE_DENIED"),
    ("expired", "PUBLISHER_KEY_INVALID_TIME"),
    ("revoked", "PUBLISHER_KEY_REVOKED"),
])
def test_publisher_denial_cannot_lease_fixture(pipeline, tmp_path, fault, reason):
    journal = Journal()
    grant = pipeline["publisher_grant"]
    event = pipeline["envelope"]
    if fault == "wrong-signer":
        event = sign(event.finding, Ed25519PrivateKey.generate())
    elif fault == "wrong-role":
        grant = replace(grant, roles=frozenset({"revocation"}))
    elif fault == "expired":
        grant = replace(grant, expires_at=event.finding.issued_at)
    elif fault == "revoked":
        grant = replace(grant, revoked_at=event.finding.issued_at)
    journal.append(event)

    async def scenario():
        async with journal.client() as client:
            defense = pipeline["defense"](pipeline["enroll"](client, grant))
            with defense.lab:
                with pytest.raises(Denied, match="exact delivered finding has no local audit"):
                    await defense.prepare(3000)
                assert read_rows(tmp_path / "rapid.db", "SELECT outcome FROM decisions") == []
                assert read_rows(tmp_path / "rapid.db", "SELECT reason_code FROM rejected_events") == [(reason,)]
                assert read_rows(tmp_path / "fixture.db", "SELECT event FROM audit") == []
                probe_all(defense.lab, "open", (0, 0, 0))

    asyncio.run(scenario())


def test_valid_evidence_from_another_cohort_cannot_prepare(pipeline, tmp_path):
    journal = Journal()
    envelope = pipeline["envelope"]
    cohort = "lab-green"
    bundle = pipeline["researcher"].bundle(claim_bytes(envelope.finding).decode(),
                                            family="route-toggle", cohort=cohort)
    result = pipeline["collector"].verify(bundle, cohort=cohort)
    assert result.outcome == "reproduced"
    reference = Reference(uri="urn:aegis:evidence:" + bundle.sha256, sha256=bundle.sha256,
                          method="lab-reproduction")
    scoped = envelope.finding.model_copy(update={"evidence": [reference]})
    envelope = sign(scoped, pipeline["publisher"])

    async def scenario():
        async with journal.client() as client:
            intake = pipeline["enroll"](client)
            with pytest.raises(Denied, match="exact enrolled"):
                EvidenceGate(envelope, bundle, result, intake, pipeline["collector"], pipeline["relying"])
            assert not (tmp_path / "fixture.db").exists()

    asyncio.run(scenario())


def test_plan_review_and_initial_status_are_both_required(pipeline, tmp_path):
    journal = Journal()
    journal.append(pipeline["envelope"])

    async def scenario():
        async with journal.client() as client:
            defense = pipeline["defense"](pipeline["enroll"](client))
            with defense.lab:
                journal.available = False
                with pytest.raises(httpx.HTTPStatusError) as unavailable:
                    await defense.prepare(3000)
                assert unavailable.value.response.status_code == 503
                journal.available = True
                reviewed = await defense.prepare(3000)
                replacement = await defense.prepare(3000)
                assert replacement.digest != reviewed.digest
                with pytest.raises(Denied, match="exact reviewed"):
                    await defense.execute(replacement, reviewed.digest)
                journal.available = False
                with pytest.raises(httpx.HTTPStatusError):
                    await defense.execute(reviewed, reviewed.digest)
                assert read_rows(tmp_path / "fixture.db", "SELECT event FROM audit") == []
                probe_all(defense.lab, "open", (0, 0, 0))

    asyncio.run(scenario())


def test_signed_journal_withdrawal_after_canary_stops_expansion(pipeline, tmp_path):
    journal = Journal()
    envelope = pipeline["envelope"]
    journal.append(envelope)

    async def scenario():
        async with journal.client() as client:
            defense = pipeline["defense"](pipeline["enroll"](client))
            with defense.lab:
                plan = await defense.prepare(3000)
                # The local audit supplies the finding digest, distinct from its evidence digest.
                ((finding_digest,),) = read_rows(tmp_path / "rapid.db", "SELECT digest FROM decisions")
                now = datetime.now(timezone.utc)
                withdrawal = Revocation(
                    schema_version="1.1", revocation_id=uuid4(), sequence=1,
                    publisher_id=pipeline["revoker_grant"].publisher_id,
                    issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(minutes=1),
                    target_artifact_id=envelope.finding.artifact_id, target_sha256=finding_digest,
                    target_publisher_id=envelope.finding.publisher_id, reason="withdrawn",
                )
                signed = sign_revocation(withdrawal, pipeline["revoker"], pipeline["revoker_grant"].key_id)
                verify = defense.lab.controller.verify

                def publish_withdrawal(plan, *, canary=False):
                    verify(plan, canary=canary)
                    if canary:
                        journal.append(signed)

                defense.lab.controller.verify = publish_withdrawal
                with pytest.raises(Denied, match="FINDING_REVOKED"):
                    await defense.execute(plan, plan.digest)
                audit_path = tmp_path / "rapid.db"
                assert read_rows(audit_path, "SELECT position FROM recovery_cursor") == [(2,)]
                assert read_rows(audit_path, "SELECT target_publisher_id, artifact_id, digest FROM revoked_targets") == [
                    (envelope.finding.publisher_id, str(envelope.finding.artifact_id), finding_digest),
                ]
                path = tmp_path / "fixture.db"
                assert restrictions(path) == ["canary"]
                assert read_rows(path, "SELECT event FROM audit ORDER BY seq") == [
                    ("leased",), ("restricted",), ("canary_verified",), ("quarantined",), ("safe_hold",),
                ]
                probe_all(defense.lab, "quarantined", (2, 1, 1))

    asyncio.run(scenario())


def test_lease_expiry_fails_closed_before_recovery_and_stays_closed_after_reconnect(pipeline, tmp_path):
    journal = Journal()
    journal.append(pipeline["envelope"])

    async def scenario():
        async with journal.client() as client:
            intake = pipeline["enroll"](client)
            defense = pipeline["defense"](intake)
            path = tmp_path / "fixture.db"
            with defense.lab:
                plan = await defense.prepare(600)
                approval = defense.lab.operator.approve(plan, plan.digest)
                probe_all(defense.lab, "open", (0, 0, 0))
                await defense.execute(plan, plan.digest)
                probe_all(defense.lab, "restricted", (1, 1, 1))
                ((deadline,),) = read_rows(path, "SELECT deadline_ns FROM rollout")
                journal.available = False
                await asyncio.sleep(max(0, (deadline - time.monotonic_ns()) / 1e9) + 0.01)
                # No monitor or recovery command has run. Local expiry alone closes the routes.
                assert defense.gate.status_current()
                assert read_rows(path, "SELECT phase FROM rollout") == [("confirmed",)]
                probe_all(defense.lab, "quarantined", (1, 1, 1))
                assert await asyncio.to_thread(defense.lab.controller.rollback, "local expiry") == "safe_hold"
                probe_all(defense.lab, "quarantined", (2, 2, 2))

            journal.available = True
            resumed = pipeline["defense"](intake)
            with resumed.lab:
                with pytest.raises(Denied, match="invalid or expired local approval|lease inactive"):
                    await resumed.transition(resumed.lab.controller.restrict, plan, approval, "canary")
                assert read_rows(path, "SELECT phase FROM rollout") == [("safe_hold",)]
                assert restrictions(path) == list(REPLICAS)
                probe_all(resumed.lab, "quarantined", (2, 2, 2))

    asyncio.run(scenario())
