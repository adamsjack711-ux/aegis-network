"""Faults at the trust, outbox, redelivery, and local audit boundaries."""

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aegis.agent_runtime import durable_name, process_message
from aegis.api import REVOCATION_SUBJECT, SUBJECT, app, dispatch_once
from aegis.artifact import (
    Evidence, Finding, Revocation, Software, canonical_bytes, sign, sign_revocation,
)
from aegis.config import load_publishers
from aegis.core import Coordinator, InventoryItem, LocalAgent, LocalPolicy
from aegis.storage import MemoryBus, MemoryRepository, SqliteAudit
from aegis.trust import PublisherGrant, TrustStore


def grant(publisher, key, roles, *, revoked_at=None, expires_at=None):
    return PublisherGrant(
        publisher, "key-1", key.public_key(), frozenset(roles),
        datetime(2020, 1, 1, tzinfo=timezone.utc),
        expires_at or datetime(2035, 1, 1, tzinfo=timezone.utc), revoked_at,
        frozenset({"finder"}) if publisher == "revoker" and "revocation" in roles else None,
    )


def finding(key, publisher="finder", sequence=1):
    now = datetime.now(timezone.utc)
    return sign(Finding(
        schema_version="1.0", artifact_id=uuid4(), publisher_id=publisher,
        sequence=sequence, issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1), vulnerability_id="AEGIS-LAB-1",
        software=Software(purl="pkg:generic/aegis-demo", affected_versions=["1.0.0"]),
        evidence=[Evidence(uri="urn:lab:evidence", sha256="a" * 64, method="lab-reproduction")],
        applicability="authorized-lab", mitigation_template="observe-only",
    ), key, "key-1")


def revocation(key, target, publisher="revoker", sequence=1):
    now = datetime.now(timezone.utc)
    return sign_revocation(Revocation(
        schema_version="1.1", revocation_id=uuid4(), publisher_id=publisher,
        sequence=sequence, issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        target_artifact_id=target.finding.artifact_id,
        target_sha256=hashlib.sha256(canonical_bytes(target.finding)).hexdigest(),
        target_publisher_id=target.finding.publisher_id,
        reason="invalid-evidence",
    ), key, "key-1")


def agent(tmp_path, trust, agent_id):
    audit = SqliteAudit(tmp_path / f"{agent_id}.db", agent_id=agent_id)
    local = LocalAgent(
        LocalPolicy(trust, frozenset({"observe-only"}), True),
        [InventoryItem("pkg:generic/aegis-demo", "1.0.0")], audit,
    )
    return local, audit


def test_independent_audits_redelivery_and_recovery(tmp_path):
    key = Ed25519PrivateKey.generate()
    trust = TrustStore([grant("finder", key, {"finding"})])
    event = finding(key)
    first, first_audit = agent(tmp_path, trust, "first")
    second, second_audit = agent(tmp_path, trust, "second")
    assert first.evaluate(event).outcome == "allow_dry_run"
    assert second.evaluate(event).outcome == "allow_dry_run"
    assert first.evaluate(event).outcome == "allow_dry_run"
    assert len(first_audit.all_decisions()) == len(second_audit.all_decisions()) == 1
    first_audit.db.close()
    restarted, restarted_audit = agent(tmp_path, trust, "first")
    assert restarted.evaluate(event).outcome == "allow_dry_run"
    assert len(restarted_audit.all_decisions()) == 1
    with pytest.raises(ValueError, match="different agent"):
        SqliteAudit(tmp_path / "first.db", agent_id="stolen")


def test_signed_revocation_before_and_after_finding(tmp_path):
    finder_key, revoker_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trust = TrustStore([
        grant("finder", finder_key, {"finding"}),
        grant("revoker", revoker_key, {"revocation"}),
    ])
    target = finding(finder_key)
    revoke = revocation(revoker_key, target)
    before, before_audit = agent(tmp_path, trust, "before")
    assert before.evaluate_event(revoke).outcome == "revoked_dry_run"
    assert before.evaluate(target).reason == "finding revoked"
    after, after_audit = agent(tmp_path, trust, "after")
    assert after.evaluate(target).outcome == "allow_dry_run"
    assert after.evaluate_event(revoke).outcome == "revoked_dry_run"
    assert after.evaluate(target).reason == "finding revoked"
    after_audit.db.close()
    recovered, _ = agent(tmp_path, trust, "after")
    assert recovered.evaluate(target).reason == "finding revoked"
    assert before_audit.high_water("finder") == 1
    assert before_audit.high_water("revoker") == 1


def test_revocation_requires_role_signature_and_live_key(tmp_path):
    finder_key, revoker_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    target = finding(finder_key)
    revoke = revocation(revoker_key, target)
    wrong_role, audit = agent(tmp_path, TrustStore([
        grant("finder", finder_key, {"finding"}), grant("revoker", revoker_key, {"finding"}),
    ]), "wrong-role")
    assert wrong_role.evaluate_event(revoke).reason == "publisher key lacks role"
    assert audit.high_water("revoker") == 0
    forged = revoke.model_copy(update={"signature": base64.b64encode(b"x" * 64).decode()})
    trusted, audit2 = agent(tmp_path, TrustStore([
        grant("finder", finder_key, {"finding"}), grant("revoker", revoker_key, {"revocation"}),
    ]), "trusted")
    assert trusted.evaluate_event(forged).reason == "invalid signature"
    assert audit2.high_water("revoker") == 0
    assert trusted.evaluate_event(revoke).outcome == "revoked_dry_run"
    expired, _ = agent(tmp_path, TrustStore([
        grant("finder", finder_key, {"finding"}),
        grant("revoker", revoker_key, {"revocation"}, revoked_at=datetime(2021, 1, 1, tzinfo=timezone.utc)),
    ]), "expired")
    assert expired.evaluate_event(revoke).reason == "publisher key revoked"


def test_config_grants_and_revocation_endpoint(tmp_path):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    path = tmp_path / "publishers.json"
    path.write_text(json.dumps({"grants": [{
        "publisher_id": "revoker", "key_id": "key-1",
        "public_key": base64.b64encode(public).decode(), "roles": ["revocation"],
        "revocation_publishers": ["finder"],
        "not_before": "2020-01-01T00:00:00+00:00",
        "expires_at": "2035-01-01T00:00:00+00:00", "revoked_at": None,
    }]}))
    trust = load_publishers(str(path))
    event = revocation(key, finding(Ed25519PrivateKey.generate()))
    bus = MemoryBus()
    app.state.coordinator = Coordinator(trust, MemoryRepository(), bus)
    client = TestClient(app)
    response = client.post("/v1/revocations", json=event.model_dump(mode="json"))
    assert response.status_code == 202
    assert response.json()["accepted"] is True
    assert client.post("/v1/revocations", json=event.model_dump(mode="json")).json()["accepted"] is False
    assert bus.events == [event]


def test_dispatch_retries_publish_and_mark_failures():
    event = finding(Ed25519PrivateKey.generate())
    class Repo:
        sent = False
        fail_mark = True
        def pending(self):
            return [] if self.sent else [event]
        def mark_sent(self, eid):
            if self.fail_mark:
                raise OSError("database unavailable after broker ack")
            self.sent = True

    class Bus:
        def __init__(self):
            self.calls = []
            self.fail_publish = True
        async def publish(self, subject, data, headers):
            if self.fail_publish:
                raise OSError("broker unavailable")
            self.calls.append((subject, data, headers))

    repo, bus = Repo(), Bus()
    with pytest.raises(OSError, match="broker"):
        asyncio.run(dispatch_once(repo, bus))
    assert not repo.sent and bus.calls == []
    bus.fail_publish = False
    with pytest.raises(OSError, match="database"):
        asyncio.run(dispatch_once(repo, bus))
    assert not repo.sent
    repo.fail_mark = False
    assert asyncio.run(dispatch_once(repo, bus)) == 1
    assert len(bus.calls) == 2
    assert all(call[0] == SUBJECT for call in bus.calls)
    assert bus.calls[0][2] == bus.calls[1][2] == {"Nats-Msg-Id": str(event.finding.artifact_id)}


def test_dispatch_routes_revocation_with_its_own_event_id():
    event = revocation(Ed25519PrivateKey.generate(), finding(Ed25519PrivateKey.generate()))
    class Repo:
        sent = None
        def pending(self):
            return [event]
        def mark_sent(self, eid):
            self.sent = eid
    class Bus:
        call = None
        async def publish(self, subject, data, headers):
            self.call = (subject, headers)
    repo, bus = Repo(), Bus()
    assert asyncio.run(dispatch_once(repo, bus)) == 1
    assert bus.call == (REVOCATION_SUBJECT, {"Nats-Msg-Id": str(event.revocation.revocation_id)})
    assert repo.sent == str(event.revocation.revocation_id)


def test_agent_acks_after_commit_and_terms_bad_payload(tmp_path):
    key = Ed25519PrivateKey.generate()
    local, audit = agent(tmp_path, TrustStore([grant("finder", key, {"finding"})]), "listener")
    class Message:
        def __init__(self, data):
            self.data, self.acked, self.terminated = data, False, False
        async def ack_sync(self):
            assert len(audit.all_decisions()) == 1
            self.acked = True
        async def term(self):
            self.terminated = True

    valid = Message(finding(key).model_dump_json().encode())
    asyncio.run(process_message(valid, local))
    assert valid.acked and not valid.terminated
    malformed = Message(b"[]")
    asyncio.run(process_message(malformed, local))
    assert malformed.terminated and not malformed.acked
    agent_id = "36e1c9d7-b513-4c24-86c5-8923909170ec"
    assert durable_name(agent_id) == f"aegis-{agent_id}"
    with pytest.raises(ValueError):
        durable_name("Agent.1")


def test_agent_retries_transient_audit_failure(tmp_path):
    key = Ed25519PrivateKey.generate()
    local, audit = agent(tmp_path, TrustStore([grant("finder", key, {"finding"})]), "retry")
    event = finding(key)
    class Message:
        def __init__(self):
            self.data = event.model_dump_json().encode()
            self.acked = self.terminated = False
        async def ack_sync(self):
            self.acked = True
        async def term(self):
            self.terminated = True
    original = audit.record
    def unavailable(*args):
        raise OSError("audit disk unavailable")
    audit.record = unavailable
    message = Message()
    asyncio.run(process_message(message, local))
    assert not message.acked and not message.terminated
    audit.record = original
    asyncio.run(process_message(message, local))
    assert message.acked and len(audit.all_decisions()) == 1
