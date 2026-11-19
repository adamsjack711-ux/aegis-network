"""Adversarial identity, trust, ordering, replay, and dead-letter boundaries."""

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nats.js.errors import BucketNotFoundError, KeyNotFoundError, KeyWrongLastSequenceError

from aegis.agent_runtime import dead_letter, durable_name, process_message
from aegis.artifact import (
    Evidence, Finding, Revocation, Software, canonical_bytes, sign, sign_revocation,
)
from aegis.core import Coordinator, InventoryItem, LocalAgent, LocalPolicy
from aegis.identity import IdentityInUse, IdentityLease, IdentityLost
from aegis.recovery import RecoveryBlocked, reconcile
from aegis.storage import MemoryBus, MemoryRepository, SqliteAudit
from aegis.trust import PublisherGrant, TrustStore


NOW = datetime.now(timezone.utc)


def grant(publisher, key, roles, scope=None):
    return PublisherGrant(
        publisher, "default", key.public_key(), frozenset(roles),
        NOW - timedelta(days=1), NOW + timedelta(days=30),
        revocation_publishers=frozenset(scope) if scope is not None else None,
    )


def finding(key, publisher="finder", sequence=1, artifact_id=None):
    return sign(Finding(
        schema_version="1.0", artifact_id=artifact_id or uuid4(), publisher_id=publisher,
        sequence=sequence, issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1), vulnerability_id="SYNTHETIC",
        software=Software(purl="pkg:generic/aegis-demo", affected_versions=["1.0.0"]),
        evidence=[Evidence(uri="urn:synthetic", sha256="a" * 64, method="lab-reproduction")],
        applicability="authorized-lab", mitigation_template="observe-only",
    ), key, "default")


def revocation(key, target, sequence=1, publisher="revoker", *, version="1.1",
               target_publisher=None):
    return sign_revocation(Revocation(
        schema_version=version, revocation_id=uuid4(), publisher_id=publisher,
        sequence=sequence, issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=1),
        target_artifact_id=target.finding.artifact_id,
        target_sha256=hashlib.sha256(canonical_bytes(target.finding)).hexdigest(),
        target_publisher_id=(target.finding.publisher_id if target_publisher is None else target_publisher)
        if version == "1.1" else None,
        reason="withdrawn",
    ), key, "default")


def local(tmp_path, trust, name="agent-a"):
    audit = SqliteAudit(tmp_path / f"{name}.db", agent_id=name)
    agent = LocalAgent(LocalPolicy(trust, frozenset({"observe-only"}), True),
                       [InventoryItem("pkg:generic/aegis-demo", "1.0.0")], audit)
    return agent, audit


def test_scoped_revoker_cannot_withdraw_another_publisher_or_use_v1(tmp_path):
    finder_key, other_key, revoker_key = (Ed25519PrivateKey.generate() for _ in range(3))
    trust = TrustStore([
        grant("finder", finder_key, {"finding"}),
        grant("other", other_key, {"finding"}),
        grant("revoker", revoker_key, {"revocation"}, {"finder"}),
    ])
    agent, audit = local(tmp_path, trust)
    other = finding(other_key, "other")
    denied = agent.evaluate_revocation(revocation(revoker_key, other), NOW)
    assert (denied.outcome, denied.reason_code) == ("deny", "REVOCATION_SCOPE_DENIED")
    assert audit.high_water("revoker") == 0
    assert agent.evaluate(other, NOW).outcome == "allow_dry_run"
    assert audit.db.execute("SELECT COUNT(*) FROM revoked_targets").fetchone()[0] == 0

    coordinator = Coordinator(trust, MemoryRepository(), MemoryBus())
    with pytest.raises(ValueError, match="scope"):
        coordinator.revoke(revocation(revoker_key, other), NOW)
    legacy = revocation(revoker_key, finding(finder_key), version="1.0")
    assert agent.evaluate_revocation(legacy, NOW).reason_code == "REVOCATION_SCOPE_UNBOUND"
    with pytest.raises(ValueError, match="target publisher"):
        coordinator.revoke(legacy, NOW)


def test_invalid_revocation_scopes_and_ambiguous_audit_identity_fail_closed(tmp_path):
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="scope"):
        grant("revoker", key, {"revocation"}, {"*"})
    with pytest.raises(ValueError, match="requires revocation role"):
        grant("finder", key, {"finding"}, {"other"})
    path = tmp_path / "ambiguous.db"
    audit = SqliteAudit(path, agent_id="agent-a")
    audit.db.execute("INSERT INTO audit_identity(agent_id) VALUES('agent-b')")
    audit.db.commit()
    audit.db.close()
    with pytest.raises(ValueError, match="different agent"):
        SqliteAudit(path, agent_id="agent-a")


def test_late_signed_revocation_wins_and_sequence_collision_fails_closed(tmp_path):
    finder_key, revoker_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trust = TrustStore([grant("finder", finder_key, {"finding"}),
                        grant("revoker", revoker_key, {"revocation"}, {"finder"})])
    agent, audit = local(tmp_path, trust)
    target = finding(finder_key, sequence=1)
    assert agent.evaluate(target, NOW).outcome == "allow_dry_run"
    newer = revocation(revoker_key, finding(finder_key, sequence=2), sequence=100)
    assert agent.evaluate_revocation(newer, NOW).reason_code == "REVOCATION_ACCEPTED"
    late = revocation(revoker_key, target, sequence=1)
    assert agent.evaluate_revocation(late, NOW).reason_code == "REVOCATION_ACCEPTED"
    repository = MemoryRepository()
    assert repository.add(newer)
    assert repository.add(late)
    assert audit.get(str(target.finding.artifact_id)).reason_code == "FINDING_REVOKED"
    conflicting = revocation(revoker_key, target, sequence=1)
    assert agent.evaluate_revocation(conflicting, NOW).reason_code == "PUBLISHER_SEQUENCE_CONFLICT"
    assert audit.db.execute("SELECT COUNT(*) FROM revoked_targets").fetchone()[0] == 2
    assert agent.evaluate_revocation(late, NOW).reason_code == "REVOCATION_ACCEPTED"


def test_out_of_order_finding_and_replay_never_promote_old_decision(tmp_path):
    key = Ed25519PrivateKey.generate()
    trust = TrustStore([grant("finder", key, {"finding"})])
    agent, audit = local(tmp_path, trust)
    newer = finding(key, sequence=10)
    older = finding(key, sequence=9)
    assert agent.evaluate(newer, NOW).reason_code == "EXACT_MATCH_ALLOWED"
    assert agent.evaluate(older, NOW).reason_code == "STALE_SEQUENCE"
    assert agent.evaluate(older, NOW).reason_code == "STALE_SEQUENCE"
    collision = finding(key, sequence=10)
    assert agent.evaluate(collision, NOW).reason_code == "PUBLISHER_SEQUENCE_CONFLICT"
    assert len(audit.all_decisions()) == 2
    assert audit.high_water("finder") == 10
    repo = MemoryRepository()
    assert repo.add(newer)
    with pytest.raises(ValueError, match="not increasing"):
        repo.add(older)


class FakeKV:
    def __init__(self):
        self.values = {}
        self.revision = 0

    async def create(self, key, value):
        if key in self.values:
            raise KeyWrongLastSequenceError()
        self.revision += 1
        self.values[key] = (value, self.revision)
        return self.revision

    async def update(self, key, value, last):
        if key not in self.values:
            raise KeyNotFoundError()
        if self.values[key][1] != last:
            raise KeyWrongLastSequenceError()
        self.revision += 1
        self.values[key] = (value, self.revision)
        return self.revision

    async def get(self, key):
        if key not in self.values:
            raise KeyNotFoundError()
        value, revision = self.values[key]
        return SimpleNamespace(value=value, revision=revision)

    async def delete(self, key, last):
        if self.values[key][1] != last:
            raise KeyWrongLastSequenceError()
        del self.values[key]


class FakeJS:
    def __init__(self):
        self.kv = FakeKV()

    async def key_value(self, bucket):
        return self.kv


def test_uuid_identity_and_broker_lease_reject_duplicate_and_takeover():
    agent_id = str(uuid4())
    assert durable_name(agent_id) == f"aegis-{agent_id}"
    for invalid in ("agent-a", str(uuid4()).upper(), "00000000-0000-0000-0000-000000000001"):
        with pytest.raises(ValueError):
            durable_name(invalid)

    async def scenario():
        js = FakeJS()
        first = await IdentityLease.claim(js, agent_id)
        with pytest.raises(IdentityInUse):
            await IdentityLease.claim(js, agent_id)
        await first.ensure()
        js.kv.values[agent_id] = (b"attacker", first.revision + 1)
        with pytest.raises(IdentityLost):
            await first.ensure()
        assert first.lost
        await first.release()
        assert js.kv.values[agent_id][0] == b"attacker"
    asyncio.run(scenario())


def test_replay_recovers_missing_revocation_after_stream_retention(tmp_path):
    finder_key, revoker_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trust = TrustStore([grant("finder", finder_key, {"finding"}),
                        grant("revoker", revoker_key, {"revocation"}, {"finder"})])
    agent, audit = local(tmp_path, trust)
    target = finding(finder_key)
    revoke = revocation(revoker_key, target)
    expired_payload = revoke.revocation.model_copy(update={
        "issued_at": NOW - timedelta(hours=2), "expires_at": NOW - timedelta(hours=1),
    })
    revoke = sign_revocation(expired_payload, revoker_key, "default")
    pages = [
        {"head": 2, "events": [{"position": 1, "envelope": target.model_dump(mode="json")},
                                {"position": 2, "envelope": revoke.model_dump(mode="json")}]},
        {"head": 2, "events": []},
    ]
    async def scenario():
        def respond(request):
            return httpx.Response(200, json=pages.pop(0))
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond),
                                     base_url="http://lab.invalid") as client:
            lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
            assert await reconcile(agent, audit, client, lease) == 2
    asyncio.run(scenario())
    assert audit.journal_position() == 2
    assert audit.get(str(target.finding.artifact_id)).reason_code == "FINDING_REVOKED"
    assert len(audit.all_decisions()) == 1


def test_replay_gap_and_invalid_revocation_keep_cursor_blocked(tmp_path):
    key = Ed25519PrivateKey.generate()
    trust = TrustStore([grant("finder", key, {"finding"})])
    agent, audit = local(tmp_path, trust)
    async def scenario(payload):
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=payload)), base_url="http://lab.invalid") as client:
            with pytest.raises(RecoveryBlocked):
                await reconcile(agent, audit, client, SimpleNamespace(ensure=lambda: asyncio.sleep(0)))
    asyncio.run(scenario({"head": 1, "events": []}))
    assert audit.journal_position() == 0
    bad = {"head": 1, "events": [{"position": 1, "envelope": {"kind": "revocation"}}]}
    asyncio.run(scenario(bad))
    assert audit.journal_position() == 0
    async def invalid_json():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text="{")), base_url="http://lab.invalid") as client:
            with pytest.raises(RecoveryBlocked, match="JSON"):
                await reconcile(agent, audit, client, SimpleNamespace(ensure=lambda: asyncio.sleep(0)))
    asyncio.run(invalid_json())
    assert audit.journal_position() == 0


def test_dead_letter_must_publish_before_termination(tmp_path):
    key = Ed25519PrivateKey.generate()
    agent, _ = local(tmp_path, TrustStore([grant("finder", key, {"finding"})]))
    class Bus:
        def __init__(self):
            self.fail = True
            self.records = []
        async def publish(self, subject, data, headers):
            if self.fail:
                raise OSError("dead-letter unavailable")
            self.records.append((subject, json.loads(data), headers))
    class Message:
        data = b"[]"
        subject = "aegis.findings.v1"
        metadata = SimpleNamespace(num_delivered=3, sequence=SimpleNamespace(stream=7))
        terminated = False
        async def term(self):
            self.terminated = True
        async def ack_sync(self):
            raise AssertionError("must never acknowledge malformed input")
    async def scenario():
        bus, message = Bus(), Message()
        await process_message(message, agent, bus)
        assert not message.terminated
        bus.fail = False
        await process_message(message, agent, bus)
        assert message.terminated and len(bus.records) == 1
        assert base64.b64decode(bus.records[0][1]["body_base64"]) == b"[]"
    asyncio.run(scenario())


def test_exhausted_audit_failure_moves_to_dead_letter_without_ack(tmp_path):
    key = Ed25519PrivateKey.generate()
    agent, audit = local(tmp_path, TrustStore([grant("finder", key, {"finding"})]))
    event = finding(key)
    def unavailable(*args):
        raise OSError("audit disk unavailable")
    audit.record = unavailable
    class Bus:
        records = []
        async def publish(self, subject, data, headers):
            self.records.append(json.loads(data))
    class Message:
        data = event.model_dump_json().encode()
        subject = "aegis.findings.v1"
        metadata = SimpleNamespace(num_delivered=5, sequence=SimpleNamespace(stream=8))
        terminated = False
        async def term(self):
            self.terminated = True
        async def ack_sync(self):
            raise AssertionError("audit failed")
    async def scenario():
        bus, message = Bus(), Message()
        await process_message(message, agent, bus)
        assert message.terminated and bus.records[0]["reason"] == "OSError"
        assert audit.high_water("finder") == 0
    asyncio.run(scenario())


def test_failed_revocation_audit_is_dead_lettered_but_never_terminated(tmp_path):
    finder_key, revoker_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trust = TrustStore([grant("finder", finder_key, {"finding"}),
                        grant("revoker", revoker_key, {"revocation"}, {"finder"})])
    agent, audit = local(tmp_path, trust)
    target = finding(finder_key)
    assert agent.evaluate(target, NOW).outcome == "allow_dry_run"
    event = revocation(revoker_key, target)
    original_record = audit.record_revocation
    def unavailable(*args):
        raise OSError("audit disk unavailable")
    audit.record_revocation = unavailable
    class Bus:
        records = []
        async def publish(self, subject, data, headers):
            self.records.append(json.loads(data))
    class Message:
        data = event.model_dump_json().encode()
        subject = "aegis.revocations.v1"
        metadata = SimpleNamespace(num_delivered=5, sequence=SimpleNamespace(stream=9))
        terminated = False
        async def term(self):
            self.terminated = True
        async def ack_sync(self):
            raise AssertionError("revocation was not audited")
    async def scenario():
        bus, message = Bus(), Message()
        await process_message(message, agent, bus)
        assert not message.terminated and len(bus.records) == 1
        audit.record_revocation = original_record
        await process_message(message, agent, bus)
        assert audit.get(str(target.finding.artifact_id)).reason_code == "FINDING_REVOKED"
        def conflict_error(*args):
            raise ValueError("audit conflict")
        audit.record_revocation = conflict_error
        conflict = Message()
        conflict.data = revocation(revoker_key, target, sequence=2).model_dump_json().encode()
        await process_message(conflict, agent, bus)
        assert not conflict.terminated
    asyncio.run(scenario())
