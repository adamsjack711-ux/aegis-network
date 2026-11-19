"""Priority and recovery regression tests for the disposable Mesh profile."""

import asyncio
from contextlib import closing
from functools import partial
import select
import signal
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nats.js.errors import KeyNotFoundError

from aegis import identity
from aegis.agent_runtime import process_message
from aegis.api import dispatch_once
from aegis.artifact import event_id
from aegis.mesh import CRITICAL_SUBJECT
from aegis.recovery import reconcile
from aegis.trust import TrustStore
from test_mesh_reliability import agent, finding, grant, revocation
from test_phase2c_hardening import FakeKV


class Lease:
    async def ensure(self):
        pass


class Message:
    def __init__(self, event):
        self.data = event.model_dump_json().encode()
        self.acks = 0
        self.terms = 0

    async def ack_sync(self):
        self.acks += 1

    async def term(self):
        self.terms += 1


def test_critical_outbox_is_independent_of_blocked_findings(monkeypatch):
    class Repo:
        def __init__(self):
            self.sent = set()

        def pending(self, limit, *, kind):
            return [record for record in events[kind] if event_id(record) not in self.sent][:limit]

        def mark_sent(self, eid):
            self.sent.add(eid)

    async def exercise():
        stalled = asyncio.Event()
        resume = asyncio.Event()
        repo = Repo()

        class Broker:
            async def publish(self, subject, body, headers):
                if subject != CRITICAL_SUBJECT:
                    stalled.set()
                    await resume.wait()
                else:
                    assert headers["Nats-Msg-Id"] == event_id(critical)

        broker = Broker()
        bulk = asyncio.create_task(dispatch_once(repo, broker, kind="finding"))
        try:
            await stalled.wait()
            assert await asyncio.wait_for(dispatch_once(repo, broker, kind="revocation"), 1) == 1
            assert repo.sent == {event_id(critical)}
        finally:
            resume.set()
            await bulk

    # Key-free scaffolding at the dispatcher boundary. Signed-wire coverage is below.
    critical = FakeEnvelope("critical")
    events = {"finding": [FakeEnvelope(str(i)) for i in range(1000)], "revocation": [critical]}
    monkeypatch.setattr("aegis.api.event_id", lambda event: event.name)
    monkeypatch.setattr(__name__ + ".event_id", lambda event: event.name)
    asyncio.run(exercise())


class FakeEnvelope:
    def __init__(self, name):
        self.name = name

    def model_dump_json(self):
        return "{}"


def test_restart_between_broker_store_and_outbox_mark_retries_stable_id(monkeypatch):
    critical = FakeEnvelope("retry")
    monkeypatch.setattr("aegis.api.event_id", lambda event: event.name)
    marks = []
    repo = SimpleNamespace(pending=lambda limit, kind: [critical] if not marks else [],
                           mark_sent=marks.append)
    retained = set()
    attempts = []

    async def publish(subject, body, headers):
        assert subject == CRITICAL_SUBJECT
        identifier = headers["Nats-Msg-Id"]
        attempts.append(identifier)
        retained.add(identifier)
        if len(attempts) == 1:
            raise ConnectionError("broker stored the event before the connection was cut")

    async def exercise():
        broker = SimpleNamespace(publish=publish)
        with pytest.raises(ConnectionError):
            await dispatch_once(repo, broker, kind="revocation")
        assert not marks
        assert await dispatch_once(repo, broker, kind="revocation") == 1

    asyncio.run(exercise())
    assert attempts == ["retry", "retry"]
    assert retained == set(marks) == {"retry"}


def test_expired_session_cannot_recreate_its_identity_after_partition(monkeypatch):
    # No private key or credential. These bytes are inert FakeKV test markers.
    clock = 10.0
    monkeypatch.setattr(identity, "time", SimpleNamespace(monotonic=lambda: clock))
    kv = FakeKV()
    aid = str(uuid4())

    async def exercise():
        nonlocal clock
        revision = await kv.create(aid, b"old")
        old = identity.IdentityLease(kv, aid, b"old", revision, clock)
        await old.ensure()
        clock += identity.LEASE_TTL_SECONDS
        del kv.values[aid]  # Retained KV TTL expired during the outage.
        with pytest.raises(identity.IdentityLost, match="expired"):
            await old.ensure()
        new_revision = await kv.create(aid, b"new")
        current = identity.IdentityLease(kv, aid, b"new", new_revision, clock)
        await current.ensure()
        await old.release()
        assert (await kv.get(aid)).value == b"new"
        del kv.values[aid]  # An unexpectedly missing KV on broker replacement also holds.
        with pytest.raises(identity.IdentityLost, match="disappeared"):
            await current.ensure()
        with pytest.raises(KeyNotFoundError):
            await kv.get(aid)

    asyncio.run(exercise())


def same_publisher(tmp_path):
    key = Ed25519PrivateKey.generate()
    trust = TrustStore([grant("finder", key, {"finding", "revocation"})])
    rapid, audit = agent(tmp_path, trust, "phase4e")
    first = finding(key, sequence=1)
    second = finding(key, sequence=2)
    earlier = revocation(key, first, publisher="finder", sequence=3)
    later = revocation(key, first, publisher="finder", sequence=4)
    return rapid, audit, first, second, earlier, later


def test_priority_reorder_duplicate_and_scoped_denial_keep_ordered_watermark(tmp_path):
    rapid, audit, first, second, earlier, later = same_publisher(tmp_path)
    with closing(audit.db):
        assert rapid.evaluate(first).outcome == "allow_dry_run"

        async def exercise():
            for event in (later, earlier, later):
                message = Message(event)
                await process_message(message, rapid, lease=Lease(), critical=True)
                assert message.acks == 1
            assert audit.high_water("finder") == 1
            assert audit.journal_position() == 0
            assert audit.sequence_owner("finder", 4) == event_id(later)
            assert audit.get(event_id(first)).reason_code == "FINDING_REVOKED"
            assert rapid.evaluate(second).outcome == "allow_dry_run"
            for envelope in (earlier, later):
                assert rapid.evaluate_event(envelope).outcome == "revoked_dry_run"
            assert audit.high_water("finder") == 4
            assert audit.db.execute("SELECT count(*) FROM revocation_decisions").fetchone()[0] == 2

        asyncio.run(exercise())


def test_critical_projection_can_repair_without_advancing_canonical_cursor(tmp_path):
    rapid, audit, first, _, earlier, later = same_publisher(tmp_path)
    ordinary = {"position": 7, "envelope": first.model_dump(mode="json")}
    withdrawals = [{"position": n, "envelope": event.model_dump(mode="json")}
                   for n, event in ((1008, earlier), (1011, later))]

    def respond(request):
        assert request.url.path == "/v1/revocations"
        after = int(request.url.params["after"])
        return httpx.Response(200, json={"head": 1011,
                                        "events": [row for row in withdrawals if row["position"] > after][:1]})

    async def exercise():
        async with httpx.AsyncClient(base_url="http://test.invalid",
                                     transport=httpx.MockTransport(respond)) as client:
            repair = partial(reconcile, rapid, audit, client, Lease(), page_size=1, critical=True)
            assert await repair() == 1
            assert audit.journal_position(critical=True) == 1008
            assert await repair() == 1
            assert audit.journal_position(critical=True) == 1011
            assert await repair() == 0
        assert audit.journal_position() == 0
        assert audit.high_water("finder") == 0
        assert rapid.evaluate(first).reason_code == "FINDING_REVOKED"
        assert audit.observe_withdrawal("finder", event_id(first), earlier.revocation.target_sha256)
        canonical = [ordinary, *withdrawals]

        def sorted_replay(request):
            after = int(request.url.params["after"])
            return httpx.Response(200, json={"head": 1011, "events": [r for r in canonical if r["position"] > after]})

        async with httpx.AsyncClient(base_url="http://test.invalid",
                                     transport=httpx.MockTransport(sorted_replay)) as client:
            assert await reconcile(rapid, audit, client, Lease()) == 3
        assert audit.journal_position() == audit.journal_position(critical=True) == 1011
        assert audit.high_water("finder") == 4

    with closing(audit.db):
        asyncio.run(exercise())


@pytest.mark.parametrize("fence_loss", ["before-audit", "after-audit"])
def test_withdrawal_ack_requires_live_lease_and_recovery_is_idempotent(tmp_path, fence_loss):
    rapid, audit, first, _, earlier, _ = same_publisher(tmp_path)
    evidence = earlier.revocation.target_sha256

    class Fence:
        checks = 0

        async def ensure(self):
            self.checks += 1
            if self.checks == (1 if fence_loss == "before-audit" else 2):
                raise identity.IdentityLost("partition or takeover")

    async def exercise():
        assert rapid.evaluate(first).outcome == "allow_dry_run"
        attempted = Message(earlier)
        with pytest.raises(identity.IdentityLost):
            await process_message(attempted, rapid, lease=Fence(), critical=True)
        assert attempted.acks == 0
        assert audit.observe_withdrawal("finder", event_id(first), evidence) == (fence_loss == "after-audit")
        audit.db.close()
        restarted, recovered = agent(tmp_path, rapid.trust, "phase4e")
        with closing(recovered.db):
            retried = Message(earlier)
            await process_message(retried, restarted, lease=Lease(), critical=True)
            assert retried.acks == 1
            assert recovered.get(event_id(first)).reason_code == "FINDING_REVOKED"
            assert recovered.db.execute("SELECT count(*) FROM revocation_decisions").fetchone()[0] == 1

    asyncio.run(exercise())



@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="requires POSIX SIGKILL")
def test_sigkill_inside_revocation_transaction_keeps_both_audit_rows_atomic(tmp_path):
    rapid, audit, first, _, withdrawal, _ = same_publisher(tmp_path)
    rev = withdrawal.revocation
    path = audit.path
    with closing(audit.db):
        assert rapid.evaluate(first).outcome == "allow_dry_run"

    # Use a TEMP trigger in the disposable child to stop after both writes
    # have reached SQLite, while the enclosing context still owns the commit.
    child_code = """
import signal
import sys
from aegis.core import Decision
from aegis.storage import SqliteAudit

path, eid, aid, digest = sys.argv[1:]
audit = SqliteAudit(path, "phase4e")

def at_barrier():
    print("before-commit", flush=True)
    signal.pause()

audit.db.create_function("at_barrier", 0, at_barrier)
audit.db.execute(
    "CREATE TEMP TRIGGER before_commit AFTER INSERT ON revoked_targets "
    "BEGIN SELECT at_barrier(); END"
)
decision = Decision(aid, digest, "revoked_dry_run", "withdrawn",
                    reason_code="REVOCATION_ACCEPTED", event_id=eid)
audit.record_revocation("finder", 3, decision, aid, digest, "finder", True, ordered=False)
"""
    with subprocess.Popen(
        [sys.executable, "-c", child_code, path, event_id(withdrawal), event_id(first), rev.target_sha256],
        stdout=subprocess.PIPE,
    ) as child:
        try:
            assert select.select([child.stdout], [], [], 5)[0]
            assert child.stdout.readline() == b"before-commit\n"
        finally:
            child.kill()
            assert child.wait(timeout=5) == -signal.SIGKILL

    restarted, recovered = agent(tmp_path, rapid.trust, "phase4e")
    with closing(recovered.db):
        assert recovered.get_revocation(event_id(withdrawal)) is None
        assert recovered.get(event_id(first)).outcome == "allow_dry_run"
        assert restarted.evaluate_revocation(withdrawal, ordered=False).outcome == "revoked_dry_run"
        assert recovered.observe_withdrawal("finder", event_id(first), rev.target_sha256)
        assert recovered.db.execute("SELECT count(*) FROM revocation_decisions").fetchone()[0] == 1
