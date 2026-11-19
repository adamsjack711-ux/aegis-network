"""Run Phase 2C dry-run entry points against independent wire and storage observations."""

import asyncio
import base64
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.agent_runtime import process_message
from aegis.artifact import parse_event
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.recovery import RecoveryBlocked, reconcile
from aegis.storage import SqliteAudit
from aegis.trust import PublisherGrant, TrustStore


VECTOR = json.loads((Path(__file__).with_name("fixtures") / "dry_run.json").read_text())
FINDING = VECTOR["finding"]
FINDING_ID = FINDING["artifact_id"]
WITHDRAWAL_ID = VECTOR["withdrawal"]["revocation_id"]
NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)
FINDER = Ed25519PrivateKey.from_private_bytes(bytes([21]) * 32)
REVOKER = Ed25519PrivateKey.from_private_bytes(bytes([22]) * 32)


def wire_bytes(body):
    # Independent Phase 2C encoding of the literal UTC wire vectors.
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def wire_event(kind, payload, private_key):
    signature = base64.b64encode(private_key.sign(wire_bytes(payload))).decode()
    return {"kind": kind, "key_id": "fixture-key", kind: payload, "signature": signature}


DIGEST = hashlib.sha256(wire_bytes(FINDING)).hexdigest()
FINDING_WIRE = wire_event("finding", FINDING, FINDER)
WITHDRAWAL_WIRE = wire_event("revocation", VECTOR["withdrawal"] | {
    "target_artifact_id": FINDING_ID, "target_sha256": DIGEST,
}, REVOKER)


def agent_for(audit, *, version="1.0.0", revoke_old_key=False):
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2090, 1, 1, tzinfo=timezone.utc)
    grants = [
        PublisherGrant("synthetic-finder", "fixture-key", FINDER.public_key(),
                       frozenset({"finding"}), start, end),
        PublisherGrant("synthetic-revoker", "fixture-key", REVOKER.public_key(),
                       frozenset({"revocation"}), start, end,
                       revoked_at=NOW if revoke_old_key else None,
                       revocation_publishers=frozenset({"synthetic-finder"})),
    ]
    return LocalAgent(
        LocalPolicy(TrustStore(grants), frozenset({"observe-only"}), True),
        [InventoryItem(FINDING["software"]["purl"], version)],
        audit,
    )


def read_rows(path, sql):
    # A separate read-only SQLite connection proves visibility outside the writer.
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as reader:
        return reader.execute(sql).fetchall()


def decisions(path):
    return read_rows(path, "SELECT artifact_id,digest,sequence,authenticated,outcome,dry_run "
                           "FROM decisions ORDER BY sequence")


def owner(path):
    return read_rows(path, "SELECT agent_id FROM agent_identity")


def test_wire_forgery_and_signed_conflict_keep_the_original_history(tmp_path):
    path = tmp_path / "wire.db"
    audit = SqliteAudit(path, agent_id="phase3d-a")
    with closing(audit.db):
        agent = agent_for(audit)
        assert decisions(path) == []
        tampered = FINDING | {"sequence": 99}
        forged = FINDING_WIRE | {"finding": tampered}
        agent.evaluate_event(parse_event(wire_bytes(forged)), NOW)
        assert decisions(path) == []
        agent.evaluate_event(parse_event(wire_bytes(FINDING_WIRE)), NOW)
        assert decisions(path) == [(FINDING_ID, DIGEST, 1, 1, "allow_dry_run", 1)]

        conflict = FINDING | {"sequence": 2, "vulnerability_id": "PHASE3D-OTHER-CLAIM"}
        collision = wire_event("finding", conflict, FINDER)
        agent.evaluate_event(parse_event(wire_bytes(collision)), NOW)
        agent.evaluate_event(parse_event(wire_bytes(FINDING_WIRE)), NOW)
        assert decisions(path) == [(FINDING_ID, DIGEST, 1, 1, "allow_dry_run", 1)]
        assert read_rows(path, "SELECT artifact_id,digest FROM rejected_events ORDER BY id") == [
            (FINDING_ID, hashlib.sha256(wire_bytes(tampered)).hexdigest()),
            (FINDING_ID, hashlib.sha256(wire_bytes(conflict)).hexdigest()),
        ]


class LocalLease:
    async def ensure(self):
        pass


def test_durable_withdrawal_survives_stale_replay_and_key_revocation(tmp_path):
    path = tmp_path / "withdrawal.db"

    async def replay(agent, audit, page, expected_after):
        def respond(request):
            assert request.url.path == "/v1/events"
            assert request.url.params["after"] == str(expected_after)
            return httpx.Response(200, json=page)

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(respond), base_url="http://phase3d.invalid",
        ) as client:
            await reconcile(agent, audit, client, LocalLease())

    def durable_state():
        return (
            read_rows(path, "SELECT position FROM recovery_cursor"),
            read_rows(path, "SELECT target_publisher_id,artifact_id,digest,revocation_id,"
                            "revoker_publisher_id FROM revoked_targets"),
            decisions(path),
        )

    expected_state = (
        [(2,)],
        [("synthetic-finder", FINDING_ID, DIGEST, WITHDRAWAL_ID, "synthetic-revoker")],
        [(FINDING_ID, DIGEST, 1, 1, "allow_dry_run", 1)],
    )
    audit = SqliteAudit(path, agent_id="phase3d-a")
    with closing(audit.db):
        asyncio.run(replay(agent_for(audit), audit, {"head": 2, "events": [
            {"position": 1, "envelope": FINDING_WIRE},
            {"position": 2, "envelope": WITHDRAWAL_WIRE},
        ]}, expected_after=0))
        assert durable_state() == expected_state

    audit = SqliteAudit(path, agent_id="phase3d-a")
    with closing(audit.db):
        restarted = agent_for(audit, revoke_old_key=True)
        with pytest.raises(RecoveryBlocked, match="gap or rollback"):
            asyncio.run(replay(restarted, audit, {"head": 1, "events": []}, expected_after=2))
        # Re-delivery reaches the effective-decision boundary under the new trust view.
        dry_run = restarted.evaluate_event(parse_event(wire_bytes(FINDING_WIRE)), NOW)
        assert dry_run.outcome == "deny" and dry_run.digest == DIGEST
        assert durable_state() == expected_state


def test_failed_ack_replay_keeps_per_agent_decisions_and_exact_inventory(tmp_path):
    first_path = tmp_path / "first.db"
    second_path = tmp_path / "second.db"
    ack_readbacks = []

    class Message:
        data = wire_bytes(FINDING_WIRE)

        def __init__(self, path, lose_ack=False):
            self.path = path
            self.lose_ack = lose_ack

        async def ack_sync(self):
            ack_readbacks.append((owner(self.path), decisions(self.path)))
            if self.lose_ack:
                raise TimeoutError("synthetic ack loss")

    def deliver(path, agent_id, *, version="1.0.0", lose_ack=False):
        audit = SqliteAudit(path, agent_id=agent_id)
        with closing(audit.db):
            asyncio.run(process_message(Message(path, lose_ack), agent_for(audit, version=version)))

    deliver(first_path, "phase3d-a", lose_ack=True)
    with pytest.raises(ValueError, match="different agent"):
        SqliteAudit(first_path, agent_id="phase3d-b")
    deliver(second_path, "phase3d-b", version="1.0.0+other")
    deliver(first_path, "phase3d-a")

    expected_first = [(FINDING_ID, DIGEST, 1, 1, "allow_dry_run", 1)]
    expected_second = [(FINDING_ID, DIGEST, 1, 1, "deny", 1)]
    assert ack_readbacks == [
        ([("phase3d-a",)], expected_first),
        ([("phase3d-b",)], expected_second),
        ([("phase3d-a",)], expected_first),
    ]
    assert decisions(first_path) == expected_first
    assert decisions(second_path) == expected_second
