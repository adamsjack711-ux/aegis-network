"""Test adapters and local SQLite audit. The agent owns its audit database."""

import sqlite3
from pathlib import Path

from .artifact import SignedEvent, event_id, event_payload
from .core import Decision


class MemoryRepository:
    def __init__(self):
        self.items: dict[str, SignedEvent] = {}
        self.sequences: set[tuple[str, int]] = set()

    def add(self, envelope: SignedEvent) -> bool:
        payload = event_payload(envelope)
        artifact_id = event_id(envelope)
        if artifact_id in self.items:
            if self.items[artifact_id] != envelope:
                raise ValueError("artifact ID conflict")
            return False
        sequence = (payload.publisher_id, payload.sequence)
        if sequence in self.sequences:
            raise ValueError("publisher sequence conflict")
        self.items[artifact_id] = envelope
        self.sequences.add(sequence)
        return True


class MemoryBus:
    def __init__(self):
        self.events: list[SignedFinding] = []

    def publish(self, envelope: SignedEvent) -> None:
        self.events.append(envelope)


class SqliteAudit:
    def __init__(self, path: str | Path, agent_id: str = "test-agent"):
        self.agent_id = agent_id
        self.db = sqlite3.connect(str(path))
        self.db.execute("""CREATE TABLE IF NOT EXISTS decisions (
            artifact_id TEXT PRIMARY KEY, digest TEXT NOT NULL, publisher_id TEXT NOT NULL,
            sequence INTEGER NOT NULL, authenticated INTEGER NOT NULL,
            outcome TEXT NOT NULL, reason TEXT NOT NULL, dry_run INTEGER NOT NULL,
            decided_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS rejected_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT NOT NULL,
            digest TEXT NOT NULL, publisher_id TEXT NOT NULL,
            reason TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS revocation_decisions (
            event_id TEXT PRIMARY KEY, target_artifact_id TEXT NOT NULL,
            target_digest TEXT NOT NULL, digest TEXT NOT NULL,
            publisher_id TEXT NOT NULL, sequence INTEGER NOT NULL,
            authenticated INTEGER NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL,
            decided_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS revoked_artifacts (
            publisher_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
            digest TEXT NOT NULL, revocation_id TEXT NOT NULL,
            PRIMARY KEY (publisher_id, artifact_id, digest)
        )""")
        self.db.commit()

    def get(self, artifact_id: str) -> Decision | None:
        row = self.db.execute(
            "SELECT artifact_id,digest,outcome,reason,dry_run FROM decisions WHERE artifact_id=?",
            (artifact_id,),
        ).fetchone()
        return Decision(*row, event_id=artifact_id, correlation_id=artifact_id, agent_id=self.agent_id) if row else None

    def high_water(self, publisher_id: str) -> int:
        row = self.db.execute(
            "SELECT MAX(value) FROM ("
            "SELECT COALESCE(MAX(sequence),0) AS value FROM decisions WHERE publisher_id=? AND authenticated=1 "
            "UNION ALL SELECT COALESCE(MAX(sequence),0) FROM revocation_decisions WHERE publisher_id=? AND authenticated=1)",
            (publisher_id, publisher_id),
        ).fetchone()
        return row[0]

    def record(self, publisher_id: str, sequence: int, decision: Decision, authenticated: bool) -> None:
        if not authenticated:
            self.db.execute(
                "INSERT INTO rejected_events(artifact_id,digest,publisher_id,reason) VALUES(?,?,?,?)",
                (decision.artifact_id, decision.digest, publisher_id, decision.reason),
            )
            self.db.commit()
            return
        self.db.execute(
            "INSERT INTO decisions(artifact_id,digest,publisher_id,sequence,authenticated,outcome,reason,dry_run) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (decision.artifact_id, decision.digest, publisher_id, sequence, int(authenticated),
             decision.outcome, decision.reason, int(decision.dry_run)),
        )
        self.db.commit()

    def all_decisions(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT artifact_id,digest,publisher_id,sequence,authenticated,outcome,reason,dry_run,decided_at "
            "FROM decisions ORDER BY rowid"
        ).fetchall()
        columns = ["artifact_id", "digest", "publisher_id", "sequence", "authenticated",
                   "outcome", "reason", "dry_run", "decided_at"]
        return [dict(zip(columns, row)) | {"agent_id": self.agent_id, "event_id": row[0], "correlation_id": row[0]} for row in rows]

    def rejected_events(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT artifact_id,digest,publisher_id,reason,decided_at FROM rejected_events ORDER BY id"
        ).fetchall()
        return [dict(zip(["artifact_id", "digest", "publisher_id", "reason", "decided_at"], row)) for row in rows]

    def is_revoked(self, publisher_id: str, artifact_id: str, digest: str) -> bool:
        return self.db.execute(
            "SELECT 1 FROM revoked_artifacts WHERE publisher_id=? AND artifact_id=? AND digest=?",
            (publisher_id, artifact_id, digest),
        ).fetchone() is not None

    def get_revocation(self, revocation_id: str) -> Decision | None:
        row = self.db.execute(
            "SELECT event_id,target_artifact_id,digest,outcome,reason FROM revocation_decisions WHERE event_id=?",
            (revocation_id,),
        ).fetchone()
        if row is None:
            return None
        rid, target_id, digest, outcome, reason = row
        return Decision(target_id, digest, outcome, reason, event_id=rid, correlation_id=target_id, agent_id=self.agent_id)

    def record_revocation(self, publisher_id: str, sequence: int, decision: Decision,
                          target_id: str, target_digest: str, authenticated: bool) -> None:
        if not authenticated:
            self.db.execute(
                "INSERT INTO rejected_events(artifact_id,digest,publisher_id,reason) VALUES(?,?,?,?)",
                (decision.event_id, decision.digest, publisher_id, decision.reason),
            )
            self.db.commit()
            return
        with self.db:
            self.db.execute(
                "INSERT INTO revocation_decisions(event_id,target_artifact_id,target_digest,digest,publisher_id,sequence,authenticated,outcome,reason) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (decision.event_id, target_id, target_digest, decision.digest, publisher_id,
                 sequence, 1, decision.outcome, decision.reason),
            )
            if decision.outcome == "revoked_dry_run":
                self.db.execute(
                    "INSERT OR IGNORE INTO revoked_artifacts(publisher_id,artifact_id,digest,revocation_id) VALUES(?,?,?,?)",
                    (publisher_id, target_id, target_digest, decision.event_id),
                )
