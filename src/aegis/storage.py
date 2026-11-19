"""Test adapters and local SQLite audit. The agent owns its audit database."""

import sqlite3
import re
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
        self.events: list[SignedEvent] = []

    def publish(self, envelope: SignedEvent) -> None:
        self.events.append(envelope)


class SqliteAudit:
    def __init__(self, path: str | Path, agent_id: str = "test-agent"):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", agent_id):
            raise ValueError("invalid agent ID")
        self.agent_id = agent_id
        self.db = sqlite3.connect(str(path))
        self.db.execute("CREATE TABLE IF NOT EXISTS audit_identity (agent_id TEXT PRIMARY KEY)")
        existing_id = self.db.execute("SELECT agent_id FROM audit_identity").fetchone()
        if existing_id is not None and existing_id[0] != agent_id:
            self.db.close()
            raise ValueError("audit database belongs to a different agent")
        self.db.execute("""CREATE TABLE IF NOT EXISTS agent_identity (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1), agent_id TEXT NOT NULL
        )""")
        self.db.execute("INSERT OR IGNORE INTO agent_identity(singleton,agent_id) VALUES(1,?)", (agent_id,))
        bound_agent_id = self.db.execute("SELECT agent_id FROM agent_identity WHERE singleton=1").fetchone()[0]
        if bound_agent_id != agent_id:
            self.db.close()
            raise ValueError("audit database belongs to a different agent")
        if existing_id is None:
            self.db.execute("INSERT INTO audit_identity(agent_id) VALUES(?)", (agent_id,))
        self.db.execute("""CREATE TABLE IF NOT EXISTS decisions (
            artifact_id TEXT PRIMARY KEY, digest TEXT NOT NULL, publisher_id TEXT NOT NULL,
            sequence INTEGER NOT NULL, authenticated INTEGER NOT NULL,
            outcome TEXT NOT NULL, reason TEXT NOT NULL, reason_code TEXT NOT NULL,
            dry_run INTEGER NOT NULL,
            decided_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS rejected_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT NOT NULL,
            digest TEXT NOT NULL, publisher_id TEXT NOT NULL,
            reason TEXT NOT NULL, reason_code TEXT NOT NULL,
            decided_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS revocation_decisions (
            event_id TEXT PRIMARY KEY, target_artifact_id TEXT NOT NULL,
            target_digest TEXT NOT NULL, digest TEXT NOT NULL,
            publisher_id TEXT NOT NULL, sequence INTEGER NOT NULL,
            authenticated INTEGER NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            decided_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS revoked_artifacts (
            publisher_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
            digest TEXT NOT NULL, revocation_id TEXT NOT NULL,
            PRIMARY KEY (publisher_id, artifact_id, digest)
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS decision_overrides (
            artifact_id TEXT PRIMARY KEY REFERENCES decisions(artifact_id),
            digest TEXT NOT NULL, reason TEXT NOT NULL, reason_code TEXT NOT NULL,
            decided_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )""")
        for table in ("decisions", "rejected_events", "revocation_decisions"):
            columns = {row[1] for row in self.db.execute(f"PRAGMA table_info({table})")}
            if "reason_code" not in columns:
                self.db.execute(
                    f"ALTER TABLE {table} ADD COLUMN reason_code TEXT NOT NULL DEFAULT 'LEGACY_REASON'"
                )
        self.db.commit()

    def get(self, artifact_id: str) -> Decision | None:
        row = self.db.execute(
            "SELECT artifact_id,digest,publisher_id,outcome,reason,reason_code,dry_run "
            "FROM decisions WHERE artifact_id=?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            return None
        artifact_id, digest, publisher_id, outcome, reason, reason_code, dry_run = row
        if self.is_revoked(publisher_id, artifact_id, digest):
            outcome, reason, reason_code = "deny", "finding revoked", "FINDING_REVOKED"
        else:
            override = self.db.execute(
                "SELECT reason,reason_code FROM decision_overrides WHERE artifact_id=? AND digest=?",
                (artifact_id, digest),
            ).fetchone()
            if override is not None:
                outcome, (reason, reason_code) = "deny", override
        return Decision(artifact_id, digest, outcome, reason, reason_code=reason_code,
                        dry_run=bool(dry_run), event_id=artifact_id,
                        correlation_id=artifact_id, agent_id=self.agent_id)

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
                "INSERT INTO rejected_events(artifact_id,digest,publisher_id,reason,reason_code) VALUES(?,?,?,?,?)",
                (decision.artifact_id, decision.digest, publisher_id, decision.reason, decision.reason_code),
            )
            self.db.commit()
            return
        self.db.execute(
            "INSERT INTO decisions(artifact_id,digest,publisher_id,sequence,authenticated,outcome,reason,reason_code,dry_run) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (decision.artifact_id, decision.digest, publisher_id, sequence, int(authenticated),
             decision.outcome, decision.reason, decision.reason_code, int(decision.dry_run)),
        )
        self.db.commit()

    def record_override(self, decision: Decision) -> Decision:
        if decision.outcome != "deny" or not decision.dry_run:
            raise ValueError("only dry-run denial can override a decision")
        with self.db:
            row = self.db.execute(
                "SELECT digest FROM decisions WHERE artifact_id=?", (decision.artifact_id,)
            ).fetchone()
            if row is None or row[0] != decision.digest:
                raise ValueError("override target is not an audited finding")
            self.db.execute(
                "INSERT OR IGNORE INTO decision_overrides(artifact_id,digest,reason,reason_code) "
                "VALUES(?,?,?,?)",
                (decision.artifact_id, decision.digest, decision.reason, decision.reason_code),
            )
        return self.get(decision.artifact_id)

    def all_decisions(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT artifact_id,digest,publisher_id,sequence,authenticated,outcome,reason,reason_code,dry_run,decided_at "
            "FROM decisions ORDER BY rowid"
        ).fetchall()
        columns = ["artifact_id", "digest", "publisher_id", "sequence", "authenticated",
                   "outcome", "reason", "reason_code", "dry_run", "decided_at"]
        return [dict(zip(columns, row)) | {"agent_id": self.agent_id, "event_id": row[0], "correlation_id": row[0]} for row in rows]

    def rejected_events(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT artifact_id,digest,publisher_id,reason,reason_code,decided_at FROM rejected_events ORDER BY id"
        ).fetchall()
        return [dict(zip(["artifact_id", "digest", "publisher_id", "reason", "reason_code", "decided_at"], row)) for row in rows]

    def is_revoked(self, publisher_id: str, artifact_id: str, digest: str) -> bool:
        return self.db.execute(
            "SELECT 1 FROM revoked_artifacts WHERE artifact_id=? AND digest=?",
            (artifact_id, digest),
        ).fetchone() is not None

    def get_revocation(self, revocation_id: str) -> Decision | None:
        row = self.db.execute(
            "SELECT event_id,target_artifact_id,digest,outcome,reason,reason_code FROM revocation_decisions WHERE event_id=?",
            (revocation_id,),
        ).fetchone()
        if row is None:
            return None
        rid, target_id, digest, outcome, reason, reason_code = row
        return Decision(target_id, digest, outcome, reason, reason_code=reason_code,
                        event_id=rid, correlation_id=target_id, agent_id=self.agent_id)

    def record_revocation(self, publisher_id: str, sequence: int, decision: Decision,
                          target_id: str, target_digest: str, authenticated: bool) -> None:
        if not authenticated:
            self.db.execute(
                "INSERT INTO rejected_events(artifact_id,digest,publisher_id,reason,reason_code) VALUES(?,?,?,?,?)",
                (decision.event_id, decision.digest, publisher_id, decision.reason, decision.reason_code),
            )
            self.db.commit()
            return
        with self.db:
            self.db.execute(
                "INSERT INTO revocation_decisions(event_id,target_artifact_id,target_digest,digest,publisher_id,sequence,authenticated,outcome,reason,reason_code) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (decision.event_id, target_id, target_digest, decision.digest, publisher_id,
                 sequence, 1, decision.outcome, decision.reason, decision.reason_code),
            )
            if decision.outcome == "revoked_dry_run":
                self.db.execute(
                    "INSERT OR IGNORE INTO revoked_artifacts(publisher_id,artifact_id,digest,revocation_id) VALUES(?,?,?,?)",
                    (publisher_id, target_id, target_digest, decision.event_id),
                )
