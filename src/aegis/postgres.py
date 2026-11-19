"""Durable coordinator store and transactional outbox."""

import json

import psycopg

from .artifact import SignedFinding


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  artifact_id UUID PRIMARY KEY,
  publisher_id TEXT NOT NULL,
  sequence BIGINT NOT NULL,
  envelope JSONB NOT NULL,
  UNIQUE (publisher_id, sequence)
);
CREATE TABLE IF NOT EXISTS outbox (
  artifact_id UUID PRIMARY KEY REFERENCES findings(artifact_id),
  sent_at TIMESTAMPTZ
);
"""


class PostgresRepository:
    def __init__(self, dsn: str):
        self.dsn = dsn
        with psycopg.connect(dsn) as db:
            db.execute(SCHEMA)

    def add(self, envelope: SignedFinding) -> bool:
        finding = envelope.finding
        payload = envelope.model_dump_json()
        with psycopg.connect(self.dsn) as db:
            with db.transaction():
                row = db.execute(
                    "SELECT envelope FROM findings WHERE artifact_id=%s FOR UPDATE",
                    (finding.artifact_id,),
                ).fetchone()
                if row is not None:
                    if row[0] != json.loads(payload):
                        raise ValueError("artifact ID conflict")
                    return False
                db.execute(
                    "INSERT INTO findings(artifact_id,publisher_id,sequence,envelope) VALUES(%s,%s,%s,%s::jsonb)",
                    (finding.artifact_id, finding.publisher_id, finding.sequence, payload),
                )
                db.execute("INSERT INTO outbox(artifact_id) VALUES(%s)", (finding.artifact_id,))
                return True

    def pending(self, limit: int = 100) -> list[SignedFinding]:
        with psycopg.connect(self.dsn) as db:
            rows = db.execute(
                "SELECT f.envelope FROM outbox o JOIN findings f USING(artifact_id) "
                "WHERE o.sent_at IS NULL ORDER BY f.publisher_id,f.sequence LIMIT %s",
                (limit,),
            ).fetchall()
        return [SignedFinding.model_validate(row[0]) for row in rows]

    def mark_sent(self, artifact_id) -> None:
        with psycopg.connect(self.dsn) as db:
            db.execute("UPDATE outbox SET sent_at=now() WHERE artifact_id=%s AND sent_at IS NULL", (artifact_id,))
