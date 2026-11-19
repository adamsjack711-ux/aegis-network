"""Coordinator event store and transactional outbox."""

import json

import psycopg

from .artifact import SignedEvent, event_id, event_payload


SCHEMA = """
CREATE TABLE IF NOT EXISTS mesh_events (
  event_id UUID PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('finding', 'revocation')),
  publisher_id TEXT NOT NULL,
  sequence BIGINT NOT NULL,
  envelope JSONB NOT NULL,
  UNIQUE (publisher_id, sequence)
);
CREATE TABLE IF NOT EXISTS mesh_outbox (
  event_id UUID PRIMARY KEY REFERENCES mesh_events(event_id),
  sent_at TIMESTAMPTZ
);
"""


class SequenceConflict(ValueError):
    """A publisher sequence has already been used for a different event."""


class PostgresRepository:
    def __init__(self, dsn: str):
        self.dsn = dsn
        with psycopg.connect(dsn) as db:
            db.execute(SCHEMA)
            # Carry unsent v1 findings forward when reusing a local lab volume.
            legacy = db.execute("SELECT to_regclass('public.findings')").fetchone()[0]
            if legacy is not None:
                db.execute(
                    "INSERT INTO mesh_events(event_id,kind,publisher_id,sequence,envelope) "
                    "SELECT artifact_id,'finding',publisher_id,sequence,envelope FROM findings "
                    "ON CONFLICT DO NOTHING"
                )
                db.execute(
                    "INSERT INTO mesh_outbox(event_id,sent_at) "
                    "SELECT artifact_id,sent_at FROM outbox ON CONFLICT DO NOTHING"
                )

    def add(self, envelope: SignedEvent) -> bool:
        payload = event_payload(envelope)
        eid = event_id(envelope)
        encoded = envelope.model_dump(mode="json")
        with psycopg.connect(self.dsn) as db:
            with db.transaction():
                inserted = db.execute(
                    "INSERT INTO mesh_events(event_id,kind,publisher_id,sequence,envelope) "
                    "VALUES(%s,%s,%s,%s,%s::jsonb) ON CONFLICT DO NOTHING RETURNING event_id",
                    (eid, envelope.kind, payload.publisher_id, payload.sequence, json.dumps(encoded)),
                ).fetchone()
                if inserted is None:
                    existing = db.execute(
                        "SELECT envelope FROM mesh_events WHERE event_id=%s", (eid,)
                    ).fetchone()
                    if existing is not None:
                        if existing[0] != encoded:
                            raise ValueError("event ID conflict")
                        return False
                    raise SequenceConflict("publisher sequence conflict")
                db.execute("INSERT INTO mesh_outbox(event_id) VALUES(%s)", (eid,))
                return True

    def pending(self, limit: int = 100) -> list[SignedEvent]:
        from .artifact import SignedFinding, SignedRevocation

        with psycopg.connect(self.dsn) as db:
            rows = db.execute(
                "SELECT e.kind,e.envelope FROM mesh_outbox o JOIN mesh_events e USING(event_id) "
                "WHERE o.sent_at IS NULL ORDER BY e.publisher_id,e.sequence LIMIT %s",
                (limit,),
            ).fetchall()
        return [
            (SignedFinding if kind == "finding" else SignedRevocation).model_validate(raw)
            for kind, raw in rows
        ]

    def mark_sent(self, eid: str) -> None:
        with psycopg.connect(self.dsn) as db:
            db.execute(
                "UPDATE mesh_outbox SET sent_at=now() WHERE event_id=%s AND sent_at IS NULL", (eid,)
            )
