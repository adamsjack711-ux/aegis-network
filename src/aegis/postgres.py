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
CREATE TABLE IF NOT EXISTS mesh_journal (
  position BIGSERIAL PRIMARY KEY,
  event_id UUID NOT NULL UNIQUE REFERENCES mesh_events(event_id)
);
"""


class SequenceConflict(ValueError):
    """A publisher sequence has already been used for a different event."""


JOURNAL_LOCK = 4611686018427387904


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
            # Positions must become visible in commit order. Otherwise a
            # concurrent transaction could commit a higher cursor first.
            db.execute("SELECT pg_advisory_xact_lock(%s)", (JOURNAL_LOCK,))
            db.execute(
                "INSERT INTO mesh_journal(event_id) "
                "SELECT event_id FROM mesh_events ORDER BY publisher_id,sequence,event_id "
                "ON CONFLICT DO NOTHING"
            )

    def add(self, envelope: SignedEvent) -> bool:
        payload = event_payload(envelope)
        eid = event_id(envelope)
        encoded = envelope.model_dump(mode="json")
        with psycopg.connect(self.dsn) as db:
            with db.transaction():
                # Serializes this publisher across concurrent coordinators.
                db.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (payload.publisher_id,))
                existing = db.execute(
                    "SELECT envelope FROM mesh_events WHERE event_id=%s", (eid,)
                ).fetchone()
                if existing is not None:
                    if existing[0] != encoded:
                        raise ValueError("event ID conflict")
                    return False
                latest = db.execute(
                    "SELECT MAX(sequence) FROM mesh_events WHERE publisher_id=%s",
                    (payload.publisher_id,),
                ).fetchone()[0]
                if envelope.kind == "finding" and latest is not None and payload.sequence <= latest:
                    raise SequenceConflict("publisher sequence is not increasing")
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
                db.execute("SELECT pg_advisory_xact_lock(%s)", (JOURNAL_LOCK,))
                db.execute("INSERT INTO mesh_journal(event_id) VALUES(%s)", (eid,))
                db.execute("INSERT INTO mesh_outbox(event_id) VALUES(%s)", (eid,))
                return True

    def events_after(self, position: int, limit: int = 100) -> tuple[list[dict], int]:
        if position < 0 or not 1 <= limit <= 100:
            raise ValueError("invalid journal range")
        with psycopg.connect(self.dsn) as db:
            head = db.execute("SELECT COALESCE(MAX(position),0) FROM mesh_journal").fetchone()[0]
            rows = db.execute(
                "SELECT j.position,e.envelope FROM mesh_journal j "
                "JOIN mesh_events e USING(event_id) WHERE j.position>%s AND j.position<=%s "
                "ORDER BY j.position LIMIT %s",
                (position, head, limit),
            ).fetchall()
        return [{"position": item, "envelope": envelope} for item, envelope in rows], head

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
