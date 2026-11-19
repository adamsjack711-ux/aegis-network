"""Coordinator event store and transactional outbox."""

import json

import psycopg

from .artifact import SignedEvent, SignedFinding, SignedRevocation, event_id, event_payload
from .mesh import MAX_EVENT_BYTES


SCHEMA = """
CREATE TABLE IF NOT EXISTS mesh_delivery_profile (
  singleton BOOLEAN PRIMARY KEY CHECK (singleton),
  profile TEXT NOT NULL CHECK (profile IN ('legacy', 'priority'))
);
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
  sent_at TIMESTAMPTZ,
  kind TEXT
);
CREATE TABLE IF NOT EXISTS mesh_journal (
  position BIGSERIAL PRIMARY KEY,
  event_id UUID NOT NULL UNIQUE REFERENCES mesh_events(event_id),
  kind TEXT
);
"""


class AdmissionFull(RuntimeError):
    """The reserved admission capacity for this event class is full."""


class EventTooLarge(ValueError):
    """The event would exceed the broker message limit."""


class SequenceConflict(ValueError):
    """A publisher sequence has already been used for a different event."""


JOURNAL_LOCK = 4611686018427387904
SCHEMA_LOCK = JOURNAL_LOCK + 1
OUTBOX_LIMITS = {"finding": 2048, "revocation": 256}


class PostgresRepository:
    def __init__(self, dsn: str, *, priority: bool = False):
        self.dsn = dsn
        self.priority = priority
        profile = "priority" if priority else "legacy"
        with psycopg.connect(dsn) as db:
            db.execute("SELECT pg_advisory_xact_lock(%s)", (SCHEMA_LOCK,))
            exists, = db.execute("SELECT to_regclass('public.mesh_delivery_profile')").fetchone()
            if exists is not None:
                stored = db.execute("SELECT profile FROM mesh_delivery_profile").fetchone()
                if stored != (profile,):
                    raise ValueError("coordinators sharing a repository must use the pinned Mesh delivery profile")
                return

            # This transaction is the offline cutover from pre-profile schemas.
            # Same-profile peers use the fast path above and take no table DDL locks.
            db.execute("SELECT pg_advisory_xact_lock(%s)", (JOURNAL_LOCK,))
            db.execute(SCHEMA)
            db.execute("ALTER TABLE mesh_journal ADD COLUMN IF NOT EXISTS kind TEXT")
            db.execute("ALTER TABLE mesh_outbox ADD COLUMN IF NOT EXISTS kind TEXT")
            legacy, = db.execute("SELECT to_regclass('public.findings')").fetchone()
            if legacy is not None:
                db.execute(
                    "INSERT INTO mesh_events(event_id,kind,publisher_id,sequence,envelope) "
                    "SELECT artifact_id,'finding',publisher_id,sequence,envelope FROM findings "
                    "ON CONFLICT DO NOTHING"
                )
                db.execute(
                    "INSERT INTO mesh_outbox(event_id,sent_at,kind) "
                    "SELECT artifact_id,sent_at,'finding' FROM outbox ON CONFLICT DO NOTHING"
                )
            db.execute(
                "INSERT INTO mesh_journal(event_id,kind) SELECT e.event_id,e.kind FROM mesh_events e "
                "LEFT JOIN mesh_journal j USING(event_id) WHERE j.event_id IS NULL "
                "ORDER BY e.publisher_id,e.sequence,e.event_id ON CONFLICT DO NOTHING"
            )
            for table in ("mesh_journal", "mesh_outbox"):
                db.execute(f"UPDATE {table} t SET kind=e.kind FROM mesh_events e "
                           "WHERE t.kind IS NULL AND t.event_id=e.event_id")
            db.execute("CREATE INDEX IF NOT EXISTS mesh_outbox_unsent ON mesh_outbox(kind,event_id) "
                       "WHERE sent_at IS NULL")
            db.execute("CREATE INDEX IF NOT EXISTS mesh_journal_kind_position "
                       "ON mesh_journal(kind,position)")
            db.execute("INSERT INTO mesh_delivery_profile VALUES(true,%s)", (profile,))

    def add(self, envelope: SignedEvent) -> bool:
        payload = event_payload(envelope)
        eid = event_id(envelope)
        encoded = envelope.model_dump(mode="json")
        if self.priority and len(envelope.model_dump_json().encode()) > MAX_EVENT_BYTES:
            raise EventTooLarge("event exceeds the broker message limit")
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
                if self.priority:
                    limit = OUTBOX_LIMITS[envelope.kind]
                    pending, = db.execute(
                        "SELECT count(*) FROM (SELECT 1 FROM mesh_outbox "
                        "WHERE kind=%s AND sent_at IS NULL LIMIT %s) reserved",
                        (envelope.kind, limit),
                    ).fetchone()
                    if pending >= limit:
                        raise AdmissionFull(f"{envelope.kind} delivery backlog is full")
                db.execute("INSERT INTO mesh_journal(event_id,kind) VALUES(%s,%s)", (eid, envelope.kind))
                db.execute("INSERT INTO mesh_outbox(event_id,kind) VALUES(%s,%s)", (eid, envelope.kind))
                return True

    def events_after(self, position: int, limit: int = 100, *, critical: bool = False) -> tuple[list[dict], int]:
        if position < 0 or not 1 <= limit <= 100:
            raise ValueError("invalid journal range")
        scope = " AND j.kind='revocation'" if critical else ""
        with psycopg.connect(self.dsn) as db:
            head = db.execute(
                "SELECT COALESCE(MAX(j.position),0) FROM mesh_journal j WHERE true" + scope
            ).fetchone()[0]
            rows = db.execute(
                "SELECT j.position,e.envelope FROM mesh_journal j "
                "JOIN mesh_events e USING(event_id) WHERE j.position>%s AND j.position<=%s"
                + scope + " ORDER BY j.position LIMIT %s",
                (position, head, limit),
            ).fetchall()
        return [{"position": item, "envelope": envelope} for item, envelope in rows], head

    def pending(self, limit: int = 100, *, kind: str | None = None) -> list[SignedEvent]:
        with psycopg.connect(self.dsn) as db:
            critical = kind == "revocation"
            rows = db.execute(
                "SELECT e.kind,e.envelope FROM mesh_outbox o JOIN mesh_events e USING(event_id) "
                + ("JOIN mesh_journal j USING(event_id) " if critical else "")
                + "WHERE o.sent_at IS NULL "
                + ("AND o.kind=%s " if kind is not None else "")
                + ("ORDER BY j.position LIMIT %s" if critical else "ORDER BY e.publisher_id,e.sequence LIMIT %s"),
                (limit,) if kind is None else (kind, limit),
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
