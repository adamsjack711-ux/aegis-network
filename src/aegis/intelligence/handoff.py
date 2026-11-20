"""Private offline research over Scout's local SQLite event queue."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from .baseline import normalize
from .investigator import AdvisoryInput, Investigation, ScriptedProvider, investigate, verify_investigation
from .models import Asset, Claim, SourceSnapshot
from .scout import AdvisoryInput as ScoutInput

VERSION = "scout-investigator-adapter-v1"

# An incomparable conflict emits an event but does not advance current_state.
# Both the event head and the current digest must therefore agree.
_SCHEMA = """
CREATE INDEX IF NOT EXISTS research_event_head ON events(source_kind, advisory_id, sequence);
CREATE VIEW IF NOT EXISTS research_revision_state AS
SELECT e.sequence, e.record, e.advisory_id, e.source_kind,
       json_extract(e.record, '$.content_sha256') AS digest,
       CASE WHEN h.kind = 'conflict' THEN 'conflict'
            WHEN json_extract(h.record, '$.withdrawn_at') IS NOT NULL THEN 'withdrawn'
            WHEN c.digest IS NULL THEN 'unknown'
            WHEN h.sequence = e.sequence AND c.digest = json_extract(e.record, '$.content_sha256')
              THEN 'current'
            ELSE 'superseded' END AS status
FROM events e
JOIN events h ON h.sequence = (SELECT MAX(n.sequence) FROM events n
    WHERE n.source_kind=e.source_kind AND n.advisory_id=e.advisory_id)
LEFT JOIN current_state c ON c.source_kind=e.source_kind AND c.advisory_id=e.advisory_id;

CREATE TABLE IF NOT EXISTS research_results (
    sequence INTEGER NOT NULL REFERENCES events(sequence),
    vulnerability_id TEXT NOT NULL, asset_digest TEXT NOT NULL,
    investigation TEXT NOT NULL,
    PRIMARY KEY(sequence,vulnerability_id,asset_digest)
);
"""


def _has_applicability(claim: Claim) -> bool:
    if (not claim.identity or claim.identity_kind == "unknown"
            or {"affected-products", "affected-versions"}.intersection(claim.missing)):
        return False
    if claim.identity_kind == "ecosystem" and not all(claim.identity.split(":", 1)):
        return False
    for version in claim.versions:
        if version.scheme == "none" or not version.value:
            return False
        if version.scheme == "osv" and (version.value not in {"ECOSYSTEM", "SEMVER"} or not version.events):
            return False
    return bool(claim.versions)


@dataclass(frozen=True)
class Receipt:
    outcome: Literal["committed", "duplicate", "held"]
    sequence: int
    reason: str


class OfflineHandoff:
    """One consumer connection per worker, on the same file as ThreatScout."""

    def __init__(self, path: Path):
        self.db = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True)
        try:
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.executescript(_SCHEMA)
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    def consume(self, sequence: int, vulnerability_id: str, asset: Asset,
                provider: ScriptedProvider, *, now: datetime | None = None) -> Receipt:
        """Pick up a pinned event. Only history() publishes a result with currency."""
        if type(provider) is not ScriptedProvider:
            raise PermissionError("offline scripted research only")
        row = self.db.execute("""
            SELECT s.status,s.record,b.content FROM research_revision_state s
            LEFT JOIN snapshots b ON b.digest=s.digest WHERE sequence=?
        """, (sequence,)).fetchone()
        if row is None or row[0] != "current":
            return Receipt("held", sequence, row[0] if row else "unknown-event")
        try:
            scout = ScoutInput.model_validate_json(row[1])
            if vulnerability_id not in scout.vulnerability_ids:
                return Receipt("held", sequence, "unknown-vulnerability-id")
            source = SourceSnapshot(kind=scout.source_kind, uri=scout.source_uri,
                                    retrieved_at=scout.retrieved_at, acquisition=scout.acquisition,
                                    sha256=scout.content_sha256, content=row[2])
            claims = normalize(source)
            if (not claims or claims != scout.claims or
                    any(vulnerability_id not in (c.vulnerability_id, *c.aliases) for c in claims)):
                return Receipt("held", sequence, "lossy-claim-projection")
            if not all(_has_applicability(claim) for claim in claims):
                return Receipt("held", sequence, "unsupported-applicability")
            if any(reason.startswith("conflicting-") for reason in scout.missing):
                return Receipt("held", sequence, "conflicting-metadata")
            advisory = AdvisoryInput(advisory_id=scout.advisory_id, vulnerability_id=vulnerability_id,
                                     asset=asset, sources=(source,))
            result = investigate(advisory, provider, now=now)
            verify_investigation(advisory, result, now=now)
        except (ValueError, TypeError, KeyError):
            return Receipt("held", sequence, "invalid-source-or-research-input")
        asset_bytes = json.dumps(asset.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
        return self._commit(sequence, scout.content_sha256, hashlib.sha256(asset_bytes).hexdigest(), result)

    def _commit(self, sequence: int, digest: str, asset_digest: str, result: Investigation) -> Receipt:
        # Acquire the writer lock BEFORE evaluating currency. No provider work under lock.
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            inserted = self.db.execute("""
                INSERT INTO research_results(sequence,vulnerability_id,asset_digest,investigation)
                SELECT sequence,?,?,? FROM research_revision_state
                WHERE sequence=? AND status='current' AND digest=? AND advisory_id=?
                ON CONFLICT(sequence,vulnerability_id,asset_digest) DO NOTHING
            """, (result.candidate.vulnerability_id, asset_digest, result.model_dump_json(),
                  sequence, digest, result.candidate.advisory_id))
            if inserted.rowcount:
                return Receipt("committed", sequence, "revision-current-at-commit")
            row = self.db.execute("SELECT status FROM research_revision_state WHERE sequence=?",
                                  (sequence,)).fetchone()
            if row and row[0] == "current":
                existing = self.db.execute("""SELECT 1 FROM research_results
                    WHERE sequence=? AND vulnerability_id=? AND asset_digest=?""",
                    (sequence, result.candidate.vulnerability_id, asset_digest)).fetchone()
                if existing:
                    return Receipt("duplicate", sequence, "already-recorded")
                return Receipt("held", sequence, "binding-mismatch")
            return Receipt("held", sequence, row[0] if row else "unknown-event")

    def history(self, source_kind: str, advisory_id: str) -> list[dict]:
        """Single statement snapshot; currency is derived, never cached on a result."""
        rows = self.db.execute("""
            SELECT s.sequence,s.status,s.record,r.vulnerability_id,r.asset_digest,r.investigation
            FROM research_results r JOIN research_revision_state s ON s.sequence=r.sequence
            WHERE s.source_kind=? AND s.advisory_id=? ORDER BY s.sequence,r.vulnerability_id,r.asset_digest
        """, (source_kind, advisory_id)).fetchall()
        history = []
        for seq, status, record, vid, asset_digest, investigation in rows:
            scout = ScoutInput.model_validate_json(record)
            history.append(dict(adapter=VERSION, scout_schema=scout.schema_version,
                                investigator_schema="advisory-input-v1", sequence=seq, status=status,
                                source_kind=scout.source_kind, advisory_id=scout.advisory_id,
                                source_uri=scout.source_uri, revision=scout.content_sha256,
                                acquisition=scout.acquisition, provenance=scout.provenance,
                                redistribution=scout.redistribution, priority=scout.priority.tier,
                                vulnerability_id=vid, asset_digest=asset_digest,
                                research=json.loads(investigation)))
        return history
