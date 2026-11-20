"""Offline advisory intake. Records and events have no Mesh or writer authority."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Mapping

from pydantic import Field, model_validator

from .baseline import _decode, _identifier, _ref, normalize
from .feeds import FeedClient, KEV_URI, MAX_BYTES
from .models import Claim, Record, SourceSnapshot, VersionClaim

SCHEMA_VERSION = "scout-advisory-input-v1"
_GHSA_URI = re.compile(
    r"https://api\.github\.com/repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/security-advisories/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})"
)
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.I)
MAX_CLAIMS = 10_000


class PriorityIndicator(Record):
    tier: Literal["urgent", "high", "review", "unscored"]
    reasons: tuple[str, ...]
    exploited: bool | None
    exposed: bool | None
    severity_score: float | None


class AdvisoryInput(Record):
    schema_version: Literal["scout-advisory-input-v1"] = SCHEMA_VERSION
    source_kind: Literal["nvd", "osv", "kev", "vendor-ghsa"]
    advisory_id: str
    vulnerability_ids: tuple[str, ...]
    source_uri: str
    retrieved_at: datetime
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    acquisition: Literal["fixture", "https"]
    provenance: Literal["synthetic-fixture", "unverified-archive"]
    redistribution: Literal["synthetic-test-only", "unknown"]
    published_at: str | None
    modified_at: str | None
    withdrawn_at: str | None
    missing: tuple[str, ...]
    conflict: bool
    priority: PriorityIndicator
    claims: tuple[Claim, ...]

    @model_validator(mode="after")
    def validate_references(self):
        if not self.claims or any(
            claim.reference.sha256 != self.content_sha256
            or claim.reference.uri != self.source_uri
            or claim.reference.kind != self.source_kind
            or claim.reference.retrieved_at != self.retrieved_at
            for claim in self.claims
        ):
            raise ValueError("claim source reference mismatch")
        return self


class ScoutEvent(Record):
    sequence: int
    kind: Literal["new", "changed", "conflict"]
    advisory: AdvisoryInput


def _timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("invalid source timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid source timestamp") from exc
    if parsed.tzinfo is None:
        # Official KEV date-only values are dates, not local wall-clock times.
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            raise ValueError("source timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _validate_uri(source: SourceSnapshot, claims: tuple[Claim, ...]) -> None:
    client = FeedClient()
    if source.kind == "kev":
        expected = KEV_URI
    elif source.kind == "vendor-ghsa":
        match = _GHSA_URI.fullmatch(source.uri)
        if not match or any(part in {".", ".."} for part in match.group(1).split("/")):
            raise ValueError("noncanonical source URI")
        client = FeedClient(vendor_repositories=frozenset({match.group(1)}))
        expected = client.canonical_uri("vendor-ghsa", match.group(2), repository=match.group(1))
    else:
        source_id = source.uri.rsplit("/", 1)[-1] if source.kind == "osv" else claims[0].vulnerability_id
        expected = client.canonical_uri(source.kind, source_id)
    if source.uri != expected:
        raise ValueError("noncanonical source URI")


def _advisory_id(source: SourceSnapshot, claim: Claim) -> str:
    if source.kind == "kev":
        return claim.vulnerability_id
    if source.kind == "nvd":
        return claim.vulnerability_id
    return source.uri.rsplit("/", 1)[-1]


def _unknown_product_claim(source: SourceSnapshot) -> Claim:
    """Retain a valid notice whose product list is absent, without implying impact."""
    data = _decode(source)
    if source.kind == "osv":
        vid = _identifier(data["id"])
        aliases = tuple(_identifier(value) for value in data.get("aliases", []))
        published, modified, withdrawn = data.get("published"), data.get("modified"), data.get("withdrawn")
    elif source.kind == "vendor-ghsa":
        vid = _identifier(data.get("cve_id") or data["ghsa_id"])
        aliases = (_identifier(data["ghsa_id"]),) if vid != data["ghsa_id"] else ()
        published, modified, withdrawn = (data.get("published_at"), data.get("updated_at"),
                                          data.get("withdrawn_at"))
    else:
        raise ValueError("source has no advisory entries")
    return Claim(vulnerability_id=vid, aliases=aliases, identity_kind="unknown", identity="",
                 versions=(VersionClaim(scheme="none"),), missing=("affected-products", "affected-versions"),
                 confidence="fixture" if source.acquisition == "fixture" else
                 "aggregated" if source.kind == "osv" else "vendor-published",
                 summary=str(data.get("summary") or "")[:4000], published_at=published,
                 modified_at=modified, withdrawn_at=withdrawn, reference=_ref(source, "/"))


def _priority(claims: tuple[Claim, ...], exposed: bool | None) -> PriorityIndicator:
    exploited = True if any(c.exploited is True for c in claims) else None
    scores = [c.severity_score for c in claims if c.severity_score is not None]
    if any(not math.isfinite(s) or not 0 <= s <= 10 for s in scores):
        raise ValueError("invalid severity score")
    score = max(scores) if scores else None
    reasons = []
    if exploited:
        reasons.append("listed-as-known-exploited")
    if exposed is True:
        reasons.append("operator-reported-exposure")
    elif exposed is False:
        reasons.append("operator-reported-no-exposure")
    if score is not None:
        reasons.append("cvss-score")
    if any(c.withdrawn_at is not None for c in claims):
        reasons.append("withdrawn-source")
        tier = "unscored"
    else:
        tier = ("urgent" if exploited and exposed is True else
            "high" if exploited or (exposed is True and score is not None and score >= 9) else
            "review" if exposed is True or score is not None else "unscored")
    return PriorityIndicator(tier=tier, reasons=tuple(reasons), exploited=exploited,
                             exposed=exposed, severity_score=score)


def _material(advisory: AdvisoryInput) -> str:
    """Ignore acquisition time and byte-only formatting; retain source revision separately."""
    data = advisory.model_dump(mode="json")
    for field in ("retrieved_at", "content_sha256", "acquisition", "provenance", "redistribution", "conflict"):
        data.pop(field)
    for claim in data["claims"]:
        claim.pop("reference")
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ThreatScout:
    """Synchronous, transactional offline intake. Pass a path to opt into durable SQLite."""

    def __init__(self, database: Path | None = None):
        if database is not None and not isinstance(database, Path):
            raise TypeError("database must be a Path")
        self.db = sqlite3.connect(str(database) if database is not None else ":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS snapshots (
                digest TEXT PRIMARY KEY, content BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS observations (
                source_kind TEXT NOT NULL, uri TEXT NOT NULL, digest TEXT NOT NULL,
                retrieved_at TEXT NOT NULL, acquisition TEXT NOT NULL,
                PRIMARY KEY (source_kind, uri, digest, retrieved_at, acquisition),
                FOREIGN KEY (digest) REFERENCES snapshots(digest)
            );
            CREATE TABLE IF NOT EXISTS revisions (
                source_kind TEXT NOT NULL, advisory_id TEXT NOT NULL, digest TEXT NOT NULL,
                record TEXT NOT NULL, material TEXT NOT NULL, modified_time TEXT,
                PRIMARY KEY (source_kind, advisory_id, digest),
                FOREIGN KEY (digest) REFERENCES snapshots(digest)
            );
            CREATE TABLE IF NOT EXISTS current_state (
                source_kind TEXT NOT NULL, advisory_id TEXT NOT NULL, digest TEXT NOT NULL,
                material TEXT NOT NULL, modified_time TEXT,
                PRIMARY KEY (source_kind, advisory_id)
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                source_kind TEXT NOT NULL, advisory_id TEXT NOT NULL, record TEXT NOT NULL
            );
        """)

    def close(self) -> None:
        self.db.close()

    def ingest(self, source: SourceSnapshot, *, exposure: Mapping[str, bool] | None = None) -> tuple[ScoutEvent, ...]:
        """Validate a supplied snapshot and atomically save every advisory revision."""
        if hashlib.sha256(source.content).hexdigest() != source.sha256:
            raise ValueError("snapshot digest mismatch")
        if len(source.content) > MAX_BYTES:
            raise ValueError("snapshot exceeds byte limit")
        if source.retrieved_at.tzinfo is None:
            raise ValueError("snapshot time lacks timezone")
        claims = normalize(source)
        if not claims and source.kind in {"osv", "vendor-ghsa"}:
            claims = (_unknown_product_claim(source),)
        if len(claims) > MAX_CLAIMS:
            raise ValueError("oversized advisory set")
        _validate_uri(source, claims)
        if exposure is not None and (not isinstance(exposure, Mapping) or
                                     any(not isinstance(k, str) or type(v) is not bool for k, v in exposure.items())):
            raise ValueError("invalid exposure metadata")
        grouped: dict[str, list[Claim]] = {}
        for claim in claims:
            grouped.setdefault(_advisory_id(source, claim), []).append(claim)
        prepared = []
        for advisory_id, group in grouped.items():
            group = tuple(group)
            published = {c.published_at for c in group if c.published_at is not None}
            modified = {c.modified_at for c in group if c.modified_at is not None}
            withdrawn = {c.withdrawn_at for c in group if c.withdrawn_at is not None}
            for value in (*published, *modified, *withdrawn):
                _timestamp(value)
            missing = {fact for claim in group for fact in claim.missing}
            if not published:
                missing.add("published-at")
            if not modified:
                missing.add("modified-at")
            if len(published) > 1 or len(modified) > 1 or len(withdrawn) > 1:
                missing.add("conflicting-source-metadata")
            ids = tuple(sorted({v.upper() if _CVE.fullmatch(v) else v
                                for c in group for v in (c.vulnerability_id, *c.aliases)}))
            exposed = next((exposure[v] for v in ids if exposure is not None and v in exposure), None)
            if exposure is not None and len({exposure[v] for v in ids if v in exposure}) > 1:
                missing.add("conflicting-exposure-metadata")
                exposed = None
            record = AdvisoryInput(source_kind=source.kind, advisory_id=advisory_id,
                                   vulnerability_ids=ids, source_uri=source.uri,
                                   retrieved_at=source.retrieved_at, content_sha256=source.sha256,
                                   acquisition=source.acquisition,
                                   provenance="synthetic-fixture" if source.acquisition == "fixture" else "unverified-archive",
                                   redistribution="synthetic-test-only" if source.acquisition == "fixture" else "unknown",
                                   published_at=next(iter(published)) if len(published) == 1 else None,
                                   modified_at=next(iter(modified)) if len(modified) == 1 else None,
                                   withdrawn_at=next(iter(withdrawn)) if len(withdrawn) == 1 else None,
                                   missing=tuple(sorted(missing)), conflict=False,
                                   priority=_priority(group, exposed), claims=group)
            prepared.append(record)
        emitted: list[ScoutEvent] = []
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO snapshots VALUES (?, ?)", (source.sha256, source.content))
            actual = self.db.execute("SELECT content FROM snapshots WHERE digest=?", (source.sha256,)).fetchone()[0]
            if actual != source.content:
                raise ValueError("snapshot digest collision")
            self.db.execute("INSERT OR IGNORE INTO observations VALUES (?, ?, ?, ?, ?)",
                            (source.kind, source.uri, source.sha256,
                             source.retrieved_at.isoformat(), source.acquisition))
            for record in prepared:
                key = (record.source_kind, record.advisory_id)
                if self.db.execute("SELECT 1 FROM revisions WHERE source_kind=? AND advisory_id=? AND digest=?",
                                   (*key, source.sha256)).fetchone():
                    previous = self.db.execute("SELECT material FROM revisions WHERE source_kind=? "
                                               "AND advisory_id=? AND digest=?", (*key, source.sha256)).fetchone()[0]
                    if previous != _material(record):
                        raise ValueError("metadata differs for pinned source revision")
                    continue
                material = _material(record)
                modified = _timestamp(record.modified_at)
                modified_key = modified.isoformat() if modified else None
                current = self.db.execute("SELECT digest, material, modified_time FROM current_state "
                                          "WHERE source_kind=? AND advisory_id=?", key).fetchone()
                kind = None
                advance = False
                if current is None:
                    kind, advance = "new", True
                elif current[1] != material:
                    if modified_key and current[2] and modified_key > current[2]:
                        kind, advance = "changed", True
                    elif modified_key and current[2] and modified_key < current[2]:
                        pass  # Historical version arrives late; retain without rolling back current.
                    else:
                        kind = "conflict"
                conflict = kind == "conflict"
                if conflict:
                    record = record.model_copy(update={"conflict": True})
                encoded = record.model_dump_json()
                self.db.execute("INSERT INTO revisions VALUES (?, ?, ?, ?, ?, ?)",
                                (*key, source.sha256, encoded, material, modified_key))
                if advance:
                    self.db.execute("INSERT OR REPLACE INTO current_state VALUES (?, ?, ?, ?, ?)",
                                    (*key, source.sha256, material, modified_key))
                if kind is not None:
                    cursor = self.db.execute("INSERT INTO events (kind, source_kind, advisory_id, record) "
                                             "VALUES (?, ?, ?, ?)", (kind, *key, encoded))
                    emitted.append(ScoutEvent(sequence=cursor.lastrowid, kind=kind, advisory=record))
        return tuple(emitted)

    def events(self, after: int = 0, limit: int = 100) -> tuple[ScoutEvent, ...]:
        if after < 0 or not 1 <= limit <= 1000:
            raise ValueError("invalid event cursor or limit")
        rows = self.db.execute("SELECT sequence, kind, record FROM events WHERE sequence>? "
                               "ORDER BY sequence LIMIT ?", (after, limit)).fetchall()
        return tuple(ScoutEvent(sequence=n, kind=kind, advisory=AdvisoryInput.model_validate_json(record))
                     for n, kind, record in rows)

    def revisions(self, source_kind: str, advisory_id: str) -> tuple[AdvisoryInput, ...]:
        rows = self.db.execute("SELECT record FROM revisions WHERE source_kind=? AND advisory_id=? "
                               "ORDER BY rowid", (source_kind, advisory_id)).fetchall()
        return tuple(AdvisoryInput.model_validate_json(row[0]) for row in rows)

    def source_bytes(self, digest: str) -> bytes | None:
        row = self.db.execute("SELECT content FROM snapshots WHERE digest=?", (digest,)).fetchone()
        return row[0] if row else None

    def observations(self, digest: str) -> tuple[tuple[str, str, str, str], ...]:
        """Return source kind, URI, acquisition and original supplied acquisition time."""
        rows = self.db.execute("SELECT source_kind, uri, acquisition, retrieved_at FROM observations "
                               "WHERE digest=? ORDER BY retrieved_at, source_kind, uri", (digest,)).fetchall()
        return tuple(rows)
