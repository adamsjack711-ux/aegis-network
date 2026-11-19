"""Single-coordinator collection, portable appraisal and durable Evidence history."""

import json
import math
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import runner
from ._worker import registered
from .records import (
    MATERIAL_ROLES, Attestation, Grant, Manifest, Outcome, SignedAttestation, SignedManifest,
    SignedWithdrawal, TargetKind, Trust, decode, digest, sign_record,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_clock (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    high_water INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_manifests (
    cohort TEXT NOT NULL,
    issuer TEXT NOT NULL,
    record_id TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL,
    wire BLOB NOT NULL,
    PRIMARY KEY (cohort, issuer, record_id)
);
CREATE INDEX IF NOT EXISTS evidence_material_scope ON evidence_manifests (cohort, scope);
CREATE TABLE IF NOT EXISTS evidence_attestations (
    cohort TEXT NOT NULL,
    bundle TEXT NOT NULL,
    issuer TEXT NOT NULL,
    record_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    wire BLOB NOT NULL,
    PRIMARY KEY (cohort, issuer, record_id)
);
CREATE INDEX IF NOT EXISTS evidence_scope ON evidence_attestations (cohort, bundle, expires_at);
CREATE TABLE IF NOT EXISTS evidence_withdrawals (
    cohort TEXT NOT NULL,
    issuer TEXT NOT NULL,
    record_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_issuer TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    wire BLOB NOT NULL,
    PRIMARY KEY (cohort, issuer, record_id)
);
CREATE INDEX IF NOT EXISTS evidence_targets ON evidence_withdrawals (
    cohort, target_kind, target_issuer, target_digest
);
CREATE TABLE IF NOT EXISTS evidence_contradictions (
    cohort TEXT NOT NULL,
    scope TEXT NOT NULL,
    positive_digest TEXT NOT NULL,
    negative_digest TEXT NOT NULL,
    PRIMARY KEY (cohort, scope)
);
"""


@dataclass(frozen=True)
class Bundle:
    """The caller supplies the expected digest from its authorized intake."""
    sha256: str
    manifest: bytes
    objects: Mapping[str, bytes]


@dataclass(frozen=True)
class Verifier:
    issuer: str
    key_id: str
    private_key: Ed25519PrivateKey


AssessmentReason = Literal[
    "quorum", "insufficient-corroboration", "worker-unavailable", "contested",
    "bundle-not-current", "bundle-withdrawn",
]


@dataclass(frozen=True)
class Assessment:
    bundle_sha256: str
    outcome: Outcome
    reason: AssessmentReason
    attestations: tuple[bytes, ...] = ()
    contradiction: tuple[str, str] | None = None


@dataclass(frozen=True)
class _Admitted:
    sha256: str
    scope: str
    manifest: Manifest
    submitter: Grant
    objects: dict[str, bytes]


def _admit(bundle: Bundle, cohort: str, trust: Trust, profiles: frozenset[runner.WorkerProfile]) -> _Admitted:
    signed = decode(SignedManifest, bundle.manifest)
    manifest = signed.body
    if digest(bundle.manifest) != bundle.sha256:
        raise ValueError("manifest digest mismatch")
    if cohort != manifest.cohort:
        raise ValueError("bundle is outside the requested cohort")
    submitter = trust.authorize(signed, "submitter", manifest.issued_at)
    if runner.WorkerProfile.from_manifest(manifest) not in profiles:
        raise ValueError("fixture environment, check or oracle pin is unsupported")
    if len(bundle.objects) != len(MATERIAL_ROLES):
        raise ValueError("incomplete or unexpected evidence materials")
    objects = {}
    for role in MATERIAL_ROLES:
        content = bundle.objects.get(role)
        pin = getattr(manifest.materials, role)
        if type(content) is not bytes or len(content) != pin.size or digest(content) != pin.sha256:
            raise ValueError(f"evidence material pin mismatch: {role}")
        objects[role] = content
    if not registered(manifest.family, objects):
        raise ValueError("fixture is not registered")
    # Envelope reissuance requires new signatures but cannot erase a material disagreement.
    inputs = manifest.model_dump(
        mode="json", exclude={"record_id", "issued_at", "expires_at", "key_id"},
    )
    scope = digest(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode("ascii"))
    return _Admitted(bundle.sha256, scope, manifest, submitter, objects)


class Evidence:
    """Own one trusted local ledger per coordinator. Clients pass their authorized cohort."""

    def __init__(
        self, database: str | Path, trust: Trust, verifiers: tuple[Verifier, ...] = (), *,
        clock: Callable[[], float] = time.time, attestation_ttl: int = 300,
        worker_timeout: float = 2.0, max_workers: int = 4,
        profiles: frozenset[runner.WorkerProfile] = frozenset({runner.LOCAL_PROFILE}),
    ):
        if not 0 < attestation_ttl <= 3600 or not math.isfinite(worker_timeout) or worker_timeout <= 0:
            raise ValueError("invalid verification time limit")
        if max_workers < 1:
            raise ValueError("at least one worker slot is required")
        self._verifiers = {}
        for verifier in verifiers:
            identity = (verifier.issuer, verifier.key_id)
            grant = trust.grants.get(identity)
            if (identity in self._verifiers or grant is None or grant.role != "verifier"
                    or grant.public_key.public_bytes_raw() != verifier.private_key.public_key().public_bytes_raw()):
                raise ValueError("worker signer does not match a unique pinned verifier")
            self._verifiers[identity] = verifier
        self._db = sqlite3.connect(database, check_same_thread=False)
        self._db.executescript(SCHEMA)
        self._trust = trust
        self._profiles = profiles
        self._clock = clock
        self._ttl = attestation_ttl
        self._timeout = worker_timeout
        self._slots = threading.BoundedSemaphore(max_workers)
        self._lock = threading.RLock()
        self._pending: dict[tuple[str, str, str, str], Future[bool]] = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._db.close()

    def _now(self) -> int:
        now = int(self._clock())
        previous = self._db.execute("SELECT high_water FROM evidence_clock WHERE id = 1").fetchone()
        if previous is not None and now < previous[0]:
            raise ValueError("evidence clock regressed")
        if previous is None or now > previous[0]:
            self._db.execute(
                "INSERT INTO evidence_clock VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET high_water = excluded.high_water",
                (now,),
            )
        return now

    def _register(self, bundle: _Admitted, wire: bytes) -> None:
        body = bundle.manifest
        self._store_record(
            "evidence_manifests", wire, (body.cohort, body.issuer, body.record_id),
            """INSERT INTO evidence_manifests
               (cohort, issuer, record_id, wire, digest, scope) VALUES (?, ?, ?, ?, ?, ?)""",
            (bundle.sha256, bundle.scope),
        )

    def _withdrawn(self, cohort: str, kind: TargetKind, issuer: str, sha256: str) -> bool:
        return self._db.execute(
            """SELECT 1 FROM evidence_withdrawals
               WHERE cohort = ? AND target_kind = ? AND target_issuer = ? AND target_digest = ? LIMIT 1""",
            (cohort, kind, issuer, sha256),
        ).fetchone() is not None

    def _bundle_problem(self, bundle: _Admitted, now: int) -> AssessmentReason | None:
        manifest = bundle.manifest
        if self._withdrawn(manifest.cohort, "bundle", manifest.issuer, bundle.sha256):
            return "bundle-withdrawn"
        if not manifest.issued_at <= now < min(manifest.expires_at, bundle.submitter.expires_at):
            return "bundle-not-current"
        return None

    def _verifier_current(self, bundle: _Admitted, grant: Grant, now: int) -> bool:
        cohort = bundle.manifest.cohort
        return (
            grant.organization != bundle.submitter.organization and cohort in grant.cohorts
            and grant.not_before <= now < grant.expires_at
            and not self._withdrawn(cohort, "verifier-key", grant.issuer, digest(grant.public_key.public_bytes_raw()))
        )

    def _attestation_grant(
        self, bundle: _Admitted, attestation: SignedAttestation, wire: bytes, now: int,
    ) -> Grant:
        body = attestation.body
        if (body.bundle_sha256 != bundle.sha256 or body.cohort != bundle.manifest.cohort
                or body.started_at < bundle.manifest.issued_at
                or body.expires_at > min(bundle.manifest.expires_at, body.issued_at + self._ttl)):
            raise ValueError("attestation is outside the exact bundle scope")
        grant = self._trust.authorize(attestation, "verifier", now)
        if (body.started_at < grant.not_before or body.expires_at > grant.expires_at
                or not self._verifier_current(bundle, grant, now)
                or self._withdrawn(body.cohort, "attestation", body.issuer, digest(wire))):
            raise ValueError("attestation is withdrawn or verifier is ineligible")
        return grant

    def _qualifying(self, bundle: _Admitted, now: int):
        rows = self._db.execute(
            """SELECT digest, wire FROM evidence_attestations
               WHERE cohort = ? AND bundle = ? AND expires_at > ? ORDER BY digest""",
            (bundle.manifest.cohort, bundle.sha256, now),
        ).fetchall()
        for expected, wire in rows:
            if type(wire) is not bytes or digest(wire) != expected:
                continue
            try:
                attestation = decode(SignedAttestation, wire)
                grant = self._attestation_grant(bundle, attestation, wire, now)
            except ValueError:
                continue
            yield attestation.body.observation.outcome, grant, wire

    def _comparable(self, bundle: _Admitted, now: int):
        rows = self._db.execute(
            """SELECT digest, wire FROM evidence_manifests
               WHERE cohort = ? AND scope = ? AND digest != ? ORDER BY digest""",
            (bundle.manifest.cohort, bundle.scope, bundle.sha256),
        ).fetchall()
        for sha256, wire in rows:
            try:
                other = _admit(Bundle(sha256, wire, bundle.objects), bundle.manifest.cohort,
                               self._trust, self._profiles)
            except ValueError:
                continue
            if other.scope == bundle.scope and not self._bundle_problem(other, now):
                yield from self._qualifying(other, now)

    def _assessment(self, bundle: _Admitted, now: int) -> Assessment:
        problem = self._bundle_problem(bundle, now)
        if problem:
            return Assessment(bundle.sha256, "inconclusive", problem)
        pair = self._db.execute(
            """SELECT positive_digest, negative_digest FROM evidence_contradictions
               WHERE cohort = ? AND scope = ?""", (bundle.manifest.cohort, bundle.scope),
        ).fetchone()
        if pair:
            return Assessment(bundle.sha256, "inconclusive", "contested", contradiction=pair)

        votes: dict[Outcome, dict[str, bytes]] = {"reproduced": {}, "not-reproduced": {}, "inconclusive": {}}
        for outcome, grant, wire in self._qualifying(bundle, now):
            votes[outcome].setdefault(grant.organization, wire)
        positive, negative = votes["reproduced"], votes["not-reproduced"]
        comparison = {
            "reproduced": next(iter(positive.values()), None),
            "not-reproduced": next(iter(negative.values()), None),
        }
        if not all(comparison.values()):
            for outcome, _, wire in self._comparable(bundle, now):
                if outcome in comparison and comparison[outcome] is None:
                    comparison[outcome] = wire
                if all(comparison.values()):
                    break
        reproduced, not_reproduced = comparison["reproduced"], comparison["not-reproduced"]
        if reproduced is not None and not_reproduced is not None:
            pair = (digest(reproduced), digest(not_reproduced))
            self._db.execute(
                "INSERT INTO evidence_contradictions VALUES (?, ?, ?, ?)",
                (bundle.manifest.cohort, bundle.scope, *pair),
            )
            return Assessment(bundle.sha256, "inconclusive", "contested", contradiction=pair)
        if len(positive) >= 2:
            return Assessment(bundle.sha256, "reproduced", "quorum", tuple(positive.values()))
        if len(negative) >= 2:
            return Assessment(bundle.sha256, "not-reproduced", "quorum", tuple(negative.values()))
        available = tuple(wire for group in votes.values() for wire in group.values())
        return Assessment(bundle.sha256, "inconclusive", "insufficient-corroboration", available)

    def assess(self, bundle: Bundle, *, cohort: str) -> Assessment:
        """Reappraise cached records using local trust and current withdrawals."""
        admitted = _admit(bundle, cohort, self._trust, self._profiles)
        with self._lock, self._db:
            self._register(admitted, bundle.manifest)
            return self._assessment(admitted, self._now())

    def _store_attestation(self, bundle: _Admitted, wire: bytes, now: int) -> Assessment:
        attestation = decode(SignedAttestation, wire)
        body = attestation.body
        if self._bundle_problem(bundle, now):
            raise ValueError("bundle no longer eligible for attestation intake")
        self._attestation_grant(bundle, attestation, wire, now)
        self._store_record(
            "evidence_attestations", wire, (body.cohort, body.issuer, body.record_id),
            """INSERT INTO evidence_attestations
               (cohort, issuer, record_id, wire, bundle, digest, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (body.bundle_sha256, digest(wire), body.expires_at),
        )
        return self._assessment(bundle, now)

    def _store_record(self, table, wire, identity, insert_sql, extra):
        # Table names and insert statements are fixed at the call sites.
        existing = self._db.execute(
            f"SELECT wire FROM {table} WHERE cohort = ? AND issuer = ? AND record_id = ?", identity,
        ).fetchone()
        if existing is None:
            self._db.execute(insert_sql, (*identity, wire, *extra))
        elif existing[0] != wire:
            raise ValueError("conflicting evidence record ID")

    def accept_attestation(self, bundle: Bundle, wire: bytes, *, cohort: str) -> Assessment:
        admitted = _admit(bundle, cohort, self._trust, self._profiles)
        with self._lock, self._db:
            now = self._now()
            self._register(admitted, bundle.manifest)
            return self._store_attestation(admitted, wire, now)

    def accept_withdrawal(self, wire: bytes, *, cohort: str) -> None:
        signed = decode(SignedWithdrawal, wire)
        body = signed.body
        with self._lock, self._db:
            grant = self._trust.authorize(signed, "revoker", self._now())
            if (body.cohort != cohort or body.target_issuer not in grant.withdrawal_issuers
                    or body.target_kind not in grant.withdrawal_kinds):
                raise ValueError("withdrawal is outside the revoker's scope")
            self._store_record(
                "evidence_withdrawals", wire, (body.cohort, body.issuer, body.record_id),
                """INSERT INTO evidence_withdrawals
                   (cohort, issuer, record_id, wire, target_kind, target_issuer, target_digest)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (body.target_kind, body.target_issuer, body.target_sha256),
            )

    def _collect(self, bundle: _Admitted, verifier: Verifier, grant: Grant) -> bool:
        with self._slots:
            with self._lock, self._db:
                started = self._now()
                if self._assessment(bundle, started).reason in {"contested", "bundle-not-current", "bundle-withdrawn"}:
                    return True
                if not self._verifier_current(bundle, grant, started):
                    return True
            try:
                observation = runner.run(bundle.manifest, bundle.objects, self._timeout)
            except runner.WorkerFailure:
                return False
        with self._lock, self._db:
            now = self._now()
            if (now < started or self._bundle_problem(bundle, now)
                    or not self._verifier_current(bundle, grant, now)):
                return False
            body = Attestation(
                kind="aegis.evidence.attestation.v1", record_id=uuid4().hex, issuer=verifier.issuer,
                key_id=verifier.key_id, cohort=bundle.manifest.cohort, issued_at=now,
                expires_at=min(now + self._ttl, bundle.manifest.expires_at, grant.expires_at),
                bundle_sha256=bundle.sha256, started_at=started, observation=observation,
            )
            self._store_attestation(bundle, sign_record(body, verifier.private_key), now)
        return True

    def _ensure_observation(self, bundle: _Admitted, verifier: Verifier, grant: Grant) -> bool:
        key = (bundle.manifest.cohort, bundle.sha256, verifier.issuer, verifier.key_id)
        with self._lock, self._db:
            now = self._now()
            if not self._verifier_current(bundle, grant, now):
                return True
            pending = self._pending.get(key)
            if pending is None:
                if any(eligible == grant for _, eligible, _ in self._qualifying(bundle, now)):
                    return True
                pending = self._pending[key] = Future()
                owner = True
            else:
                owner = False
        if not owner:
            return pending.result()
        try:
            pending.set_result(self._collect(bundle, verifier, grant))
        except BaseException as exc:
            pending.set_exception(exc)
            raise
        finally:
            with self._lock:
                del self._pending[key]
        return pending.result()

    def verify(self, bundle: Bundle, *, cohort: str) -> Assessment:
        """Collect missing verifier observations, then independently appraise them."""
        admitted = _admit(bundle, cohort, self._trust, self._profiles)
        with self._lock, self._db:
            self._register(admitted, bundle.manifest)
            initial = self._assessment(admitted, self._now())
        if initial.reason != "insufficient-corroboration":
            return initial
        workers_ok = True
        for identity, verifier in self._verifiers.items():
            workers_ok = self._ensure_observation(admitted, verifier, self._trust.grants[identity]) and workers_ok
        with self._lock, self._db:
            result = self._assessment(admitted, self._now())
        if not workers_ok and result.reason == "insufficient-corroboration":
            return Assessment(result.bundle_sha256, result.outcome, "worker-unavailable", result.attestations)
        return result
