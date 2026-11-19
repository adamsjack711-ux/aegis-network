"""Independent status operator and relying-party lab prototype. No actuator access."""

import json
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .records import (
    MAX_RECORD, Grant, Outcome, SignedAttestation, SignedManifest, SignedWithdrawal, canonical, decode,
    digest,
)
from .service import Bundle, _admit
from .status_protocol import (
    MAX_HISTORY, STATUS_TTL, Challenge, Endorsement, Head, ReviewBinding, Scope, SignedEndorsement,
    StatusPolicy, archive_head, authenticate, canonical_json, check_observation, endorsement_bytes,
    material_scope,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS status_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    policy TEXT NOT NULL,
    owner TEXT NOT NULL,
    high_water INTEGER NOT NULL DEFAULT 0,
    floor BLOB NOT NULL DEFAULT X'5B5D',
    blocked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS status_records (
    digest TEXT PRIMARY KEY,
    wire BLOB NOT NULL
);
"""

Reason = Literal[
    "quorum", "insufficient-corroboration", "inconclusive-observations", "stale-evidence", "revoked",
    "contested", "missing-bundle", "withheld-status", "withheld-records", "invalid-status",
    "invalid-history", "divergent-status", "stale-status", "conflicting-history",
]


@dataclass(frozen=True)
class StatusProof:
    endorsements: tuple[bytes, ...]
    records: tuple[bytes, ...]


@dataclass(frozen=True)
class StatusAssessment:
    outcome: Outcome
    reason: Reason
    head: Head | None = None
    attestation_sha256: tuple[str, ...] = ()
    binding: ReviewBinding | None = None
    valid_until: int | None = None

    @property
    def binding_sha256(self) -> str | None:
        return digest(canonical(self.binding)) if self.binding is not None else None


class _State:
    def __init__(self, path: Path, policy: StatusPolicy, owner: str, clock, *, provision: bool):
        self._path = path
        self._policy = policy
        self._clock = clock
        self._owner = owner
        self._policy_sha256 = policy.sha256
        if provision:
            # Create only a new store. A missing or replaced store must be reconciled outside runtime.
            with path.open("xb"):
                pass
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript(_SCHEMA)
                db.execute("INSERT INTO status_state (id, policy, owner) VALUES (1, ?, ?)",
                           (self._policy_sha256, owner))
        with self._transaction():
            pass

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self._path.resolve().as_uri() + "?mode=rw", uri=True)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            pin = db.execute("SELECT policy, owner FROM status_state WHERE id = 1").fetchone()
            if pin != (self._policy_sha256, self._owner):
                raise ValueError("Evidence status state belongs to another policy or operator")
            yield db

    def _now(self, db: sqlite3.Connection) -> int:
        now = int(self._clock())
        previous, = db.execute("SELECT high_water FROM status_state WHERE id = 1").fetchone()
        if not previous <= now:
            raise ValueError("Evidence status clock regressed")
        if now != previous:
            db.execute("UPDATE status_state SET high_water = ? WHERE id = 1", (now,))
        return now


class StatusWitness(_State):
    """Admit signed records directly and endorse only this operator's committed view."""

    def __init__(self, path: Path, policy: StatusPolicy, witness_id: str, key: Ed25519PrivateKey, *,
                 clock: Callable[[], float] = time.time, provision: bool = False):
        if not any(w.witness_id == witness_id and w.public_key.public_bytes_raw() == key.public_key().public_bytes_raw()
                   for w in policy.witnesses):
            raise ValueError("status signer does not match an enrolled witness")
        self._witness_id = witness_id
        self._key = key
        super().__init__(path, policy, f"witness:{witness_id}", clock, provision=provision)

    def admit(self, wire: bytes) -> str | None:
        """Return the digest after durable intake. None means capacity was exceeded and status stopped."""
        if type(wire) is not bytes or len(wire) > MAX_RECORD:
            raise ValueError("invalid Evidence record size")
        pin = digest(wire)
        with self._transaction() as db:
            now = self._now(db)
            if db.execute("SELECT 1 FROM status_records WHERE digest = ?", (pin,)).fetchone():
                return pin
            record, grant = authenticate(self._policy, wire, now, admission=True)
            if isinstance(record, SignedAttestation):
                row = db.execute("SELECT wire FROM status_records WHERE digest = ?",
                                 (record.body.bundle_sha256,)).fetchone()
                if row is None:
                    raise ValueError("observation is missing its signed manifest")
                manifest, publisher = authenticate(self._policy, row[0], now, admission=True)
                if not isinstance(manifest, SignedManifest):
                    raise ValueError("observation must reference a signed manifest")
                check_observation(record.body, grant, manifest.body, publisher)
            count, = db.execute("SELECT count(*) FROM status_records").fetchone()
            if count >= MAX_HISTORY:
                # Even an unretained authorized update can make an old positive checkpoint unsafe.
                db.execute("UPDATE status_state SET blocked = 1 WHERE id = 1")
                return None
            db.execute("INSERT INTO status_records VALUES (?, ?)", (pin, wire))
            return pin

    def endorse(self, request: bytes) -> StatusProof:
        challenge = decode(Challenge, request)
        with self._transaction() as db:
            now = self._now(db)
            blocked, = db.execute("SELECT blocked FROM status_state WHERE id = 1").fetchone()
            if (blocked or challenge.policy_sha256 != self._policy_sha256
                    or challenge.scope.cohort != self._policy.cohort
                    or not challenge.issued_at <= now < challenge.issued_at + STATUS_TTL):
                return StatusProof((), ())
            rows = db.execute("SELECT digest, wire FROM status_records ORDER BY digest").fetchall()
            if any(digest(wire) != pin for pin, wire in rows):
                return StatusProof((), ())
            head = archive_head(tuple(pin for pin, _ in rows))
            body = Endorsement(
                witness_id=self._witness_id, challenge_sha256=digest(request), head=head,
                issued_at=now, expires_at=challenge.issued_at + STATUS_TTL,
            )
            signed = SignedEndorsement(body=body, signature=self._key.sign(endorsement_bytes(body)).hex())
            return StatusProof((canonical(signed),), tuple(wire for _, wire in rows))


class RelyingStatus(_State):
    """Recompute scope and outcome from a complete, independently endorsed current view."""

    def __init__(self, path: Path, policy: StatusPolicy, audience: str, *,
                 clock: Callable[[], float] = time.time, provision: bool = False):
        self._audience = audience
        self._witnesses = {w.witness_id: w.public_key for w in policy.witnesses}
        super().__init__(path, policy, f"relying:{audience}", clock, provision=provision)

    def evaluate(self, bundle: Bundle, *, expected_bundle_sha256: str, expected_claim_sha256: str,
                 expected_environment_sha256: str, fetch: Callable[[bytes], StatusProof]) -> StatusAssessment:
        """Return Evidence only. A fresh positive binding is an input to exact local review."""
        admitted = _admit(bundle, self._policy.cohort, self._policy.trust, self._policy.profiles)
        manifest = admitted.manifest
        if (bundle.sha256 != expected_bundle_sha256 or manifest.claim_sha256 != expected_claim_sha256
                or manifest.environment_sha256 != expected_environment_sha256):
            raise ValueError("bundle mismatches the exact digest, claim or target environment")
        scope = Scope(cohort=manifest.cohort, claim_sha256=manifest.claim_sha256,
                      bundle_sha256=bundle.sha256, material_scope_sha256=material_scope(manifest))
        with self._transaction() as db:
            issued = self._now(db)
        challenge = Challenge(issued_at=issued, nonce=secrets.token_hex(32), audience=self._audience,
                              scope=scope, policy_sha256=self._policy_sha256)
        request = canonical(challenge)
        try:
            proof = fetch(request)
        except OSError:
            return StatusAssessment("inconclusive", "withheld-status")

        with self._transaction() as db:
            now = self._now(db)
            blocked, previous = db.execute("SELECT blocked, floor FROM status_state WHERE id = 1").fetchone()
            if blocked:
                return StatusAssessment("inconclusive", "conflicting-history")
            failure, head, valid_until = self._endorsements(proof, challenge, digest(request), now)
            if failure is not None:
                return StatusAssessment("inconclusive", failure)
            assert head is not None and valid_until is not None
            if (len(proof.records) != head.revision
                    or any(type(wire) is not bytes or len(wire) > MAX_RECORD for wire in proof.records)):
                return StatusAssessment("inconclusive", "withheld-records", head)
            records = sorted((digest(wire), wire) for wire in proof.records)
            pins = tuple(pin for pin, _ in records)
            if len(set(pins)) != len(pins) or archive_head(pins) != head:
                return StatusAssessment("inconclusive", "withheld-records", head)

            old = set(json.loads(previous))
            if set(pins) < old:
                return StatusAssessment("inconclusive", "stale-status", head)
            if not old.issubset(pins):
                db.execute("UPDATE status_state SET blocked = 1 WHERE id = 1")
                return StatusAssessment("inconclusive", "conflicting-history", head)
            try:
                history = _History(self._policy, records, now)
            except ValueError:
                return StatusAssessment("inconclusive", "invalid-history", head)
            if len(old) != len(pins):
                db.execute("UPDATE status_state SET floor = ? WHERE id = 1", (canonical_json(pins),))
            now = self._now(db)
            if now >= valid_until:
                return StatusAssessment("inconclusive", "stale-status", head)
            return history.assess(challenge, head, now, valid_until)

    def _endorsements(self, proof: StatusProof, challenge: Challenge, challenge_sha256: str, now: int):
        if (not isinstance(proof, StatusProof) or type(proof.endorsements) is not tuple
                or type(proof.records) is not tuple or len(proof.endorsements) > len(self._witnesses)):
            return "invalid-status", None, None
        if now >= challenge.issued_at + STATUS_TTL:
            return "stale-status", None, None
        endorsed = {}
        for wire in proof.endorsements:
            try:
                signed = decode(SignedEndorsement, wire)
                body = signed.body
                key = self._witnesses[body.witness_id]
                if body.witness_id in endorsed or body.challenge_sha256 != challenge_sha256:
                    return "invalid-status", None, None
                key.verify(bytes.fromhex(signed.signature), endorsement_bytes(body))
            except (ValueError, KeyError, InvalidSignature):
                return "invalid-status", None, None
            if not challenge.issued_at <= body.issued_at <= now < body.expires_at <= challenge.issued_at + STATUS_TTL:
                return "stale-status", None, None
            endorsed[body.witness_id] = body
        if len(endorsed) != len(self._witnesses):
            return "withheld-status", None, None
        first, second = endorsed.values()
        if first.head != second.head:
            return "divergent-status", None, None
        return None, first.head, min(first.expires_at, second.expires_at)


class _History:
    def __init__(self, policy: StatusPolicy, records: list[tuple[str, bytes]], now: int):
        self.manifests: dict[str, tuple[SignedManifest, Grant]] = {}
        self.votes: list[tuple[str, SignedAttestation, Grant]] = []
        self.withdrawals = set()
        identities = set()
        self.conflicting_ids = False
        for pin, wire in records:
            record, grant = authenticate(policy, wire, now, admission=False)
            body = record.body
            identity = (body.kind, body.issuer, body.record_id)
            if identity in identities:
                self.conflicting_ids = True
            identities.add(identity)
            if isinstance(record, SignedManifest):
                self.manifests[pin] = (record, grant)
            elif isinstance(record, SignedAttestation):
                self.votes.append((pin, record, grant))
            elif isinstance(record, SignedWithdrawal):
                self.withdrawals.add((body.target_kind, body.target_issuer, body.target_sha256))
        for _, record, grant in self.votes:
            parent = self.manifests.get(record.body.bundle_sha256)
            if parent is None:
                raise ValueError("history is missing the manifest for an observation")
            manifest, publisher = parent
            check_observation(record.body, grant, manifest.body, publisher)

    def assess(self, challenge: Challenge, head: Head, now: int, valid_until: int) -> StatusAssessment:
        def denied(reason: Reason) -> StatusAssessment:
            return StatusAssessment("inconclusive", reason, head)

        scope = challenge.scope
        if self.conflicting_ids:
            return denied("conflicting-history")
        parent = self.manifests.get(scope.bundle_sha256)
        if parent is None:
            return denied("missing-bundle")
        record, publisher = parent
        manifest = record.body
        if ("bundle", manifest.issuer, scope.bundle_sha256) in self.withdrawals:
            return denied("revoked")
        if now >= min(manifest.expires_at, publisher.expires_at):
            return denied("stale-evidence")

        comparable = {pin for pin, (signed, _) in self.manifests.items()
                      if material_scope(signed.body) == scope.material_scope_sha256}
        historical = {}
        current: dict[Outcome, dict[str, tuple[str, int]]] = {
            "reproduced": {}, "not-reproduced": {}, "inconclusive": {},
        }
        withdrawn = stale = False
        for pin, signed, grant in self.votes:
            body = signed.body
            outcome = body.observation.outcome
            if body.bundle_sha256 in comparable and outcome != "inconclusive":
                historical.setdefault(outcome, pin)
            if body.bundle_sha256 != scope.bundle_sha256:
                continue
            key_pin = digest(grant.public_key.public_bytes_raw())
            if (("attestation", body.issuer, pin) in self.withdrawals
                    or ("verifier-key", body.issuer, key_pin) in self.withdrawals):
                withdrawn = True
            elif now >= body.expires_at:
                stale = True
            else:
                current[outcome].setdefault(grant.organization, (pin, body.expires_at))

        # The authenticated append-only view makes a disagreement durable across envelope reissue,
        # withdrawal, natural expiry and relying-party restart.
        if len(historical) > 1:
            return StatusAssessment("inconclusive", "contested", head, tuple(sorted(historical.values())))
        for outcome in ("reproduced", "not-reproduced"):
            votes = current[outcome].values()
            if len(votes) < 2:
                continue
            pins = tuple(pin for pin, _ in votes)
            deadline = min(valid_until, *(end for _, end in votes))
            if outcome == "not-reproduced":
                return StatusAssessment(outcome, "quorum", head, pins, valid_until=deadline)
            binding = ReviewBinding(
                policy_sha256=challenge.policy_sha256, audience=challenge.audience, scope=scope, head=head,
                attestation_sha256=pins,
            )
            return StatusAssessment(outcome, "quorum", head, pins, binding, deadline)
        if withdrawn:
            return denied("revoked")
        if stale:
            return denied("stale-evidence")
        if len(current["inconclusive"]) >= 2:
            pins = tuple(pin for pin, _ in current["inconclusive"].values())
            return StatusAssessment("inconclusive", "inconclusive-observations", head, pins)
        return denied("insufficient-corroboration")
