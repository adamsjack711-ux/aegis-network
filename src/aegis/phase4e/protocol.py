"""Phase 4E-C wire contracts and pinned role, time, and cohort policy."""

from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, TypeAdapter

from ..artifact import SignedRevocation, StrictModel, event_id, event_payload, parse_event
from ..evidence import runner
from ..evidence.records import SignedWithdrawal, Trust
from ..evidence.status_protocol import Scope, authenticate
from ..journal.protocol import (Hash, JournalBlocked, Name, Policy, Receipt, SignedHead, Vote,
                                canonical, digest)
from ..trust import PublisherGrant, TrustStore

MAX_RECORDS = 256
MAX_ORDINARY = MAX_RECORDS - 8
MAX_WIRE = 8192
Signature = Annotated[str, Field(pattern=r"^[a-f0-9]{128}$")]
Millisecond = Annotated[int, Field(strict=True, ge=0, le=253402300799000)]


class Wire(StrictModel, frozen=True):
    lane: Literal["mesh", "evidence"]
    payload: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})+$", max_length=2 * MAX_WIRE)]

    @classmethod
    def from_bytes(cls, lane, wire):
        return cls(lane=lane, payload=wire.hex())

    @property
    def raw(self):
        return bytes.fromhex(self.payload)


class Leaf(StrictModel, frozen=True):
    wire: Wire
    receipt: Receipt


class Snapshot(StrictModel, frozen=True):
    leaves: Annotated[tuple[Leaf, ...], Field(max_length=MAX_RECORDS)]


class Subject(StrictModel, frozen=True):
    audience: Name
    finding: Hash
    scope: Scope
    environment: Hash


class Challenge(StrictModel, frozen=True):
    context: Hash
    subject: Subject
    nonce: Hash
    issued_ms: Millisecond


class View(StrictModel, frozen=True):
    signed: SignedHead
    coverage: Vote
    signature: Signature


class WithdrawalView(StrictModel, frozen=True):
    witness: Name
    leaves: Annotated[tuple[Leaf, ...], Field(max_length=MAX_RECORDS)]
    signature: Signature


class Status(StrictModel, frozen=True):
    challenge: Hash
    head: Hash
    outcome: Literal["reproduced", "not-reproduced", "inconclusive"]
    reason: str
    attestations: tuple[Hash, ...]
    expires_ms: Millisecond


class SignedStatus(StrictModel, frozen=True):
    body: Status
    signature: Signature


class Floor(StrictModel, frozen=True):
    context: Hash
    verified: SignedHead | None = None
    pending: SignedHead | None = None
    fork: tuple[SignedHead, SignedHead] | None = None


@dataclass(frozen=True)
class Authority:
    domain: str
    key: Ed25519PublicKey


class TrustPolicy:
    def __init__(self, *, stream, cohort, coordinator, publisher, witnesses, quorum, faults,
                 epoch_seconds, max_age, status_ms, mesh_grants, mesh_domains, trust,
                 profiles=frozenset({runner.LOCAL_PROFILE}), status_profile="checkpoint-v1"):
        if (len(witnesses), quorum, faults) != (4, 3, 1):
            raise ValueError("Phase 4E-C requires three of four witness domains with one fault")
        authorities = (coordinator, publisher, *witnesses.values())
        evidence_grants = tuple(trust.grants.values())
        mesh_grants = tuple(mesh_grants)
        domains = {authority.domain for authority in authorities}
        keys = [authority.key.public_bytes_raw() for authority in authorities]
        keys += [g.public_key.public_bytes_raw() for g in (*mesh_grants, *evidence_grants)]
        if (not all(domains) or len(domains) != len(authorities) or len(set(keys)) != len(keys)
                or type(status_ms) is not int or not 0 < status_ms <= max_age * 1000 or not profiles):
            raise ValueError("separate authority domains, signing keys and a bounded status window are required")
        expected = {(g.publisher_id, g.key_id) for g in mesh_grants}
        if set(mesh_domains) != expected or any(len(g.roles) != 1 for g in mesh_grants):
            raise ValueError("Mesh key enrollment requires one role and one administrative domain")
        roles = {role: set() for role in ("publish", "verify", "revoke")}
        for g in evidence_grants:
            roles[{"submitter": "publish", "verifier": "verify", "revoker": "revoke"}[g.role]].add(g.organization)
        for g in mesh_grants:
            role = "publish" if "finding" in g.roles else "revoke"
            roles[role].add(mesh_domains[g.publisher_id, g.key_id])
        publishers, verifiers, revokers = roles.values()
        identity = TypeAdapter(Name)
        identity.validate_python(stream)
        for domain in domains | publishers | verifiers | revokers:
            identity.validate_python(domain)
        scoped_roles = {grant.role for grant in evidence_grants if cohort in grant.cohorts}
        scoped_verifiers = {grant.organization for grant in evidence_grants
                            if cohort in grant.cohorts and grant.role == "verifier"}
        if (not publishers or not revokers or not all(publishers | verifiers | revokers)
                or scoped_roles != {"submitter", "verifier", "revoker"} or len(scoped_verifiers) < 2
                or publishers & (verifiers | revokers) or verifiers & revokers
                or domains & (publishers | verifiers | revokers)):
            raise ValueError("publisher, verifier, revoker and infrastructure domains overlap or are incomplete")

        if status_profile not in ("checkpoint-v1", "withdrawal-v2"):
            raise ValueError("unknown Phase 4E-C status profile")
        self.cohort, self.publisher, self.status_ms = cohort, publisher, status_ms
        self.status_profile = status_profile
        self.trust, self.profiles = Trust(list(evidence_grants)), frozenset(profiles)
        scope_pin = digest([
            "aegis-phase4e-v1" if status_profile == "checkpoint-v1" else "aegis-phase4e-withdrawal-v2",
            stream, status_ms, MAX_RECORDS, MAX_ORDINARY,
            sorted((n, w.domain) for n, w in witnesses.items()),
            coordinator.domain, publisher.domain, publisher.key.public_bytes_raw().hex(),
            sorted((p, k, d) for (p, k), d in mesh_domains.items()),
            sorted((g.issuer, g.key_id, g.public_key.public_bytes_raw().hex(), g.organization, g.role,
                    sorted(g.cohorts), g.not_before, g.expires_at, sorted(g.withdrawal_issuers),
                    sorted(g.withdrawal_kinds)) for g in evidence_grants),
            sorted((p.environment_sha256, p.check_sha256, p.oracle_sha256) for p in self.profiles),
        ])
        self.journal = Policy(scope_pin, cohort, coordinator.key, MappingProxyType({
            name: authority.key for name, authority in witnesses.items()
        }), quorum, faults, epoch_seconds, epoch_seconds, max_age, TrustStore(list(mesh_grants)))

    @property
    def context(self):
        return self.journal.context

    def authenticate(self, wire: Wire, at: float, historical=False):
        """Return the native record, conflict identities, and enrolled transport principal."""
        if wire.lane == "mesh":
            record = parse_event(wire.raw)
            if wire.raw != canonical(record):
                raise JournalBlocked("Mesh record has a noncanonical journal encoding")
            body = event_payload(record)
            grant = self.journal.trust.grants.get((body.publisher_id, record.key_id))
            if grant is None:
                raise JournalBlocked("Mesh grant unavailable")
            width = self.journal.epoch_seconds
            cutoff = (int(at // width) + 1) * width
            when = datetime.fromtimestamp(at, timezone.utc)
            if historical:
                when = max(when, body.issued_at, grant.not_before)
            if when.timestamp() >= cutoff or (grant.revoked_at and grant.revoked_at.timestamp() < cutoff):
                raise JournalBlocked("Mesh grant has no unambiguous admission interval")
            self.journal.validate_event(record, when)
            if not grant.not_before <= body.issued_at:
                raise JournalBlocked("Mesh issuance predates key enrollment")
            role = "revoke" if isinstance(record, SignedRevocation) else "publish"
            return record, (("mesh-event", event_id(record)), ("mesh-sequence", body.publisher_id, body.sequence)), (
                role, body.publisher_id, record.key_id)

        # Use the same native signature, scope and interval checks as T5. At replay,
        # the independent receipt supplies the epoch and the grant must cover admission.
        when = int(at)
        if historical:
            record, grant = authenticate(self, wire.raw, when + self.journal.epoch_seconds - 1, admission=False)
            when = max(when, record.body.issued_at, grant.not_before)
        record, grant = authenticate(self, wire.raw, when, admission=True)
        body = record.body
        role = {"submitter": "publish", "verifier": "verify", "revoker": "revoke"}[grant.role]
        return record, (("evidence", body.kind, body.issuer, body.record_id),), (role, body.issuer, body.key_id)

    def check_leaf(self, leaf, epoch):
        admission = leaf.receipt.admission
        if admission.event != digest(leaf.wire) or admission.epoch > epoch:
            raise JournalBlocked("leaf does not bind its receipt and sealed epoch")
        self.journal.check_receipt(leaf.receipt)
        return self.authenticate(leaf.wire, admission.epoch * self.journal.epoch_seconds, historical=True)

    def check_withdrawal(self, leaf, witness):
        admission = leaf.receipt.admission
        votes = leaf.receipt.votes
        if (admission.event != digest(leaf.wire) or admission.context != self.context
                or len(votes) != 1 or votes[0].operator != witness):
            raise JournalBlocked("withdrawal does not bind its enrolled witness receipt")
        self.journal.check_vote(admission, votes[0])
        record, _, _ = self.authenticate(leaf.wire, admission.epoch * self.journal.epoch_seconds, historical=True)
        if not is_withdrawal(record):
            raise JournalBlocked("withdrawal view contained a non-revocation record")
        return record

    def challenge_deadline(self, challenge, now):
        remaining = challenge.issued_ms + self.status_ms - now.upper * 1000
        if (challenge.context != self.context or challenge.subject.scope.cohort != self.cohort
                or challenge.issued_ms > now.lower * 1000 or remaining <= 0):
            raise JournalBlocked("status challenge is outside scope or freshness")
        return now.monotonic + remaining / 1000

    def expiry(self, challenge, head, now):
        return min(self.journal.deadline(head, now), self.challenge_deadline(challenge, now))


def message(purpose, value):
    return b"aegis-phase4e-v1/" + purpose.encode("ascii") + b"\0" + canonical(value)


def verify(key, purpose, value, signature):
    try:
        key.verify(bytes.fromhex(signature), message(purpose, value))
    except (InvalidSignature, ValueError) as exc:
        raise JournalBlocked("Phase 4E signature failed verification") from exc


def view_binding(challenge, signed):
    return [digest(challenge), digest(signed)]


def withdrawal_binding(challenge, witness, leaves):
    return [digest(challenge), witness, [digest(leaf) for leaf in leaves]]


def is_withdrawal(record):
    return isinstance(record, (SignedRevocation, SignedWithdrawal))
