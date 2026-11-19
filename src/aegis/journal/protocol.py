"""Wire records, pinned quorum policy and historical Mesh validation."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from threading import RLock
import time
from types import MappingProxyType
from typing import Annotated, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StringConstraints, TypeAdapter

from ..artifact import SignedEvent, SignedRevocation, StrictModel, event_id, event_payload, verify
from ..recovery import RecoveryBlocked
from ..trust import TrustStore
from .merkle import EMPTY, MAX_SIZE

Hash = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Name = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
Epoch = Annotated[int, Field(strict=True, ge=0, le=2**31 - 1)]
Index = Annotated[int, Field(strict=True, ge=0, le=MAX_SIZE)]
Envelope = Annotated[SignedEvent, Field(discriminator="kind")]


class JournalBlocked(RecoveryBlocked):
    """History cannot be used for permissive decisions."""


def canonical(value) -> bytes:
    if isinstance(value, StrictModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return sha256(canonical(value)).hexdigest()


class Vote(StrictModel, frozen=True):
    operator: Name
    signature: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]


Votes = Annotated[tuple[Vote, ...], Field(max_length=32)]
Proof = Annotated[tuple[Hash, ...], Field(max_length=64)]


class Admission(StrictModel, frozen=True):
    context: Hash
    epoch: Epoch
    event: Hash


class Receipt(StrictModel, frozen=True):
    admission: Admission
    votes: Votes


class Leaf(StrictModel, frozen=True):
    receipt: Receipt
    envelope: Envelope


class Head(StrictModel, frozen=True):
    context: Hash
    epoch: Epoch
    size: Index
    root: Hash


class SignedHead(StrictModel, frozen=True):
    head: Head
    signature: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]


class Cut(StrictModel, frozen=True):
    signed: SignedHead
    votes: Votes

    @property
    def head(self):
        return self.signed.head


class Entry(StrictModel, frozen=True):
    index: Index
    leaf: Leaf
    proof: Proof


def _message(record) -> bytes:
    domain = {Admission: b"aegis-journal-v1/admission", Head: b"aegis-journal-v1/head",
              SignedHead: b"aegis-journal-v1/coverage"}[type(record)]
    return domain + b"\x00" + canonical(record)


def vote(operator, key, record) -> Vote:
    return Vote(operator=operator, signature=key.sign(_message(record)).hex())


def sign_head(key, head: Head) -> SignedHead:
    return SignedHead(head=head, signature=key.sign(_message(head)).hex())


def check_signature(key, record, signature):
    try:
        key.verify(bytes.fromhex(signature), _message(record))
    except (InvalidSignature, ValueError) as exc:
        raise JournalBlocked("journal signature failed verification") from exc


@dataclass(frozen=True)
class Time:
    lower: float
    upper: float
    monotonic: float


class Clock:
    """The deployment supplies synchronized UTC or raises when time is uncertain."""

    def __init__(self, wall=time.time, monotonic=time.monotonic, error: float = 0.0):
        if not math.isfinite(error) or error < 0:
            raise ValueError("invalid clock error")
        self.wall, self.monotonic, self.error = wall, monotonic, error
        self._last = None
        self._lock = RLock()

    def sample(self) -> Time:
        with self._lock:
            monotonic = self.monotonic()
            utc = self.wall()
            if not math.isfinite(utc) or not math.isfinite(monotonic) or utc < 0:
                raise JournalBlocked("journal clock is uncertain")
            if self._last is not None:
                old_utc, old_mono = self._last
                if monotonic < old_mono or utc + 2 * self.error < old_utc:
                    raise JournalBlocked("journal clock rolled back")
                utc_high = max(old_utc, utc)
            else:
                utc_high = utc
            self._last = utc_high, monotonic
            return Time(utc - self.error, utc + self.error, monotonic)


@dataclass(frozen=True)
class Policy:
    log_id: str
    cohort: str
    coordinator: Ed25519PublicKey
    operators: Mapping[str, Ed25519PublicKey]
    quorum: int
    faults: int
    epoch_seconds: int
    merge_seconds: int
    max_age: int
    trust: TrustStore
    context: str = field(init=False)

    def __post_init__(self):
        identity = TypeAdapter(Name)
        identity.validate_python(self.log_id)
        identity.validate_python(self.cohort)
        roster = dict(self.operators)
        for name in roster:
            identity.validate_python(name)
        keys = [self.coordinator.public_bytes_raw(), *(key.public_bytes_raw() for key in roster.values())]
        if len(set(keys)) != len(keys):
            raise ValueError("each authority requires its own signing key")
        n = len(roster)
        numbers = (self.quorum, self.faults, self.epoch_seconds, self.merge_seconds, self.max_age)
        if (any(type(value) is not int for value in numbers)
                or not 0 <= self.faults < self.quorum <= n <= 32
                or 2 * self.quorum - n <= self.faults or self.quorum > n - self.faults):
            raise ValueError("quorum requires honest intersection and fault tolerance")
        if not 0 < self.epoch_seconds <= 3600 or not 0 < self.merge_seconds <= self.max_age <= 3600:
            raise ValueError("invalid journal time budget")
        pinned = TrustStore(list(self.trust.grants.values()))
        pinned.grants = MappingProxyType(pinned.grants)
        object.__setattr__(self, "trust", pinned)
        object.__setattr__(self, "operators", MappingProxyType(roster))
        grants = [
            [publisher, key_id, grant.public_key.public_bytes_raw().hex(), sorted(grant.roles),
             grant.not_before.isoformat(), grant.expires_at.isoformat(),
             grant.revoked_at.isoformat() if grant.revoked_at else None, sorted(grant.revocation_publishers)]
            for (publisher, key_id), grant in sorted(pinned.grants.items())
        ]
        object.__setattr__(self, "context", digest([
            "aegis-journal-v1", self.log_id, self.cohort, keys[0].hex(),
            [[name, key.public_bytes_raw().hex()] for name, key in sorted(roster.items())],
            *numbers, grants,
        ]))

    def cutoff(self, epoch: int) -> int:
        return (epoch + 1) * self.epoch_seconds

    def deadline(self, head: Head, now: Time) -> float:
        cutoff = self.cutoff(head.epoch)
        remaining = cutoff + self.max_age - now.upper
        if cutoff > now.lower or remaining <= 0:
            raise JournalBlocked("checkpoint cutoff is future or stale")
        return now.monotonic + remaining

    def check_votes(self, record, votes: tuple[Vote, ...]) -> None:
        names = [item.operator for item in votes]
        if len(names) < self.quorum or names != sorted(set(names)):
            raise JournalBlocked("journal votes lack a distinct canonical quorum")
        for item in votes:
            self.check_vote(record, item)

    def check_vote(self, record, item: Vote) -> None:
        key = self.operators.get(item.operator)
        if key is None:
            raise JournalBlocked("journal vote is outside the pinned roster")
        check_signature(key, record, item.signature)

    def valid_votes(self, record, responses) -> tuple[Vote, ...]:
        votes = {}
        for response in responses:
            try:
                self.check_vote(record, response)
            except JournalBlocked:
                continue
            votes[response.operator] = response
        return tuple(votes[name] for name in sorted(votes))

    def check_head(self, signed: SignedHead) -> None:
        head = signed.head
        if head.context != self.context or (head.size == 0 and head.root != EMPTY.hex()):
            raise JournalBlocked("checkpoint is outside the pinned history")
        check_signature(self.coordinator, head, signed.signature)

    def check_cut(self, cut: Cut) -> None:
        self.check_head(cut.signed)
        self.check_votes(cut.signed, cut.votes)

    def check_receipt(self, receipt: Receipt) -> None:
        if receipt.admission.context != self.context:
            raise JournalBlocked("receipt is outside the pinned history")
        self.check_votes(receipt.admission, receipt.votes)

    def validate_event(self, envelope: SignedEvent, now: datetime) -> None:
        payload = event_payload(envelope)
        try:
            if isinstance(envelope, SignedRevocation):
                if payload.target_publisher_id is None:
                    raise ValueError("withdrawal requires signed target publisher scope")
                key = self.trust.authorize_revocation(payload.publisher_id, envelope.key_id,
                                                     payload.target_publisher_id, now)
            else:
                key = self.trust.authorize(payload.publisher_id, envelope.key_id, "finding", now)
            verify(envelope, key, now)
        except ValueError as exc:
            raise JournalBlocked(f"journal event failed Mesh validation: {exc}") from exc

    def check_leaf(self, leaf: Leaf, epoch: int) -> None:
        admission = leaf.receipt.admission
        if admission.epoch > epoch or admission.event != digest(leaf.envelope):
            raise JournalBlocked("leaf does not bind its claimed admission")
        self.check_receipt(leaf.receipt)
        payload = event_payload(leaf.envelope)
        grant = self.trust.grants.get((payload.publisher_id, leaf.envelope.key_id))
        cutoff = datetime.fromtimestamp(self.cutoff(admission.epoch), timezone.utc)
        if grant is None or (grant.revoked_at is not None and grant.revoked_at < cutoff):
            raise JournalBlocked("historical grant is missing or compromise overlaps the admission epoch")
        start = datetime.fromtimestamp(admission.epoch * self.epoch_seconds, timezone.utc)
        when = max(start, payload.issued_at, grant.not_before)
        if when >= cutoff:
            raise JournalBlocked("no eligible admission time in epoch")
        self.validate_event(leaf.envelope, when)


def event_keys(leaf: Leaf):
    envelope = leaf.envelope
    payload = event_payload(envelope)
    return event_id(envelope), (payload.publisher_id, payload.sequence)
