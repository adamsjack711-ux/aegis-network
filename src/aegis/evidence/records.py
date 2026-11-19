"""Canonical wire records and locally pinned Evidence trust."""

import base64
import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_RECORD = 8192
MAX_OBJECT = 4096
Name = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
RecordID = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
Timestamp = Annotated[int, Field(ge=0, le=253402300799)]
Role = Literal["submitter", "verifier", "revoker"]
TargetKind = Literal["bundle", "attestation", "verifier-key"]
Outcome = Literal["reproduced", "not-reproduced", "inconclusive"]
MaterialRole = Literal["subject", "configuration", "dependencies", "recipe"]
MATERIAL_ROLES: tuple[MaterialRole, ...] = ("subject", "configuration", "dependencies", "recipe")


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class IssuedRecord(Record):
    record_id: RecordID
    issuer: Name
    key_id: Name
    cohort: Name
    issued_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def valid_interval(self):
        if self.issued_at >= self.expires_at:
            raise ValueError("invalid record validity interval")
        return self


class ObjectPin(Record):
    sha256: Digest
    size: Annotated[int, Field(gt=0, le=MAX_OBJECT)]


class Materials(Record):
    subject: ObjectPin
    configuration: ObjectPin
    dependencies: ObjectPin
    recipe: ObjectPin


class Manifest(IssuedRecord):
    kind: Literal["aegis.evidence.bundle.v1"]
    claim_sha256: Digest
    family: Literal["feature-gate", "route-toggle", "service-access", "portability-marker"]
    materials: Materials
    environment_sha256: Digest
    check_sha256: Digest
    oracle_sha256: Digest


class Observation(Record):
    outcome: Outcome
    reason: Literal["marker-observed", "marker-absent", "oracle-unavailable", "control-failed"]
    positive_control: bool
    negative_control: bool

    @model_validator(mode="after")
    def consistent_result(self):
        if self.positive_control and self.negative_control:
            expected = {"marker-observed": "reproduced", "marker-absent": "not-reproduced"}
            if expected.get(self.reason) != self.outcome:
                raise ValueError("observation disagrees with passing controls")
        elif self.outcome != "inconclusive" or self.reason not in {"oracle-unavailable", "control-failed"}:
            raise ValueError("unhealthy controls require an inconclusive result")
        return self


class Attestation(IssuedRecord):
    kind: Literal["aegis.evidence.attestation.v1"]
    bundle_sha256: Digest
    started_at: Timestamp
    observation: Observation

    @model_validator(mode="after")
    def valid_run(self):
        if self.started_at > self.issued_at:
            raise ValueError("run started after attestation issuance")
        return self


class Withdrawal(IssuedRecord):
    kind: Literal["aegis.evidence.withdrawal.v1"]
    target_kind: TargetKind
    target_sha256: Digest
    target_issuer: Name
    reason: Literal["invalid-evidence", "superseded", "key-compromised", "withdrawn"]


class SignedManifest(Record):
    body: Manifest
    signature: Annotated[str, Field(min_length=88, max_length=88)]


class SignedAttestation(Record):
    body: Attestation
    signature: Annotated[str, Field(min_length=88, max_length=88)]


class SignedWithdrawal(Record):
    body: Withdrawal
    signature: Annotated[str, Field(min_length=88, max_length=88)]


SignedRecord = SignedManifest | SignedAttestation | SignedWithdrawal


def canonical(record: Record) -> bytes:
    return json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode[T: Record](schema: type[T], wire: bytes) -> T:
    if type(wire) is not bytes or len(wire) > MAX_RECORD:
        raise ValueError("invalid record size or type")
    record = schema.model_validate_json(wire)
    # Comparing wire bytes rejects duplicate names and alternative JSON encodings.
    if canonical(record) != wire:
        raise ValueError("record is not canonical")
    return record


def signing_bytes(body: IssuedRecord) -> bytes:
    return b"AEGIS-EVIDENCE\x00" + canonical(body)


def sign_record(body: Manifest | Attestation | Withdrawal, key: Ed25519PrivateKey) -> bytes:
    signature = base64.b64encode(key.sign(signing_bytes(body))).decode("ascii")
    if isinstance(body, Manifest):
        return canonical(SignedManifest(body=body, signature=signature))
    if isinstance(body, Attestation):
        return canonical(SignedAttestation(body=body, signature=signature))
    return canonical(SignedWithdrawal(body=body, signature=signature))


@dataclass(frozen=True)
class Grant:
    issuer: str
    key_id: str
    organization: str
    role: Role
    public_key: Ed25519PublicKey
    cohorts: frozenset[str]
    not_before: int
    expires_at: int
    withdrawal_issuers: frozenset[str] = frozenset()
    withdrawal_kinds: frozenset[TargetKind] = frozenset()


class Trust:
    def __init__(self, grants: list[Grant]):
        by_id = {(grant.issuer, grant.key_id): grant for grant in grants}
        if len(by_id) != len(grants) or len({g.public_key.public_bytes_raw() for g in grants}) != len(grants):
            raise ValueError("a trust key must belong to exactly one identity and role")
        organizations = {}
        for grant in grants:
            if organizations.setdefault(grant.issuer, grant.organization) != grant.organization:
                raise ValueError("one issuer cannot belong to multiple organizations")
            if not grant.organization or not grant.cohorts or not 0 <= grant.not_before < grant.expires_at:
                raise ValueError("invalid grant")
        self.grants = MappingProxyType(by_id)

    def authorize(self, record: SignedRecord, role: Role, now: int) -> Grant:
        body = record.body
        grant = self.grants.get((body.issuer, body.key_id))
        if grant is None or grant.role != role or body.cohort not in grant.cohorts:
            raise ValueError("untrusted issuer, role or cohort")
        if not grant.not_before <= body.issued_at <= now < min(body.expires_at, grant.expires_at):
            raise ValueError("record or grant outside its validity interval")
        try:
            signed = base64.b64decode(record.signature, validate=True)
            if base64.b64encode(signed).decode("ascii") != record.signature:
                raise ValueError("noncanonical signature")
            grant.public_key.verify(signed, signing_bytes(body))
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("invalid evidence signature") from exc
        return grant
