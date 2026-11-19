"""Strict, canonical signed findings. No executable content is accepted."""

import base64
import binascii
import json
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(StrictModel):
    uri: str = Field(min_length=1, max_length=2048)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    method: Literal["lab-reproduction", "source-review", "advisory"]


class Software(StrictModel):
    purl: str = Field(pattern=r"^pkg:[A-Za-z0-9.+-]+/[A-Za-z0-9._~%/+:-]+$", max_length=512)
    affected_versions: list[str] = Field(min_length=1, max_length=100)


class Finding(StrictModel):
    schema_version: Literal["1.0"]
    artifact_id: UUID
    publisher_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    sequence: int = Field(strict=True, gt=0)
    issued_at: datetime
    expires_at: datetime
    vulnerability_id: str = Field(min_length=1, max_length=128)
    software: Software
    evidence: list[Evidence] = Field(min_length=1, max_length=20)
    applicability: Literal["authorized-lab"]
    mitigation_template: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")

    @model_validator(mode="after")
    def validate_timing_and_versions(self):
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        if self.expires_at <= self.issued_at:
            raise ValueError("expiry must follow issue time")
        if any(not v or len(v) > 128 for v in self.software.affected_versions):
            raise ValueError("invalid affected version")
        if len(set(self.software.affected_versions)) != len(self.software.affected_versions):
            raise ValueError("duplicate affected version")
        return self


class SignedFinding(StrictModel):
    kind: Literal["finding"] = "finding"
    key_id: str = Field(default="default", pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    finding: Finding
    signature: str


class Revocation(StrictModel):
    schema_version: Literal["1.0"]
    revocation_id: UUID
    publisher_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    sequence: int = Field(strict=True, gt=0)
    issued_at: datetime
    expires_at: datetime
    target_artifact_id: UUID
    target_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: Literal["withdrawn", "invalid-evidence", "superseded"]

    @model_validator(mode="after")
    def validate_timing(self):
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        if self.expires_at <= self.issued_at:
            raise ValueError("expiry must follow issue time")
        return self


class SignedRevocation(StrictModel):
    kind: Literal["revocation"] = "revocation"
    key_id: str = Field(default="default", pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    revocation: Revocation
    signature: str


SignedEvent = SignedFinding | SignedRevocation


def canonical_bytes(finding: Finding | Revocation) -> bytes:
    return json.dumps(
        finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign(finding: Finding, private_key: Ed25519PrivateKey, key_id: str = "default") -> SignedFinding:
    signature = base64.b64encode(private_key.sign(canonical_bytes(finding))).decode("ascii")
    return SignedFinding(finding=finding, signature=signature, key_id=key_id)


def sign_revocation(revocation: Revocation, private_key: Ed25519PrivateKey, key_id: str) -> SignedRevocation:
    signature = base64.b64encode(private_key.sign(canonical_bytes(revocation))).decode("ascii")
    return SignedRevocation(revocation=revocation, signature=signature, key_id=key_id)


def event_payload(envelope: SignedEvent) -> Finding | Revocation:
    return envelope.finding if isinstance(envelope, SignedFinding) else envelope.revocation


def event_id(envelope: SignedEvent) -> str:
    payload = event_payload(envelope)
    return str(payload.artifact_id if isinstance(payload, Finding) else payload.revocation_id)


def correlation_id(envelope: SignedEvent) -> str:
    payload = event_payload(envelope)
    return str(payload.artifact_id if isinstance(payload, Finding) else payload.target_artifact_id)


def parse_event(data: bytes) -> SignedEvent:
    raw = json.loads(data)
    if not isinstance(raw, dict):
        raise ValueError("event body must be an object")
    if raw.get("kind", "finding") == "revocation":
        return SignedRevocation.model_validate(raw)
    return SignedFinding.model_validate(raw)


def verify(envelope: SignedEvent, public_key: Ed25519PublicKey, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("verification time must include a timezone")
    payload = event_payload(envelope)
    if not payload.issued_at <= now < payload.expires_at:
        raise ValueError("finding is not currently valid" if isinstance(payload, Finding) else "revocation is not currently valid")
    try:
        signature = base64.b64decode(envelope.signature, validate=True)
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        public_key.verify(signature, canonical_bytes(payload))
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise ValueError("invalid signature") from exc
