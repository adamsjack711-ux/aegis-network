"""Strict, immutable research records distinct from signed Aegis findings."""

import hashlib
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SourceSnapshot(Record):
    kind: Literal["nvd", "osv", "kev", "vendor-ghsa"]
    acquisition: Literal["fixture", "https"] = "fixture"
    uri: str = Field(min_length=1, max_length=2048)
    retrieved_at: datetime
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content: bytes = Field(repr=False)

    @model_validator(mode="after")
    def valid_snapshot(self):
        if self.retrieved_at.tzinfo is None or hashlib.sha256(self.content).hexdigest() != self.sha256:
            raise ValueError("snapshot time or content digest invalid")
        return self


class SourceRef(Record):
    kind: Literal["nvd", "osv", "kev", "vendor-ghsa"]
    acquisition: Literal["fixture", "https"]
    uri: str
    retrieved_at: datetime
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    pointer: str


class VersionClaim(Record):
    scheme: Literal["exact", "osv", "cpe", "vendor-range", "none"]
    value: str = ""
    events: tuple[tuple[str, str], ...] = ()
    fixed: str | None = None


class Claim(Record):
    vulnerability_id: str
    aliases: tuple[str, ...] = ()
    identity_kind: Literal["purl", "ecosystem", "cpe", "vendor-product", "unknown"]
    identity: str
    versions: tuple[VersionClaim, ...]
    severity: str | None = None
    severity_score: float | None = None
    severity_details: tuple[tuple[str, str, float | None], ...] = ()
    exploited: bool | None = None
    confidence: Literal["official-record", "aggregated", "vendor-published", "fixture"]
    missing: tuple[str, ...] = ()
    summary: str = Field(default="", max_length=4000)
    published_at: str | None = None
    modified_at: str | None = None
    withdrawn_at: str | None = None
    reference: SourceRef


class Asset(Record):
    asset_id: str = Field(pattern=r"^[a-zA-Z0-9._-]{1,80}$")
    identity_kind: Literal["purl", "ecosystem", "cpe", "vendor-product"]
    identity: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=128)
    configuration: str | None = None


class Assessment(Record):
    asset_id: str
    vulnerability_id: str
    outcome: Literal["affected", "unaffected", "unknown", "conflicting"]
    reasons: tuple[str, ...]
    references: tuple[SourceRef, ...]
