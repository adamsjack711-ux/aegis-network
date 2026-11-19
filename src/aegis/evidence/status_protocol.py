"""Phase 4D lab encoding and admission rules for independent Evidence status."""

import json
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field

from . import runner
from .records import (
    Attestation, Digest, Grant, Manifest, Name, Observation, Record, SignedAttestation, SignedManifest,
    SignedRecord, SignedWithdrawal, Timestamp, Trust, canonical, decode, digest, sign_record,
)
from .service import Bundle, Verifier, _admit

STATUS_TTL = 10
ATTESTATION_TTL = 60
MAX_HISTORY = 256
STATUS_DOMAIN = b"AEGIS-EVIDENCE-STATUS/v1\x00"


class Scope(Record):
    cohort: Name
    claim_sha256: Digest
    bundle_sha256: Digest
    material_scope_sha256: Digest


class Challenge(Record):
    kind: Literal["aegis.evidence.status-challenge.v1"] = "aegis.evidence.status-challenge.v1"
    policy_sha256: Digest
    audience: Name
    scope: Scope
    nonce: Digest
    issued_at: Timestamp


class Head(Record):
    revision: Annotated[int, Field(ge=0, le=MAX_HISTORY)]
    root_sha256: Digest


class Endorsement(Record):
    kind: Literal["aegis.evidence.status-endorsement.v1"] = "aegis.evidence.status-endorsement.v1"
    witness_id: Name
    challenge_sha256: Digest
    head: Head
    issued_at: Timestamp
    expires_at: Timestamp


class SignedEndorsement(Record):
    body: Endorsement
    signature: Annotated[str, Field(pattern=r"^[a-f0-9]{128}$")]


class ReviewBinding(Record):
    kind: Literal["aegis.evidence.review-binding.v1"] = "aegis.evidence.review-binding.v1"
    policy_sha256: Digest
    audience: Name
    scope: Scope
    head: Head
    outcome: Literal["reproduced"] = "reproduced"
    attestation_sha256: tuple[Digest, ...]


@dataclass(frozen=True)
class WitnessGrant:
    witness_id: str
    organization: str
    public_key: Ed25519PublicKey


@dataclass(frozen=True)
class StatusPolicy:
    """Locally provisioned policy. Organization claims are inputs from trusted enrollment."""

    stream: str
    cohort: str
    coordinator_org: str
    local_authority_org: str
    trust: Trust
    witnesses: tuple[WitnessGrant, WitnessGrant]
    profiles: frozenset[runner.WorkerProfile] = frozenset({runner.LOCAL_PROFILE})

    def __post_init__(self):
        witnesses = self.witnesses
        grants = self.cohort_grants
        witness_keys = {w.public_key.public_bytes_raw() for w in witnesses}
        witness_orgs = {w.organization for w in witnesses}
        applications = {g.organization for g in grants}
        publishers = {g.organization for g in grants if g.role == "submitter"}
        verifiers = {g.organization for g in grants if g.role == "verifier"}
        revokers = {g.organization for g in grants if g.role == "revoker"}
        if (len(witnesses) != 2 or len({w.witness_id for w in witnesses if w.witness_id}) != 2
                or len(witness_keys) != 2 or len(witness_orgs - {""}) != 2 or witness_orgs & applications
                or witness_keys & {g.public_key.public_bytes_raw() for g in self.trust.grants.values()}):
            raise ValueError("status witnesses need distinct independently enrolled organizations and keys")
        if (not self.stream or not self.cohort or not self.profiles or not self.coordinator_org
                or not self.local_authority_org or not publishers or not revokers or len(verifiers) < 2
                or self.coordinator_org in witness_orgs | verifiers | revokers
                or self.local_authority_org in witness_orgs | applications | {self.coordinator_org}
                or publishers & (verifiers | revokers) or verifiers & revokers):
            raise ValueError("coordinator, verification, revocation and local authority overlap or are incomplete")

    @property
    def cohort_grants(self) -> tuple[Grant, ...]:
        return tuple(g for g in self.trust.grants.values() if self.cohort in g.cohorts)

    @property
    def sha256(self) -> str:
        return digest(canonical_json([
            "aegis.evidence.status-policy.v1", self.stream, self.cohort, self.coordinator_org,
            self.local_authority_org, STATUS_TTL, ATTESTATION_TTL, MAX_HISTORY,
            sorted((w.witness_id, w.organization, w.public_key.public_bytes_raw().hex()) for w in self.witnesses),
            sorted((g.issuer, g.key_id, g.organization, g.role, g.public_key.public_bytes_raw().hex(),
                    g.not_before, g.expires_at, sorted(g.withdrawal_issuers), sorted(g.withdrawal_kinds))
                   for g in self.cohort_grants),
            sorted((p.environment_sha256, p.check_sha256, p.oracle_sha256) for p in self.profiles),
        ]))


def canonical_json(value) -> bytes:
    # The existing Evidence encoding for protocol arrays and hashed manifest fields.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def material_scope(manifest: Manifest) -> str:
    return digest(canonical_json(manifest.model_dump(
        mode="json", exclude={"issuer", "key_id", "record_id", "issued_at", "expires_at"},
    )))


def archive_head(digests: tuple[str, ...]) -> Head:
    return Head(
        revision=len(digests),
        root_sha256=digest(STATUS_DOMAIN + b"archive\x00" + b"".join(bytes.fromhex(pin) for pin in digests)),
    )


def endorsement_bytes(body: Endorsement) -> bytes:
    return STATUS_DOMAIN + b"endorsement\x00" + canonical(body)


class EvidencePolicy(Protocol):
    @property
    def cohort(self) -> str: ...

    @property
    def trust(self) -> Trust: ...

    @property
    def profiles(self) -> frozenset[runner.WorkerProfile]: ...


def authenticate(policy: EvidencePolicy, wire: bytes, now: int, *, admission: bool) -> tuple[SignedRecord, Grant]:
    schemas = ((SignedManifest, "submitter"), (SignedAttestation, "verifier"), (SignedWithdrawal, "revoker"))
    for schema, role in schemas:
        try:
            record = decode(schema, wire)
        except ValueError:
            continue
        body = record.body
        if body.cohort != policy.cohort or now < body.issued_at:
            raise ValueError("Evidence record has the wrong cohort or a future issue time")
        # Both status operators vouch for current admission. Historical appraisal still checks
        # the original role, signature and scope under the same pinned trust epoch.
        grant = policy.trust.authorize(record, role, now if admission else body.issued_at)
        if isinstance(record, SignedWithdrawal) and (
            body.target_issuer not in grant.withdrawal_issuers or body.target_kind not in grant.withdrawal_kinds
        ):
            raise ValueError("withdrawal is outside the independent revoker's scope")
        if isinstance(record, SignedManifest) and runner.WorkerProfile.from_manifest(body) not in policy.profiles:
            raise ValueError("manifest does not pin an enrolled worker profile")
        return record, grant
    raise ValueError("invalid Evidence record")


def check_observation(attestation: Attestation, verifier: Grant, manifest: Manifest, publisher: Grant) -> None:
    if (verifier.organization == publisher.organization
            or not max(verifier.not_before, manifest.issued_at) <= attestation.started_at
            or attestation.expires_at > min(attestation.issued_at + ATTESTATION_TTL, manifest.expires_at,
                                            verifier.expires_at, publisher.expires_at)):
        raise ValueError("observation is outside its independent verification grant or exact bundle window")


def observe(policy: StatusPolicy, verifier: Verifier, bundle: Bundle, *, clock, timeout: float = 2.0) -> bytes:
    """Run the registered fixture using one verifier's key and return its exact signed observation."""
    admitted = _admit(bundle, policy.cohort, policy.trust, policy.profiles)
    grant = policy.trust.grants.get((verifier.issuer, verifier.key_id))
    if (grant is None or grant.role != "verifier" or policy.cohort not in grant.cohorts
            or grant.public_key.public_bytes_raw() != verifier.private_key.public_key().public_bytes_raw()):
        raise ValueError("signer is not an enrolled verifier for this cohort")
    started = int(clock())
    manifest = admitted.manifest
    deadline = min(manifest.expires_at, admitted.submitter.expires_at, grant.expires_at)
    if not max(manifest.issued_at, grant.not_before) <= started < deadline:
        raise ValueError("bundle or verifier is outside the run window")
    try:
        observation = runner.run(manifest, admitted.objects, timeout)
    except runner.WorkerFailure:
        observation = Observation(outcome="inconclusive", reason="oracle-unavailable",
                                  positive_control=False, negative_control=False)
    now = int(clock())
    if not started <= now < deadline:
        raise ValueError("verification finished outside the run window")
    body = Attestation(
        kind="aegis.evidence.attestation.v1", record_id=uuid4().hex, issuer=verifier.issuer,
        key_id=verifier.key_id, cohort=manifest.cohort, issued_at=now, started_at=started,
        expires_at=min(now + ATTESTATION_TTL, deadline), bundle_sha256=bundle.sha256, observation=observation,
    )
    check_observation(body, grant, manifest, admitted.submitter)
    return sign_record(body, verifier.private_key)
