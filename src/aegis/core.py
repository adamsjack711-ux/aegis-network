"""Coordinator validation and local, independent dry-run decision logic."""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .artifact import Finding, SignedEvent, SignedFinding, SignedRevocation, canonical_bytes, verify
from .trust import TrustStore


class Repository(Protocol):
    def add(self, envelope: SignedEvent) -> bool: ...


class EventBus(Protocol):
    def publish(self, envelope: SignedEvent) -> None: ...


@dataclass(frozen=True)
class InventoryItem:
    purl: str
    version: str


@dataclass(frozen=True)
class LocalPolicy:
    trusted_publishers: TrustStore | dict[str, Ed25519PublicKey]
    allowed_templates: frozenset[str]
    lab_authorized: bool = False


@dataclass(frozen=True)
class Decision:
    artifact_id: str
    digest: str
    outcome: str
    reason: str
    reason_code: str
    dry_run: bool = True
    event_id: str | None = None
    correlation_id: str | None = None
    agent_id: str | None = None


class Audit(Protocol):
    def get(self, artifact_id: str) -> Decision | None: ...
    def high_water(self, publisher_id: str) -> int: ...
    def sequence_owner(self, publisher_id: str, sequence: int) -> str | None: ...
    def record(self, publisher_id: str, sequence: int, decision: Decision, authenticated: bool) -> None: ...
    def record_override(self, decision: Decision) -> Decision: ...
    def is_revoked(self, publisher_id: str, artifact_id: str, digest: str) -> bool: ...
    def get_revocation(self, revocation_id: str) -> Decision | None: ...
    def record_revocation(self, publisher_id: str, sequence: int, decision: Decision, target_id: str, target_digest: str, target_publisher_id: str | None, authenticated: bool) -> None: ...


REJECTION_CODES = {
    "unknown publisher key": "UNKNOWN_PUBLISHER_KEY",
    "publisher key lacks role": "PUBLISHER_ROLE_DENIED",
    "publisher key outside validity interval": "PUBLISHER_KEY_INVALID_TIME",
    "publisher key revoked": "PUBLISHER_KEY_REVOKED",
    "finding is not currently valid": "FINDING_INVALID_TIME",
    "revocation is not currently valid": "REVOCATION_INVALID_TIME",
    "invalid signature": "INVALID_SIGNATURE",
    "revocation target publisher outside grant scope": "REVOCATION_SCOPE_DENIED",
    "revocation target publisher is required": "REVOCATION_SCOPE_UNBOUND",
}


def _rejection_code(exc: ValueError) -> str:
    return REJECTION_CODES.get(str(exc), "INVALID_EVENT")


class Coordinator:
    def __init__(self, publishers: TrustStore | dict[str, Ed25519PublicKey], repository: Repository, bus: EventBus):
        self.publishers = publishers if isinstance(publishers, TrustStore) else TrustStore.from_legacy(publishers)
        self.repository = repository
        self.bus = bus

    def submit(self, envelope: SignedFinding, now: datetime | None = None) -> bool:
        key = self.publishers.authorize(envelope.finding.publisher_id, envelope.key_id, "finding", now)
        verify(envelope, key, now)
        created = self.repository.add(envelope)
        if created:
            self.bus.publish(envelope)
        return created

    def revoke(self, envelope: SignedRevocation, now: datetime | None = None) -> bool:
        target_publisher_id = envelope.revocation.target_publisher_id
        if target_publisher_id is None:
            raise ValueError("revocation target publisher is required")
        key = self.publishers.authorize_revocation(
            envelope.revocation.publisher_id, envelope.key_id, target_publisher_id, now)
        verify(envelope, key, now)
        created = self.repository.add(envelope)
        if created:
            self.bus.publish(envelope)
        return created


class LocalAgent:
    def __init__(self, policy: LocalPolicy, inventory: list[InventoryItem], audit: Audit):
        self.policy = policy
        # The local inventory is exact identity data. No URL, range, or prefix
        # interpretation is performed on evidence supplied by a publisher.
        self.inventory = frozenset((item.purl, item.version) for item in inventory)
        self.audit = audit
        self.trust = policy.trusted_publishers if isinstance(policy.trusted_publishers, TrustStore) else TrustStore.from_legacy(policy.trusted_publishers)

    def _local_denial(self, finding: Finding) -> tuple[str, str] | None:
        if not self.policy.lab_authorized:
            return "lab not authorized", "LAB_NOT_AUTHORIZED"
        if finding.mitigation_template not in self.policy.allowed_templates:
            return "template not allowed", "TEMPLATE_NOT_ALLOWED"
        if not any((finding.software.purl, version) in self.inventory
                   for version in finding.software.affected_versions):
            return "no exact inventory match", "INVENTORY_NO_EXACT_MATCH"
        return None

    def evaluate_event(self, envelope: SignedEvent, now: datetime | None = None) -> Decision:
        if isinstance(envelope, SignedRevocation):
            return self.evaluate_revocation(envelope, now)
        return self.evaluate(envelope, now)

    def evaluate(self, envelope: SignedFinding, now: datetime | None = None) -> Decision:
        finding = envelope.finding
        artifact_id = str(finding.artifact_id)
        digest = hashlib.sha256(canonical_bytes(finding)).hexdigest()
        previous = self.audit.get(artifact_id)
        reason = ""
        reason_code = "INVALID_EVENT"
        outcome = "deny"
        authenticated = False
        try:
            key = self.trust.authorize(finding.publisher_id, envelope.key_id, "finding", now)
            verify(envelope, key, now)
        except ValueError as exc:
            reason = str(exc)
            reason_code = _rejection_code(exc)
        else:
            if previous is not None and previous.digest != digest:
                reason, reason_code = "artifact ID conflict", "ARTIFACT_ID_CONFLICT"
            elif (owner := self.audit.sequence_owner(finding.publisher_id, finding.sequence)) is not None and owner != artifact_id:
                reason, reason_code = "publisher sequence conflict", "PUBLISHER_SEQUENCE_CONFLICT"
            elif self.audit.is_revoked(finding.publisher_id, artifact_id, digest):
                # A revocation changes the effective result of an old finding.
                # Its own durable audit row supplies the history of that change.
                if previous is not None:
                    return Decision(artifact_id, digest, "deny", "finding revoked",
                                    reason_code="FINDING_REVOKED", event_id=artifact_id,
                                    correlation_id=artifact_id, agent_id=getattr(self.audit, "agent_id", None))
                authenticated = True
                reason, reason_code = "finding revoked", "FINDING_REVOKED"
            elif previous is not None:
                if previous.outcome == "allow_dry_run":
                    denial = self._local_denial(finding)
                    if denial is not None:
                        reason, reason_code = denial
                        return self.audit.record_override(Decision(
                            artifact_id, digest, "deny", reason, reason_code,
                            event_id=artifact_id, correlation_id=artifact_id,
                            agent_id=getattr(self.audit, "agent_id", None),
                        ))
                return previous
            else:
                authenticated = True
                if finding.sequence <= self.audit.high_water(finding.publisher_id):
                    reason, reason_code = "stale sequence", "STALE_SEQUENCE"
                else:
                    denial = self._local_denial(finding)
                    if denial is None:
                        outcome, reason, reason_code = (
                            "allow_dry_run", "exact match and local policy allow", "EXACT_MATCH_ALLOWED"
                        )
                    else:
                        reason, reason_code = denial

        decision = Decision(artifact_id, digest, outcome, reason, reason_code=reason_code,
                            event_id=artifact_id, correlation_id=artifact_id,
                            agent_id=getattr(self.audit, "agent_id", None))
        self.audit.record(finding.publisher_id, finding.sequence, decision, authenticated)
        return decision

    def evaluate_revocation(self, envelope: SignedRevocation, now: datetime | None = None) -> Decision:
        now = now or datetime.now(timezone.utc)
        revocation = envelope.revocation
        rid = str(revocation.revocation_id)
        target_id = str(revocation.target_artifact_id)
        digest = hashlib.sha256(canonical_bytes(revocation)).hexdigest()
        previous = self.audit.get_revocation(rid)
        authenticated = False
        try:
            key = self.trust.authorize(revocation.publisher_id, envelope.key_id, "revocation", now)
            if revocation.issued_at > now:
                raise ValueError("revocation is not currently valid")
            # A withdrawal is permanent. Retained signed revocations can be
            # recovered after their submission window while the key is still trusted.
            verify(envelope, key, revocation.issued_at)
        except ValueError as exc:
            outcome, reason, reason_code = "deny", str(exc), _rejection_code(exc)
        else:
            if previous is not None and previous.digest != digest:
                outcome, reason, reason_code = "deny", "revocation ID conflict", "REVOCATION_ID_CONFLICT"
            elif previous is not None:
                return previous
            elif revocation.target_publisher_id is None:
                outcome, reason, reason_code = "deny", "revocation target publisher is required", "REVOCATION_SCOPE_UNBOUND"
            else:
                try:
                    self.trust.authorize_revocation(
                        revocation.publisher_id, envelope.key_id, revocation.target_publisher_id, now)
                except ValueError as exc:
                    outcome, reason, reason_code = "deny", str(exc), _rejection_code(exc)
                else:
                    owner = self.audit.sequence_owner(revocation.publisher_id, revocation.sequence)
                    if owner is not None and owner != rid:
                        outcome, reason, reason_code = "deny", "publisher sequence conflict", "PUBLISHER_SEQUENCE_CONFLICT"
                    else:
                        # A valid late revocation must still withdraw its exact target.
                        authenticated = True
                        outcome, reason, reason_code = "revoked_dry_run", revocation.reason, "REVOCATION_ACCEPTED"
        decision = Decision(target_id, digest, outcome, reason, reason_code=reason_code,
                            event_id=rid, correlation_id=target_id, agent_id=getattr(self.audit, "agent_id", None))
        self.audit.record_revocation(revocation.publisher_id, revocation.sequence, decision, target_id,
                                     revocation.target_sha256, revocation.target_publisher_id, authenticated)
        return decision
