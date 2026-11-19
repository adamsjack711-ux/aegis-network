"""Coordinator validation and local, independent dry-run decision logic."""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .artifact import SignedEvent, SignedFinding, SignedRevocation, canonical_bytes, event_id, event_payload, verify
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
    dry_run: bool = True
    event_id: str | None = None
    correlation_id: str | None = None
    agent_id: str | None = None


class Audit(Protocol):
    def get(self, artifact_id: str) -> Decision | None: ...
    def high_water(self, publisher_id: str) -> int: ...
    def record(self, publisher_id: str, sequence: int, decision: Decision, authenticated: bool) -> None: ...
    def is_revoked(self, publisher_id: str, artifact_id: str, digest: str) -> bool: ...
    def get_revocation(self, revocation_id: str) -> Decision | None: ...
    def record_revocation(self, publisher_id: str, sequence: int, decision: Decision, target_id: str, target_digest: str, authenticated: bool) -> None: ...


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
        key = self.publishers.authorize(envelope.revocation.publisher_id, envelope.key_id, "revocation", now)
        verify(envelope, key, now)
        created = self.repository.add(envelope)
        if created:
            self.bus.publish(envelope)
        return created


class LocalAgent:
    def __init__(self, policy: LocalPolicy, inventory: list[InventoryItem], audit: Audit):
        self.policy = policy
        self.inventory = inventory
        self.audit = audit
        self.trust = policy.trusted_publishers if isinstance(policy.trusted_publishers, TrustStore) else TrustStore.from_legacy(policy.trusted_publishers)

    def evaluate_event(self, envelope: SignedEvent, now: datetime | None = None) -> Decision:
        if isinstance(envelope, SignedRevocation):
            return self.evaluate_revocation(envelope, now)
        return self.evaluate(envelope, now)

    def evaluate(self, envelope: SignedFinding, now: datetime | None = None) -> Decision:
        finding = envelope.finding
        artifact_id = str(finding.artifact_id)
        digest = hashlib.sha256(canonical_bytes(finding)).hexdigest()
        previous = self.audit.get(artifact_id)
        if previous is not None and previous.digest != digest:
            raise ValueError("artifact ID reused with different content")

        reason = ""
        outcome = "deny"
        authenticated = False
        try:
            key = self.trust.authorize(finding.publisher_id, envelope.key_id, "finding", now)
            verify(envelope, key, now)
        except ValueError as exc:
            reason = str(exc)
        else:
            authenticated = True
            if previous is not None:
                return previous
            if finding.sequence <= self.audit.high_water(finding.publisher_id):
                reason = "stale sequence"
            elif self.audit.is_revoked(finding.publisher_id, artifact_id, digest):
                reason = "finding revoked"
            elif not self.policy.lab_authorized:
                reason = "lab not authorized"
            elif finding.mitigation_template not in self.policy.allowed_templates:
                reason = "template not allowed"
            elif not any(
                item.purl == finding.software.purl
                and item.version in finding.software.affected_versions
                for item in self.inventory
            ):
                reason = "no exact inventory match"
            else:
                outcome, reason = "allow_dry_run", "exact match and local policy allow"

        decision = Decision(artifact_id, digest, outcome, reason, event_id=artifact_id, correlation_id=artifact_id, agent_id=getattr(self.audit, "agent_id", None))
        self.audit.record(finding.publisher_id, finding.sequence, decision, authenticated)
        return decision

    def evaluate_revocation(self, envelope: SignedRevocation, now: datetime | None = None) -> Decision:
        revocation = envelope.revocation
        rid = str(revocation.revocation_id)
        target_id = str(revocation.target_artifact_id)
        digest = hashlib.sha256(canonical_bytes(revocation)).hexdigest()
        previous = self.audit.get_revocation(rid)
        if previous is not None and previous.digest != digest:
            raise ValueError("revocation ID reused with different content")
        authenticated = False
        try:
            key = self.trust.authorize(revocation.publisher_id, envelope.key_id, "revocation", now)
            verify(envelope, key, now)
        except ValueError as exc:
            outcome, reason = "deny", str(exc)
        else:
            authenticated = True
            if previous is not None:
                return previous
            if revocation.sequence <= self.audit.high_water(revocation.publisher_id):
                outcome, reason = "deny", "stale sequence"
            else:
                outcome, reason = "revoked_dry_run", revocation.reason
        decision = Decision(target_id, digest, outcome, reason, event_id=rid, correlation_id=target_id, agent_id=getattr(self.audit, "agent_id", None))
        self.audit.record_revocation(revocation.publisher_id, revocation.sequence, decision, target_id, revocation.target_sha256, authenticated)
        return decision
