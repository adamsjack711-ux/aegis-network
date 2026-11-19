"""Fresh status publication and relying appraisal across independent endpoints."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import combinations
import math
import secrets
from threading import RLock

from ..artifact import SignedFinding, SignedRevocation
from ..evidence.records import digest as digest_bytes
from ..evidence.service import _admit
from ..evidence.status import EvidenceHistory
from ..evidence.status_protocol import (Challenge as EvidenceChallenge, Head as EvidenceHead, Scope,
                                        material_scope)
from ..journal.client import finding_target
from ..journal.protocol import Cut, JournalBlocked, canonical, digest
from ..phase3c import check_bundle, claim_bytes
from .history import reconcile
from .protocol import (Challenge, Floor, SignedStatus, Status, Subject, Wire, message, verify,
                       view_binding)


def _view(fetch, challenge, operator, policy):
    try:
        view = fetch(challenge)
        journal = policy.journal
        if view.coverage.operator != operator:
            raise JournalBlocked("witness endpoint returned another operator")
        journal.check_head(view.signed)
        journal.check_vote(view.signed, view.coverage)
        verify(journal.operators[operator], "view", view_binding(challenge, view.signed), view.signature)
        return view
    except (JournalBlocked, OSError, ValueError):
        return None


def _fork(left, right):
    return ((left.epoch == right.epoch and left != right)
            or (left.size == right.size and left.root != right.root)
            or (left.epoch < right.epoch and left.size > right.size)
            or (right.epoch < left.epoch and right.size > left.size))


class Reader:
    def __init__(self, policy, witnesses, archives, pin, clock):
        if set(witnesses) != set(policy.journal.operators) or not archives:
            raise ValueError("reader requires pinned witness endpoints and at least one archive")
        self.policy, self.witnesses, self.archives, self.pin, self.clock = policy, witnesses, archives, pin, clock
        self.lock = RLock()

    def _views(self, challenge):
        with ThreadPoolExecutor(max_workers=len(self.witnesses)) as pool:
            requests = [pool.submit(_view, fetch, challenge, name, self.policy)
                        for name, fetch in self.witnesses.items()]
        return tuple(view for job in requests if (view := job.result()) is not None)

    def read(self, challenge):
        with self.lock:
            return self._read(challenge)

    def _read(self, challenge):
        original = self.pin.read()
        floor = Floor.model_validate_json(original)
        if original != canonical(floor) or floor.context != self.policy.context or floor.fork:
            raise JournalBlocked("protected status floor is conflicted or outside its pinned history")
        views = self._views(challenge)
        known = tuple(cut for cut in (floor.verified, floor.pending) if cut is not None)
        candidates = tuple(dict.fromkeys(view.signed for view in views))
        for left, right in combinations((*known, *candidates), 2):
            if _fork(left.head, right.head):
                self.pin.advance(original, canonical(floor.model_copy(update={"fork": (left, right)})))
                raise JournalBlocked("conflicting signed checkpoints retained at the protected floor")
        if not candidates:
            raise JournalBlocked("no current independent checkpoint quorum")
        signed = max(candidates, key=lambda candidate: candidate.head.epoch)
        votes = tuple(sorted((view.coverage for view in views if view.signed == signed),
                             key=lambda vote: vote.operator))
        self.policy.journal.check_cut(Cut(signed=signed, votes=votes))
        head = signed.head
        deadline = self.policy.expiry(challenge, head, self.clock.sample())
        latest = floor.pending or floor.verified
        if latest and head.epoch < latest.head.epoch:
            raise JournalBlocked("checkpoint rolls back the protected status floor")

        # Never make a previously observed quorum cut disappear if replay fails.
        # A further cut can advance only after the outstanding pin is resolved.
        if floor.pending and floor.pending != signed:
            prefix = reconcile(self.archives, self.policy, floor.pending.head)
            prefix.require_extension(floor.verified.head if floor.verified else None, floor.pending.head)
            floor = Floor(context=self.policy.context, verified=floor.pending)
            updated = canonical(floor)
            self.pin.advance(original, updated)
            original = updated
        if signed != floor.verified and signed != floor.pending:
            updated = canonical(floor.model_copy(update={"pending": signed}))
            self.pin.advance(original, updated)
            original = updated

        history = reconcile(self.archives, self.policy, head)
        # A complete authenticated prefix at the selected head gives a proof
        # against every previously seen or currently reported older cut.
        for earlier in dict.fromkeys((*known, *candidates)):
            if earlier == signed:
                continue
            try:
                history.require_extension(earlier.head, head)
            except JournalBlocked:
                fork = floor.model_copy(update={"pending": signed, "fork": (earlier, signed)})
                self.pin.advance(original, canonical(fork))
                raise
        updated = canonical(Floor(context=self.policy.context, verified=signed))
        if original != updated:
            self.pin.advance(original, updated)
        elif self.pin.read() != original:
            raise JournalBlocked("protected status floor changed during replay")
        return head, history, min(deadline, self.policy.expiry(challenge, head, self.clock.sample())), updated


def appraise(policy, challenge, head, history, now):
    subject = challenge.subject
    until = min(challenge.issued_ms + policy.status_ms,
                (policy.journal.cutoff(head.epoch) + policy.journal.max_age) * 1000)

    def status(outcome, reason, pins=()):
        return Status(challenge=digest(challenge), head=digest(head), outcome=outcome, reason=reason,
                      attestations=tuple(sorted(pins)), expires_ms=until)

    entry = history.events.get(subject.finding)
    if entry is None or not isinstance(entry[1], SignedFinding):
        return status("inconclusive", "missing-finding")
    _, finding = entry
    if any(isinstance(event, SignedRevocation) and
           (event.revocation.target_publisher_id, str(event.revocation.target_artifact_id),
            event.revocation.target_sha256) == finding_target(finding)
           for _, event in history.events.values()):
        return status("inconclusive", "mesh-withdrawn")
    grant = policy.journal.trust.grants[finding.finding.publisher_id, finding.key_id]
    try:
        policy.journal.validate_event(finding, datetime.fromtimestamp(now, timezone.utc))
    except JournalBlocked:
        return status("inconclusive", "stale-finding")
    until = min(until, int(min(finding.finding.expires_at, grant.expires_at,
                               grant.revoked_at or grant.expires_at).timestamp() * 1000))
    records = [(digest_bytes(leaf.wire.raw), leaf.wire.raw) for leaf, _ in history.events.values()
               if leaf.wire.lane == "evidence"]
    evidence = EvidenceHistory(policy, sorted(records), math.floor(now))
    parent = evidence.manifests.get(subject.scope.bundle_sha256)
    if parent is None:
        return status("inconclusive", "missing-bundle")
    signed, publisher = parent
    manifest = signed.body
    if (subject.scope.claim_sha256 != manifest.claim_sha256
            or manifest.claim_sha256 != digest_bytes(claim_bytes(finding.finding))
            or subject.scope.material_scope_sha256 != material_scope(manifest)
            or subject.environment != manifest.environment_sha256
            or not any(ref.sha256 == subject.scope.bundle_sha256 for ref in finding.finding.evidence)):
        return status("inconclusive", "scope-mismatch")
    until = min(until, 1000 * min(manifest.expires_at, publisher.expires_at))
    request = EvidenceChallenge(policy_sha256=policy.context, audience=subject.audience,
                                scope=subject.scope, nonce=challenge.nonce, issued_at=challenge.issued_ms // 1000)
    result = evidence.assess(request, EvidenceHead(revision=head.size, root_sha256=head.root),
                             math.floor(now), (until + 999) // 1000)
    if result.valid_until is not None:
        until = min(until, result.valid_until * 1000)
    return status(result.outcome, result.reason, result.attestation_sha256)


class Publisher:
    def __init__(self, reader, key):
        if key.public_key() != reader.policy.publisher.key:
            raise ValueError("status signing key does not match pinned enrollment")
        self.reader, self.key = reader, key

    def publish(self, challenge):
        with self.reader.lock:
            head, history, deadline, floor = self.reader.read(challenge)
            now = self.reader.clock.sample()
            body = appraise(self.reader.policy, challenge, head, history, now.upper)
            if (self.reader.clock.monotonic() >= deadline
                    or now.upper * 1000 >= body.expires_ms or self.reader.pin.read() != floor):
                raise JournalBlocked("status expired or advanced before publication")
            return SignedStatus(body=body, signature=self.key.sign(message("status", body)).hex())


@dataclass(frozen=True)
class VerifiedStatus:
    body: Status
    binding: str
    deadline: float
    floor: bytes


class Gate:
    """Appraise exact materials and independent signed status before each protected write."""

    def __init__(self, reader, fetch_status, audience):
        self.reader, self.fetch_status, self.audience = reader, fetch_status, audience
        self._status = None

    def refresh(self, finding, bundle, *, expected_environment):
        with self.reader.lock:
            self._status = None
            self._status = self._refresh(finding, bundle, expected_environment=expected_environment)
            return self._status

    def _refresh(self, finding, bundle, *, expected_environment):
        policy = self.reader.policy
        admitted = _admit(bundle, policy.cohort, policy.trust, policy.profiles)
        check_bundle(finding.finding, bundle)
        subject = Subject(audience=self.audience, finding=digest(finding_wire(finding)),
                          environment=expected_environment,
                          scope=Scope(cohort=policy.cohort, claim_sha256=admitted.manifest.claim_sha256,
                                      bundle_sha256=bundle.sha256,
                                      material_scope_sha256=material_scope(admitted.manifest)))
        now = self.reader.clock.sample()
        challenge = Challenge(context=policy.context, subject=subject, nonce=secrets.token_hex(32),
                              issued_ms=math.floor(now.lower * 1000))
        # First observe and retain the independent witness floor even if status publication fails.
        head, history, deadline, floor = self.reader.read(challenge)
        signed = self.fetch_status(challenge)
        verify(policy.publisher.key, "status", signed.body, signed.signature)
        now = self.reader.clock.sample()
        expected = appraise(policy, challenge, head, history, now.upper)
        if signed.body != expected:
            raise JournalBlocked("published status disagrees with current scoped witnessed appraisal")
        remaining = expected.expires_ms / 1000 - now.upper
        if remaining <= 0 or now.monotonic >= deadline or self.reader.pin.read() != floor:
            raise JournalBlocked("status expired or advanced during appraisal")
        binding = digest([policy.context, subject.model_dump(mode="json"), expected.head,
                          expected.outcome, expected.attestations])
        return VerifiedStatus(expected, binding, min(deadline, now.monotonic + remaining), floor)

    def require_current(self, status):
        now = self.reader.clock.sample()
        if (status is not self._status or status.body.outcome != "reproduced" or now.monotonic >= status.deadline
                or now.upper * 1000 >= status.body.expires_ms or self.reader.pin.read() != status.floor):
            raise JournalBlocked(f"no current enforcement authority: {status.body.reason}")

    @contextmanager
    def authorize(self, status, reviewed_binding):
        with self.reader.lock:
            try:
                if status.binding != reviewed_binding:
                    raise JournalBlocked("exact status binding changed since review")
                self.require_current(status)
                yield
            finally:
                self._status = None


def finding_wire(finding):
    return Wire.from_bytes("mesh", canonical(finding))
