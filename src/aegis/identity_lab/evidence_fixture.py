"""Local-only composition with the native Evidence appraisal and synthetic writer."""

from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from dataclasses import dataclass
import sqlite3
from time import monotonic_ns, time_ns
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..evidence.records import Digest, Record, canonical
from ..journal.protocol import JournalBlocked
from ..mitigation.policy import Denied as NativeDenied, Plan
from ..phase3c import EvidenceGate
from .protocol import Denied, Mutation, Signature, Tick, Unavailable, Write
from .services import Target
from .transport import Peer

_APPROVAL_DOMAIN = b"AEGIS-IDENTITY-LAB-EVIDENCE-APPROVAL/v1\x00"


class NativeCut(Record):
    agent_id: str
    finding_id: str
    finding_sha256: Digest
    bundle_sha256: Digest
    attestation_sha256: tuple[Digest, ...]
    mesh_checkpoint_sha256: Digest
    evidence_status_sha256: Digest


class EvidenceApproval(Record):
    kind: Literal["aegis.identity-lab.evidence-approval.v1"] = "aegis.identity-lab.evidence-approval.v1"
    mutation: Mutation
    native_plan_sha256: Digest
    cut: NativeCut
    expires_ns: Tick


class SignedEvidenceApproval(Record):
    body: EvidenceApproval
    signature: Signature


def sign_evidence_approval(approval: EvidenceApproval, local_key: Ed25519PrivateKey) -> SignedEvidenceApproval:
    """The disposable local operator signs the exact context they reviewed."""
    return SignedEvidenceApproval(body=approval, signature=local_key.sign(
        _APPROVAL_DOMAIN + canonical(approval)).hex())


@dataclass(frozen=True)
class NativeAppraisal:
    """Configured locally with the native gate and its prepared disposable plan."""

    gate: EvidenceGate
    plan: Plan

    @contextmanager
    def verified_cut(self):
        if self.gate.journal is None or self.gate.independent_evidence is None:
            raise Denied("the local native gate requires witnessed history and independent Evidence")
        try:
            with self.gate.authorize(self.plan) as context:
                yield NativeCut.model_validate(context)
        except (NativeDenied, JournalBlocked, ValueError) as exc:
            raise Denied("local native appraisal is unavailable or no longer current") from exc

    def _deadline_under_guard(self, approval_expires_ns: int) -> int:
        # The native authorization context holds the gate lock through commit.
        return min(self.gate._fresh_until, self.gate.valid_until_ns,
                   self.plan.expires_ns, approval_expires_ns)


@dataclass
class _PendingWrite:
    target: "EvidenceBoundTarget"
    approval: EvidenceApproval
    appraisal: NativeAppraisal
    guards: ExitStack
    assignment_issued_ns: int
    identity_deadline_ns: int
    native_deadline_ns: int = 0
    commit_checked: bool = False
    commit_denial: Exception | None = None

    def check_current(self) -> None:
        if monotonic_ns() >= self.native_deadline_ns:
            raise Denied("bound Evidence authorization reached its exclusive deadline")
        status_current = self.appraisal.gate.status_current()
        if monotonic_ns() >= self.native_deadline_ns:
            raise Denied("bound Evidence authorization reached its exclusive deadline")
        if not self.assignment_issued_ns <= time_ns() < self.identity_deadline_ns:
            raise Denied("bound identity validity window has closed")
        if not status_current:
            raise Denied("bound Evidence or witnessed cut is no longer current")

    def authorize_sql(self, action, operation, _unused, _database, _trigger):
        if action == sqlite3.SQLITE_TRANSACTION and operation == "COMMIT":
            try:
                self.check_current()
            except Exception as exc:
                self.commit_denial = exc
                return sqlite3.SQLITE_DENY
            self.commit_checked = True
        return sqlite3.SQLITE_OK


_pending: ContextVar[_PendingWrite | None] = ContextVar("local_evidence_write", default=None)


class EvidenceBoundTarget(Target):
    """Explicit fixture writer. Neither the ordinary RPC nor the base lab instantiates it."""

    def write(self, peer: Peer, request: Write) -> dict:
        raise Denied("this fixture requires the local Evidence-bound entry point")

    def write_verified(self, peer: Peer, request: Write, approval: SignedEvidenceApproval,
                       appraisal: NativeAppraisal) -> dict:
        body = approval.body
        command = request.command.body
        if (body.mutation != command.mutation
                or body.native_plan_sha256 != appraisal.plan.digest):
            raise Denied("local Evidence approval must bind the exact mutation and native plan")
        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.policy.approval_key))
            key.verify(bytes.fromhex(approval.signature), _APPROVAL_DOMAIN + canonical(body))
        except (InvalidSignature, ValueError) as exc:
            raise Denied("Evidence approval signature does not match the local operator") from exc
        assignment = command.mutation.assignment
        identity_deadline = min(request.approval.body.expires_ns, request.credential_until_ns,
                                peer.expires_ns, assignment.expires_ns, command.expires_ns)
        with ExitStack() as guards:
            pending = _PendingWrite(self, body, appraisal, guards, assignment.issued_ns, identity_deadline)
            token = _pending.set(pending)
            try:
                result = super().write(peer, request)
                if not pending.commit_checked:
                    raise RuntimeError("reviewed SQLite commit guard was not called")
                return result
            except Unavailable as exc:
                if pending.commit_denial is not None:
                    if isinstance(pending.commit_denial, Denied):
                        raise pending.commit_denial from exc
                    raise Denied("local native precommit verification failed") from pending.commit_denial
                raise
            finally:
                _pending.reset(token)

    def apply(self, db: sqlite3.Connection, request: Write) -> dict:
        pending = _pending.get()
        if pending is None or pending.target is not self:
            raise Denied("the writer transaction has no local Evidence appraisal")
        cut = pending.guards.enter_context(pending.appraisal.verified_cut())
        if cut != pending.approval.cut or cut.agent_id != request.command.body.mutation.assignment.deployment:
            raise Denied("local Evidence cut differs from the exact approval or deployment")
        pending.native_deadline_ns = pending.appraisal._deadline_under_guard(pending.approval.expires_ns)
        pending.check_current()
        # B's explicit commit follows its final ownership RPC and takes the
        # loss mutex. Keep the native guard open and veto that same commit.
        db.set_authorizer(pending.authorize_sql)
        return super().apply(db, request)
