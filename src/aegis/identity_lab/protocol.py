"""Private Phase 4E laboratory records. No published contracts are extended here."""

from secrets import token_hex
from time import time_ns
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from ..evidence.records import Digest, Name, Record, RecordID, canonical, digest
from ..identity import canonical_agent_id

DOMAIN = "spiffe://phase4e.test/"
PROOF_NS = 5_000_000_000
MAX_LEASE_NS = 120_000_000_000
Counter = Annotated[int, Field(ge=0, le=2**63 - 1)]
Tick = Annotated[int, Field(gt=0, le=2**63 - 1)]
Signature = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


class Denied(Exception):
    """A request failed a laboratory authorization check."""


class Unavailable(Exception):
    """A dependency or continuity check is unavailable."""


def principal(name: str) -> str:
    return DOMAIN + name


class Workload(Record):
    instance_key: Digest
    tls_keys: tuple[Digest, ...]


class Enrollment(Record):
    deployment: str
    brokers: tuple[Name, ...]
    targets: tuple[Name, ...]
    workloads: dict[Name, Workload]
    approval_key: Digest
    lease_ns: Annotated[int, Field(ge=100_000_000, le=MAX_LEASE_NS)]

    @model_validator(mode="after")
    def distinct_inventory(self):
        canonical_agent_id(self.deployment)
        roles = ["anchor", "home", "operator", "observer", *self.brokers,
                 *self.targets, *self.workloads]
        if (not self.brokers or not self.targets or not self.workloads
                or len(set(roles)) != len(roles)):
            raise ValueError("enrollment roles must be distinct and nonempty")
        signing_keys = {entry.instance_key for entry in self.workloads.values()}
        tls_keys = [key for entry in self.workloads.values() for key in entry.tls_keys]
        if (len(signing_keys) != len(self.workloads) or self.approval_key in signing_keys
                or any(not entry.tls_keys for entry in self.workloads.values())
                or len(set(tls_keys)) != len(tls_keys)):
            raise ValueError("instance, approval and transport key pins must be distinct by role")
        return self

    @property
    def binding(self) -> str:
        return digest(canonical(self))


class Claim(Record):
    deployment: str
    enrollment: Digest
    agent: Name
    broker: Name
    expected_generation: Counter
    nonce: RecordID
    expires_ns: Tick


class Assignment(Record):
    deployment: str
    enrollment: Digest
    agent: Name
    broker: Name
    generation: Counter
    claim_id: RecordID
    issued_ns: Tick
    expires_ns: Tick

    def live(self) -> bool:
        return self.issued_ns <= time_ns() < self.expires_ns


class Mutation(Record):
    assignment: Assignment
    target: Name
    expected_version: Counter
    marker: Literal["observing", "quarantined"]


class Approval(Record):
    mutation: Mutation
    expires_ns: Tick


class Command(Record):
    mutation: Mutation
    nonce: RecordID
    expires_ns: Tick


class ClaimProof(Record):
    body: Claim
    signature: Signature


class ApprovalProof(Record):
    body: Approval
    signature: Signature


class CommandProof(Record):
    body: Command
    signature: Signature


class Admission(Record):
    proof: ClaimProof
    credential_until_ns: Tick


class Write(Record):
    command: CommandProof
    approval: ApprovalProof
    credential_until_ns: Tick


class Fence(Record):
    assignment: Assignment
    target: Name


class InstalledFence(Record):
    assignment: Assignment
    boot: RecordID


class State(Record):
    enrollment: Digest
    revision: Counter
    generation: Counter
    phase: Literal["vacant", "preparing", "active"]
    assignment: Assignment | None = None

    @property
    def stamp(self) -> "Stamp":
        return Stamp(revision=self.revision, generation=self.generation, commitment=digest(canonical(self)))


class Stamp(Record):
    revision: Counter
    generation: Counter
    commitment: Digest


class Advance(Record):
    previous: Stamp
    current: Stamp


class SessionRequest(Record):
    agent: Name


def _message(body: Claim | Approval | Command) -> bytes:
    return b"AEGIS-PHASE4E-LAB/v1\0" + type(body).__name__.encode("ascii") + b"\0" + canonical(body)


def _signature(key: Ed25519PrivateKey, body: Claim | Approval | Command) -> str:
    return key.sign(_message(body)).hex()


def verify(key: str, proof: ClaimProof | ApprovalProof | CommandProof) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(proof.signature), _message(proof.body)
        )
    except (InvalidSignature, ValueError) as exc:
        raise Denied("signature does not match the enrolled role") from exc


def live_proof(expires_ns: int) -> None:
    now = time_ns()
    if not now < expires_ns <= now + PROOF_NS:
        raise Denied("proof is outside its validity window")


def make_claim(policy: Enrollment, agent: str, broker: str, generation: int,
               key: Ed25519PrivateKey) -> ClaimProof:
    body = Claim(deployment=policy.deployment, enrollment=policy.binding, agent=agent,
                 broker=broker, expected_generation=generation, nonce=token_hex(16),
                 expires_ns=time_ns() + PROOF_NS)
    return ClaimProof(body=body, signature=_signature(key, body))


def approve(mutation: Mutation, key: Ed25519PrivateKey) -> ApprovalProof:
    body = Approval(mutation=mutation, expires_ns=mutation.assignment.expires_ns)
    return ApprovalProof(body=body, signature=_signature(key, body))


def command(mutation: Mutation, key: Ed25519PrivateKey) -> CommandProof:
    body = Command(mutation=mutation, nonce=token_hex(16),
                   expires_ns=min(time_ns() + PROOF_NS, mutation.assignment.expires_ns))
    return CommandProof(body=body, signature=_signature(key, body))
