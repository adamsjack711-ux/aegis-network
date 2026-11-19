"""Single-home identity and generation fencing for the disposable fixture."""

from dataclasses import dataclass
import json
import re
import secrets
import sqlite3
from time import monotonic_ns, time_ns
from typing import Annotated, Literal, TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field

from .evidence.records import Digest, Name, Record, RecordID, canonical, digest
from .identity import canonical_agent_id
from .mitigation.policy import Denied

if TYPE_CHECKING:
    from .mitigation.store import TargetStore

REQUEST_NS = 5_000_000_000
LEASE_NS = 10_000_000_000
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_PRINCIPAL = re.compile(r"spiffe://[a-z0-9][a-z0-9.-]*(?:/[a-zA-Z0-9_-]+)+")
Generation = Annotated[int, Field(ge=0, le=2**63 - 1)]
Tick = Annotated[int, Field(gt=0, le=2**63 - 1)]
Signature = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
Action = Literal["begin", "restrict", "verify-canary", "verify-health"]


class Assignment(Record):
    fixture: RecordID
    deployment: str
    principal: str
    holder_key: Digest
    broker: Name
    generation: Generation

    @property
    def binding(self) -> str:
        return digest(b"AEGIS-OWNERSHIP/v1\0assignment\0" + canonical(self))


class LeaseRequest(Record):
    action: Literal["claim", "renew"]
    assignment: Assignment
    nonce: RecordID
    expires_ns: Tick


class TargetCommand(Record):
    action: Action
    assignment: Assignment
    plan: Digest
    target: Name | None = None
    nonce: RecordID
    expires_ns: Tick


class LeaseProof(Record):
    body: LeaseRequest
    signature: Signature


class CommandProof(Record):
    body: TargetCommand
    signature: Signature


def _message(body: LeaseRequest | TargetCommand) -> bytes:
    domain = b"lease" if isinstance(body, LeaseRequest) else b"target-intent"
    return b"AEGIS-OWNERSHIP/v1\0" + domain + b"\0" + canonical(body)


def lease_proof(action: Literal["claim", "renew"], assignment: Assignment,
                key: Ed25519PrivateKey) -> LeaseProof:
    body = LeaseRequest(action=action, assignment=assignment, nonce=secrets.token_hex(16),
                        expires_ns=monotonic_ns() + REQUEST_NS)
    return LeaseProof(body=body, signature=key.sign(_message(body)).hex())


@dataclass(frozen=True)
class IdentitySession:
    """Local fixture runner's instance key and claimed assignment."""

    assignment: Assignment
    key: Ed25519PrivateKey

    def command(self, action: Action, plan: str, target: str | None = None) -> CommandProof:
        body = TargetCommand(action=action, assignment=self.assignment, plan=plan, target=target,
                             nonce=secrets.token_hex(16), expires_ns=monotonic_ns() + REQUEST_NS)
        return CommandProof(body=body, signature=self.key.sign(_message(body)).hex())


def _verify(row: sqlite3.Row, proof: LeaseProof | CommandProof, now: int) -> None:
    if not now < proof.body.expires_ns <= now + REQUEST_NS:
        raise Denied("identity proof is outside its request window")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(row["holder_key"]))
        key.verify(bytes.fromhex(proof.signature), _message(proof.body))
    except (ValueError, InvalidSignature) as exc:
        raise Denied("identity proof does not match the enrolled instance key") from exc


class OwnershipHome:
    """Operator-only local home sharing the enrolled target store transaction."""

    def __init__(self, store: "TargetStore") -> None:
        self.store = store

    @staticmethod
    def read(db: sqlite3.Connection) -> sqlite3.Row | None:
        if db.execute("SELECT 1 FROM sqlite_schema WHERE name = 'ownership'").fetchone() is None:
            return None
        row = db.execute("SELECT * FROM ownership WHERE id = 1").fetchone()
        if row is None:
            raise Denied("durable ownership enrollment is missing")
        return row

    @staticmethod
    def deadlines(row: sqlite3.Row) -> tuple[int, tuple[int, int]] | None:
        if OwnershipHome._live_at(row, monotonic_ns(), time_ns()):
            return row["until_ns"], (row["since_utc_ns"], row["until_utc_ns"])
        return None

    @staticmethod
    def _live_at(row, now, utc) -> bool:
        return (row["broker"] is not None and row["since_ns"] <= now < row["until_ns"]
                and row["since_utc_ns"] <= utc < row["until_utc_ns"])

    @staticmethod
    def _record(db, action, generation, *, broker=None, nonce=None, plan=None, target=None,
                holder_key=None):
        try:
            db.execute(
                "INSERT INTO ownership_audit (action, generation, broker, nonce, plan, target, holder_key) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", (action, generation, broker, nonce, plan, target, holder_key),
            )
        except sqlite3.IntegrityError as exc:
            raise Denied("identity request or command was already consumed") from exc

    def enroll(self, deployment: str, principal: str, key: Ed25519PublicKey,
               brokers: tuple[str, ...]) -> None:
        """Provision once using operator-controlled inventory and pins."""
        canonical_agent_id(deployment)
        if (len(principal) > 255 or _PRINCIPAL.fullmatch(principal) is None
                or not brokers or len(set(brokers)) != len(brokers)
                or any(_NAME.fullmatch(broker) is None for broker in brokers)):
            raise ValueError("invalid workload principal or broker allowlist")
        with self.store._transaction(write=True) as db:
            if self.read(db) is not None or self.store._rollout(db) is not None:
                raise Denied("enrollment requires a fresh fixture and cannot overwrite an identity")
            db.execute("""
                CREATE TABLE ownership (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    deployment TEXT NOT NULL, principal TEXT NOT NULL, holder_key TEXT NOT NULL,
                    brokers TEXT NOT NULL, generation INTEGER NOT NULL, retired INTEGER NOT NULL,
                    broker TEXT, since_ns INTEGER, until_ns INTEGER,
                    since_utc_ns INTEGER, until_utc_ns INTEGER, rollout_generation INTEGER
                )
            """)
            db.execute("""
                CREATE TABLE ownership_audit (
                    seq INTEGER PRIMARY KEY, action TEXT NOT NULL, generation INTEGER NOT NULL,
                    broker TEXT, nonce TEXT UNIQUE, plan TEXT, target TEXT, holder_key TEXT
                )
            """)
            holder_key = key.public_bytes_raw().hex()
            db.execute(
                "INSERT INTO ownership (id, deployment, principal, holder_key, brokers, generation, retired) "
                "VALUES (1, ?, ?, ?, ?, 0, 0)",
                (deployment, principal, holder_key, json.dumps(brokers)),
            )
            self._record(db, "enroll", 0, holder_key=holder_key)

    def _require_row(self, db):
        row = self.read(db)
        if row is None or row["retired"]:
            raise Denied("deployment is unenrolled or retired")
        return row

    def _assignment(self, db, row, broker: str) -> Assignment:
        if broker not in json.loads(row["brokers"]):
            raise Denied("broker is outside the deployment enrollment")
        return Assignment(fixture=self.store._lab_id(db), deployment=row["deployment"],
                          principal=row["principal"], holder_key=row["holder_key"],
                          broker=broker, generation=row["generation"])

    def candidate(self, broker: str) -> Assignment:
        """Public metadata to sign; does not carry authority."""
        with self.store._transaction() as db:
            return self._assignment(db, self._require_row(db), broker)

    def accept(self, proof: LeaseProof, *, peer_principal: str, broker: str) -> Assignment:
        """Admit through a trusted local adapter; peer and broker come from that adapter."""
        if (not isinstance(proof, LeaseProof) or not isinstance(proof.body, LeaseRequest)
                or proof.body.action not in {"claim", "renew"}):
            raise Denied("ownership home requires a lease request proof")
        offered = proof.body.assignment
        if offered.principal != peer_principal or offered.broker != broker:
            raise Denied("authenticated peer or broker does not match the signed request")
        with self.store._transaction(write=True) as db:
            row = self._require_row(db)
            request = proof.body
            if offered != self._assignment(db, row, offered.broker):
                raise Denied("lease request differs from the current enrollment or generation")
            _verify(row, proof, monotonic_ns())
            now, utc = monotonic_ns(), time_ns()
            if now >= request.expires_ns:
                raise Denied("lease request expired while being checked")
            current = self._live_at(row, now, utc)
            if request.action == "claim":
                if current:
                    raise Denied("deployment already has a current authoritative broker")
                # A lease whose time became uncertain must be explicitly fenced.
                if row["broker"] is not None and (
                    now < row["since_ns"] or utc < row["since_utc_ns"]
                ):
                    raise Denied("ownership clock is uncertain")
                generation = row["generation"] + 1
            else:
                if not current or row["broker"] != offered.broker:
                    raise Denied("only the current broker assignment may renew")
                generation = row["generation"]
            self._record(db, request.action, generation, broker=offered.broker, nonce=request.nonce)
            db.execute(
                "UPDATE ownership SET generation = ?, broker = ?, since_ns = ?, until_ns = ?, "
                "since_utc_ns = ?, until_utc_ns = ? WHERE id = 1",
                (generation, offered.broker, now, now + LEASE_NS, utc, utc + LEASE_NS),
            )
            return offered.model_copy(update={"generation": generation})

    def _invalidate(self, action: str, expected_generation: int,
                    replacement: Ed25519PublicKey | None = None) -> int:
        with self.store._transaction(write=True) as db:
            row = self._require_row(db)
            if row["generation"] != expected_generation:
                raise Denied("operator lifecycle request used a stale generation")
            generation = expected_generation + 1
            key = row["holder_key"] if replacement is None else replacement.public_bytes_raw().hex()
            if replacement is not None and db.execute(
                "SELECT 1 FROM ownership_audit WHERE holder_key = ?", (key,)
            ).fetchone() is not None:
                raise Denied("rotation requires a previously unused instance key")
            db.execute(
                "UPDATE ownership SET generation = ?, holder_key = ?, broker = NULL, retired = ? WHERE id = 1",
                (generation, key, int(action == "retire")),
            )
            self._record(db, action, generation, holder_key=key if replacement is not None else None)
            return generation

    def fence(self, expected_generation: int) -> int:
        """Operator ends the assignment before moving to another enrolled broker."""
        return self._invalidate("fence", expected_generation)

    def rotate(self, expected_generation: int, replacement: Ed25519PublicKey) -> int:
        """Operator replaces a lost or compromised instance key and fences its grants."""
        return self._invalidate("rotate", expected_generation, replacement)

    def retire(self, expected_generation: int) -> int:
        """Operator permanently retires the deployment at this home."""
        return self._invalidate("retire", expected_generation)

    def _require_current(self, db, row, assignment: Assignment) -> tuple[int, tuple[int, int]]:
        if assignment != self._assignment(db, row, assignment.broker) or row["broker"] != assignment.broker:
            raise Denied("assignment generation, broker or holder is stale")
        deadlines = self.deadlines(row)
        if deadlines is None:
            raise Denied("ownership lease is expired or its clock is uncertain")
        return deadlines

    def check(self, assignment: Assignment) -> int:
        """Preflight only. Protected mutations check again inside their transaction."""
        with self.store._transaction() as db:
            deadline, _ = self._require_current(db, self._require_row(db), assignment)
            return deadline

    def authorize_target(self, db, row, plan, action: Action, target: str | None,
                         proof: CommandProof | None) -> Assignment:
        if (row is None or row["retired"] or not isinstance(proof, CommandProof)
                or not isinstance(proof.body, TargetCommand)):
            raise Denied("guarded target write requires an enrolled command proof")
        command = proof.body
        assignment = command.assignment
        self._require_current(db, row, assignment)
        if (plan.ownership_binding != assignment.binding or command.plan != plan.digest
                or command.action != action or command.target != target):
            raise Denied("command does not match the exact approved plan, operation and target")
        _verify(row, proof, monotonic_ns())
        if action == "begin":
            db.execute("UPDATE ownership SET rollout_generation = ? WHERE id = 1", (assignment.generation,))
        elif row["rollout_generation"] != assignment.generation:
            raise Denied("rollout belongs to a stale ownership generation")
        self._record(db, action, assignment.generation, broker=assignment.broker,
                     nonce=command.nonce, plan=command.plan, target=target)
        return assignment

    def recheck_target(self, db, assignment: Assignment, proof: CommandProof) -> None:
        self._require_current(db, self._require_row(db), assignment)
        if monotonic_ns() >= proof.body.expires_ns:
            raise Denied("command expired before the target commit")
