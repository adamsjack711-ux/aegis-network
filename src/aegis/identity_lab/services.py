"""Durable home, independent continuity anchor, brokers and synthetic writers."""

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
from pathlib import Path
from secrets import token_hex
import sqlite3
import sys
from time import monotonic_ns, time_ns

from pydantic import BaseModel

from ..evidence.records import Record, canonical
from .protocol import (
    Admission, Advance, Assignment, ClaimProof, Denied, Enrollment, Fence, InstalledFence,
    SessionRequest, Stamp, State, Unavailable, Write, live_proof, verify,
)
from .transport import AuthenticationFailed, Client, Endpoint, Peer


@contextmanager
def transaction(path: Path):
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=2)
    try:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except sqlite3.Error as exc:
        raise Unavailable("durable store unavailable") from exc
    finally:
        db.close()  # rolls back an incomplete transaction


def initialize(path: Path, role: str, policy: Enrollment) -> None:
    """Provision once, offline. A missing store at service startup never bootstraps."""
    state = State(enrollment=policy.binding, generation=0, revision=0, phase="vacant")
    path.touch(mode=0o600, exist_ok=False)
    with transaction(path) as db:
        db.execute("CREATE TABLE record (id INTEGER PRIMARY KEY CHECK (id=1), body BLOB)")
        initial = state.stamp if role == "anchor" else state
        db.execute("INSERT INTO record VALUES (1, ?)", (canonical(initial),))
        if role in policy.targets:
            db.execute("UPDATE record SET body=NULL WHERE id=1")
            db.execute("CREATE TABLE receipts (nonce TEXT PRIMARY KEY, generation INTEGER, marker TEXT)")
            db.execute("CREATE TABLE marker (id INTEGER PRIMARY KEY CHECK (id=1), "
                       "version INTEGER NOT NULL, value TEXT NOT NULL)")
            db.execute("INSERT INTO marker VALUES (1, 0, 'quarantined')")


def load(db: sqlite3.Connection, model: type[BaseModel]):
    row = db.execute("SELECT body FROM record WHERE id=1").fetchone()
    if row is None:
        raise Unavailable("durable record missing")
    return model.model_validate_json(row[0]) if row[0] is not None else None


def save(db: sqlite3.Connection, record: Record) -> None:
    db.execute("UPDATE record SET body=? WHERE id=1", (canonical(record),))


def remote(client: Client, endpoint: Endpoint, path: str, body: Record | None = None) -> dict:
    try:
        return client.call(endpoint, path, body)
    except AuthenticationFailed as exc:
        raise Unavailable("dependency TLS authentication failed") from exc


@dataclass
class Anchor:
    path: Path

    def dispatch(self, peer: Peer, route: str, raw: bytes) -> Stamp:
        with transaction(self.path) as db:
            stamp = load(db, Stamp)
            if route == "/stamp":
                peer.require("home", "operator")
                return stamp
            if route == "/advance":
                peer.require("home")
                advance = Advance.model_validate_json(raw)
                if (advance.previous != stamp or advance.current.revision != stamp.revision + 1
                        or advance.current.generation not in (stamp.generation, stamp.generation + 1)):
                    raise Denied("anchor compare-and-swap failed")
                save(db, advance.current)
                return advance.current
        raise Denied("operation outside anchor scope")


@dataclass
class Home:
    path: Path
    policy: Enrollment
    client: Client
    endpoints: dict[str, Endpoint]

    def anchor(self) -> Stamp:
        return Stamp.model_validate(remote(self.client, self.endpoints["anchor"], "/stamp"))

    def checked(self, db: sqlite3.Connection) -> State:
        state = load(db, State)
        if state.enrollment != self.policy.binding or state.stamp != self.anchor():
            raise Unavailable("ownership state is behind its independent anchor")
        return state

    def publish(self, db: sqlite3.Connection, previous: Stamp, state: State) -> None:
        advance = Advance(previous=previous, current=state.stamp)
        result = remote(self.client, self.endpoints["anchor"], "/advance", advance)
        if Stamp.model_validate(result) != advance.current:
            raise Unavailable("anchor did not record the expected state")
        save(db, state)

    def prepare(self, peer: Peer, admission: Admission) -> Assignment:
        claim = admission.proof.body
        peer.require(claim.broker)
        holder = self.policy.workloads.get(claim.agent)
        if (claim.broker not in self.policy.brokers or holder is None
                or claim.deployment != self.policy.deployment or claim.enrollment != self.policy.binding):
            raise Denied("claim is outside the enrollment")
        verify(holder.instance_key, admission.proof)
        with transaction(self.path) as db:
            state = self.checked(db)
            live_proof(claim.expires_ns)
            now = time_ns()
            credential_until = min(admission.credential_until_ns, peer.expires_ns)
            if now >= credential_until:
                raise Denied("credential expired before admission")
            previous = state.assignment
            if previous is not None and now < previous.issued_ns:
                raise Unavailable("home clock precedes the last assignment")
            if previous is not None and previous.live():
                same_holder = (previous.agent == claim.agent and previous.broker == claim.broker
                               and claim.expected_generation + 1 == state.generation)
                if same_holder and (state.phase == "preparing" or previous.claim_id == claim.nonce):
                    return previous
                raise Denied("another assignment is active or preparing")
            if claim.expected_generation != state.generation:
                raise Denied("claim presents a retired generation")
            assignment = Assignment(
                deployment=claim.deployment, enrollment=claim.enrollment, agent=claim.agent,
                broker=claim.broker, generation=state.generation + 1, claim_id=claim.nonce,
                issued_ns=now, expires_ns=min(now + self.policy.lease_ns, credential_until),
            )
            pending = State(enrollment=self.policy.binding, revision=state.revision + 1,
                            generation=assignment.generation, phase="preparing", assignment=assignment)
            self.publish(db, state.stamp, pending)
            return assignment

    def claim(self, peer: Peer, admission: Admission) -> Assignment:
        assignment = self.prepare(peer, admission)
        with transaction(self.path) as db:
            state = self.checked(db)
            if state.assignment != assignment or not assignment.live():
                raise Denied("assignment changed during transfer")
            if state.phase == "active":
                live_proof(admission.proof.body.expires_ns)
                return assignment

        # Never hold the home lock here. A writer may hold its own mutation lock while
        # asking the home to authorize a prior in-flight write.
        barrier_started = monotonic_ns()
        for target in self.policy.targets:
            started = monotonic_ns()
            fence = Fence(assignment=assignment, target=target)
            receipt = remote(self.client, self.endpoints[target], "/fence", fence)
            if Fence.model_validate(receipt) != fence:
                raise Unavailable("target returned a different fence receipt")
            receipt_at = monotonic_ns()
            print(json.dumps({"event": "fence-receipt", "generation": assignment.generation,
                              "target": target, "rpc_ns": receipt_at - started,
                              "barrier_ns": receipt_at - barrier_started}), file=sys.stderr, flush=True)

        with transaction(self.path) as db:
            state = self.checked(db)
            live_proof(admission.proof.body.expires_ns)
            peer.require(assignment.broker)
            if state.assignment != assignment or not assignment.live():
                raise Denied("assignment changed or expired during fencing")
            if time_ns() >= admission.credential_until_ns:
                raise Denied("claim credential expired during fencing")
            if state.phase == "preparing":
                active = state.model_copy(update={"phase": "active", "revision": state.revision + 1})
                self.publish(db, state.stamp, active)
        return assignment

    def recover(self, peer: Peer, expected: Stamp) -> Stamp:
        peer.require("operator")
        with transaction(self.path) as db:
            anchor = self.anchor()
            if anchor != expected:
                raise Denied("operator recovery stamp has changed")
            local = load(db, State)
            if (local.enrollment != self.policy.binding or local.revision > anchor.revision
                    or local.generation > anchor.generation):
                raise Unavailable("anchor does not cover the local ownership floor")
            state = State(enrollment=self.policy.binding, revision=anchor.revision + 1,
                          generation=anchor.generation + 1, phase="vacant")
            self.publish(db, anchor, state)
            return state.stamp

    def dispatch(self, peer: Peer, route: str, raw: bytes) -> Record | dict:
        if route == "/claim":
            return self.claim(peer, Admission.model_validate_json(raw))
        if route == "/recover":
            return self.recover(peer, Stamp.model_validate_json(raw))
        if route == "/status":
            peer.require("operator", *self.policy.brokers)
            with transaction(self.path) as db:
                return self.checked(db)
        if route in ("/current", "/pending"):
            peer.require(*self.policy.targets)
            expected = Fence.model_validate_json(raw)
            peer.require(expected.target)
            with transaction(self.path) as db:
                state = self.checked(db)
                required_phase = "active" if route == "/current" else "preparing"
                if (state.phase != required_phase or state.assignment != expected.assignment
                        or not state.assignment.live()):
                    raise Denied("writer request does not hold the required home assignment")
                return expected
        if route == "/session":
            peer.require(*self.policy.brokers)
            request = SessionRequest.model_validate_json(raw)
            with transaction(self.path) as db:
                state = self.checked(db)
                assignment = state.assignment
                if (state.phase != "active" or assignment.agent != request.agent
                        or not assignment.live()):
                    raise Denied("agent has no current assignment")
                peer.require(assignment.broker)
                return assignment
        raise Denied("operation outside home scope")


@dataclass
class Broker:
    name: str
    policy: Enrollment
    client: Client
    endpoints: dict[str, Endpoint]

    def agent(self, peer: Peer, name: str) -> str:
        peer.require(name)
        entry = self.policy.workloads.get(name)
        if entry is None or peer.key not in entry.tls_keys:
            raise Denied("transport key is outside the agent enrollment")
        return entry.instance_key

    def dispatch(self, peer: Peer, route: str, raw: bytes) -> Record | dict:
        if route == "/claim":
            proof = ClaimProof.model_validate_json(raw)
            key = self.agent(peer, proof.body.agent)
            if proof.body.broker != self.name:
                raise Denied("claim names a different broker")
            verify(key, proof)
            admission = Admission(proof=proof, credential_until_ns=peer.expires_ns)
            return remote(self.client, self.endpoints["home"], "/claim", admission)
        if route == "/session":
            request = SessionRequest.model_validate_json(raw)
            self.agent(peer, request.agent)
            return remote(self.client, self.endpoints["home"], "/session", request)
        if route == "/write":
            request = Write.model_validate_json(raw)
            mutation = request.command.body.mutation
            key = self.agent(peer, mutation.assignment.agent)
            if mutation.assignment.broker != self.name or mutation.target not in self.policy.targets:
                raise Denied("command is outside this broker's assignment or inventory")
            verify(key, request.command)
            forwarded = request.model_copy(update={"credential_until_ns": peer.expires_ns})
            return remote(self.client, self.endpoints[mutation.target], "/write", forwarded)
        raise Denied("operation outside broker scope")


@dataclass
class Target:
    name: str
    path: Path
    policy: Enrollment
    client: Client
    endpoints: dict[str, Endpoint]
    boot: str = field(default_factory=lambda: token_hex(16))

    def fence(self, peer: Peer, fence: Fence) -> Fence:
        peer.require("home")
        offered = fence.assignment
        if (fence.target != self.name or offered.enrollment != self.policy.binding
                or offered.deployment != self.policy.deployment or not offered.live()):
            raise Denied("fence is outside this writer's inventory or deadline")
        with transaction(self.path) as db:
            installed = load(db, InstalledFence)
            current = installed.assignment if installed else None
            if current is not None and offered != current and offered.generation <= current.generation:
                raise Denied("fence generation has been retired")
            if current == offered:
                if installed.held:
                    raise Denied("held writer requires a new generation")
                if installed.boot == self.boot:
                    return fence
            result = remote(self.client, self.endpoints["home"], "/pending", fence)
            if Fence.model_validate(result) != fence or not offered.live():
                raise Denied("home is not preparing this writer's fence")
            save(db, InstalledFence(assignment=offered, boot=self.boot))
            # During a still-preparing transfer this generation has never authorized writes.
            if current != offered:
                db.execute("UPDATE marker SET value='quarantined', version=version+1 WHERE id=1")
        return fence  # only after SQLite commits the floor and restrictive state

    def hold(self, db: sqlite3.Connection, installed: InstalledFence) -> None:
        save(db, installed.model_copy(update={"held": True}))
        db.execute("UPDATE marker SET value='quarantined', version=version+1 WHERE value<>'quarantined'")

    def require_current(self, assignment: Assignment) -> None:
        check = Fence(assignment=assignment, target=self.name)
        result = remote(self.client, self.endpoints["home"], "/current", check)
        try:
            expected = Fence.model_validate(result)
        except ValueError as exc:
            raise Unavailable("invalid home authorization response") from exc
        if expected != check or not assignment.live():
            raise Denied("home authorization differs or has expired")

    def apply(self, db: sqlite3.Connection, request: Write, deadline: int) -> dict:
        proof = request.command
        mutation = proof.body.mutation
        assignment = mutation.assignment
        if db.execute("SELECT 1 FROM receipts WHERE nonce=?", (proof.body.nonce,)).fetchone():
            raise Denied("command was already committed")
        change = db.execute("UPDATE marker SET value=?, version=version+1 WHERE id=1 AND version=?",
                            (mutation.marker, mutation.expected_version))
        if change.rowcount != 1:
            raise Denied("target version has changed")
        db.execute("INSERT INTO receipts VALUES (?, ?, ?)", (proof.body.nonce, assignment.generation,
                   mutation.marker))
        if not assignment.live() or time_ns() >= min(deadline, proof.body.expires_ns):
            raise Denied("authorization expired before the target commit")
        return {"version": mutation.expected_version + 1, "generation": assignment.generation}

    def write(self, peer: Peer, request: Write) -> dict:
        proof = request.command
        approval = request.approval
        mutation = proof.body.mutation
        assignment = mutation.assignment
        peer.require(assignment.broker)
        holder = self.policy.workloads.get(assignment.agent)
        if (assignment.broker not in self.policy.brokers or holder is None
                or assignment.enrollment != self.policy.binding or assignment.deployment != self.policy.deployment
                or mutation.target != self.name or approval.body.mutation != mutation):
            raise Denied("command or approval does not bind the exact target and assignment")
        verify(holder.instance_key, proof)
        verify(self.policy.approval_key, approval)
        deadline = min(approval.body.expires_ns, request.credential_until_ns, peer.expires_ns)
        with transaction(self.path) as db:
            installed = load(db, InstalledFence)
            if installed is None or installed.assignment != assignment:
                raise Denied("assignment is outside the target's durable fence")
            if installed.boot != self.boot:
                raise Denied("writer restart requires a fresh home fence")
            if installed.held:
                raise Denied("held writer requires a new generation")
            live_proof(proof.body.expires_ns)
            if time_ns() >= deadline:
                raise Denied("write credential or approval expired")
            try:
                self.require_current(assignment)
            except (Denied, Unavailable) as exc:
                self.hold(db, installed)
                denial = exc
            else:
                return self.apply(db, request, deadline)
        # A denied write commits the local safety latch, never the requested mutation.
        raise denial

    def dispatch(self, peer: Peer, route: str, raw: bytes) -> Record | dict:
        if route == "/fence":
            return self.fence(peer, Fence.model_validate_json(raw))
        if route == "/write":
            return self.write(peer, Write.model_validate_json(raw))
        if route == "/ping":
            peer.require("observer")
            return {"ok": True}
        if route == "/read":
            peer.require("observer")
            with transaction(self.path) as db:
                installed = load(db, InstalledFence)
                assignment = installed.assignment if installed else None
                version, marker = db.execute("SELECT version,value FROM marker").fetchone()
                writes = db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
                if marker == "observing":
                    try:
                        if installed is None or installed.held or installed.boot != self.boot:
                            raise Denied("writer must be fenced before observing")
                        self.require_current(assignment)
                    except (Denied, Unavailable):
                        if installed is None:
                            raise Unavailable("observing marker lacks a durable fence")
                        self.hold(db, installed)
                        version, marker = db.execute("SELECT version,value FROM marker").fetchone()
                return {"generation": assignment.generation if assignment else 0,
                        "version": version, "marker": marker, "effective": marker, "writes": writes}

        raise Denied("operation outside target scope")
