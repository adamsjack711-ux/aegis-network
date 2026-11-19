"""Synthetic ownership home, rollback guard, and scope-limited target evaluator."""

import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from threading import RLock
from typing import Literal

from pydantic import ValidationError

from aegis.evidence.records import canonical, digest
from aegis.identity import canonical_agent_id

from .history import (
    Checkpoint, Coverage, Cut, Leaf, REQUIRED_WITNESSES, Subject, assess, check_extension,
    status_for, transaction, verify_archive,
)
from .identity import Hash, Hold, Name, Record, Signature, Tick, Trust, commitment, quorum

LEASE_SECONDS = 10
CHALLENGE_NS = 1_000_000_000


class Clock:
    wall = staticmethod(lambda: time.time_ns() // 1_000_000_000)
    monotonic = staticmethod(time.monotonic_ns)


class Challenge(Record):
    scope: Name
    deployment: str
    broker: Name
    holder: Name
    generation: Tick
    nonce: Hash
    issued: Tick


class Plan(Record):
    challenge: Challenge
    subject: Subject
    checkpoint: Hash
    status: Hash
    trust: Hash
    target: Literal["fixture-route"] = "fixture-route"
    fence: Tick
    operation: Literal["restrict", "renew"]
    expires: Tick


class Journal(Record):
    coverage: Coverage
    signatures: tuple[Signature, ...]
    leaves: tuple[Leaf, ...]

    @property
    def checkpoint(self) -> Checkpoint:
        return self.coverage.checkpoint


class ForkRecord(Record):
    accepted: Coverage
    accepted_signatures: tuple[Signature, ...]
    conflicting: Coverage
    conflicting_signatures: tuple[Signature, ...]


@dataclass(frozen=True)
class Pending:
    challenge: Challenge
    monotonic: int
    plan: Plan | None = None
    trust: Trust | None = None


class LabTarget:
    """Trusted local boundary. The ownership generation and target lock are shared."""

    @classmethod
    def provision(cls, path, anchor, root, deployment, enrollments, *, clock=None):
        target = cls(path, anchor, root, deployment, enrollments, clock=clock)
        # Exclusive creation prevents replacing an active database with an empty one.
        with target.path.open("xb"), target.anchor.open("xb"):
            pass
        with transaction(target.path) as db:
            db.execute("""CREATE TABLE target (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1), deployment TEXT NOT NULL,
                holder TEXT, broker TEXT, generation INTEGER NOT NULL, lease INTEGER NOT NULL,
                fence INTEGER NOT NULL, restricted INTEGER NOT NULL, journal BLOB, status_holds TEXT NOT NULL)""")
            db.execute("INSERT INTO target VALUES (1, ?, NULL, NULL, 0, 0, 0, 0, NULL, '[]')", (deployment,))
            db.execute("""CREATE TABLE audit (
                id INTEGER PRIMARY KEY, tick INTEGER, event TEXT, detail TEXT)""")
            db.execute("CREATE TABLE used (nonce TEXT PRIMARY KEY)")
            initial = target._floor(target._row(db))
        with transaction(target.anchor) as db:
            db.execute("""CREATE TABLE anchor (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1), deployment TEXT NOT NULL,
                state TEXT NOT NULL, fork BLOB)""")
            db.execute("INSERT INTO anchor VALUES (1, ?, ?, NULL)", (deployment, initial))
        return target

    def __init__(self, path, anchor, root, deployment, enrollments, *, clock=None):
        self.path, self.anchor = Path(path), Path(anchor)
        self.deployment = canonical_agent_id(deployment)
        self.enrollments = {holder: frozenset(brokers) for holder, brokers in enrollments.items()}
        self.root, self.clock = root, clock or Clock()

    def _row(self, db):
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM target WHERE deployment = ?", (self.deployment,)).fetchone()
        if row is None:
            raise Hold("target enrollment missing")
        return row

    def audit(self, db, event, detail):
        db.execute("INSERT INTO audit(tick, event, detail) VALUES (?, ?, ?)",
                   (self.clock.wall(), event, str(detail)))

    @staticmethod
    def _floor(row):
        fields = ("deployment", "holder", "broker", "generation", "lease", "fence", "restricted", "status_holds")
        raw = row["journal"]
        values = [row[field] for field in fields] + [digest(raw) if raw is not None else None]
        return digest(json.dumps(values, separators=(",", ":")).encode("ascii"))

    def _journal(self, row):
        with transaction(self.anchor) as db:
            floor = db.execute("SELECT state, fork FROM anchor WHERE deployment = ?",
                               (self.deployment,)).fetchone()
        if floor is None or floor[1] or floor[0] != self._floor(row):
            raise Hold("journal or target restore mismatch, or latched history fork")
        raw = row["journal"]
        return Journal.model_validate_json(raw) if raw is not None else None

    def _pin(self, row, *, fork=None):
        with transaction(self.anchor) as db:
            cursor = db.execute("UPDATE anchor SET state = ?, fork = ? WHERE deployment = ? AND fork IS NULL",
                                (self._floor(row), canonical(fork) if fork is not None else None, self.deployment))
            if cursor.rowcount != 1:
                raise Hold("journal anchor unavailable")

    def transfer(self, *, expected, holder, broker, chain):
        """Provisioner-only operation. No broker can create or renew ownership."""
        if broker not in self.enrollments.get(holder, ()):
            raise Hold("holder is not enrolled for this broker")
        now = self.clock.wall()
        trust = self.root.appraise(chain, now)
        grant = trust.grant(holder, "agent", now)
        deadline = min(now + LEASE_SECONDS, grant.ends, trust.current.ends, trust.cuts.get(holder, grant.ends))
        with transaction(self.path) as db:
            row = self._row(db)
            prior = self._journal(row)
            if (expected != row["generation"] or deadline <= now
                    or prior and prior.checkpoint.trust not in trust.versions):
                raise Hold("ownership or trust changed before transfer")
            db.execute("UPDATE target SET holder = ?, broker = ?, generation = ?, lease = ?",
                       (holder, broker, expected + 1, deadline))
            self.audit(db, "transfer", f"{expected + 1}/{holder}/{broker}")
            self._pin(self._row(db))
        return expected + 1

    @staticmethod
    def _snapshot(row):
        return {key: row[key] for key in ("generation", "fence", "restricted", "lease")}

    def snapshot(self):
        with transaction(self.path) as db:
            return self._snapshot(self._row(db))

    def events(self):
        with transaction(self.path) as db:
            return db.execute("SELECT tick, event, detail FROM audit ORDER BY id").fetchall()


def _audited(method):
    @wraps(method)
    def operation(self, *args, **kwargs):
        with self._lock:
            try:
                return method(self, *args, **kwargs)
            except (Hold, sqlite3.Error, ValidationError) as exc:
                self._pending = None
                try:
                    with transaction(self.target.path) as db:
                        self.target.audit(db, "hold", f"{method.__name__}: {exc}")
                except sqlite3.Error:
                    pass  # A damaged local journal may also be unable to accept an audit row.
                if isinstance(exc, Hold):
                    raise
                raise Hold("trust storage or record unavailable") from exc
    return operation


class Evaluator:
    def __init__(self, target, operator):
        self.target, self.operator = target, operator
        self._lock = RLock()
        self._pending = None

    def _owner(self, row, challenge, now):
        if ((row["holder"], row["broker"], row["generation"])
                != (challenge.holder, challenge.broker, challenge.generation)
                or now >= row["lease"]):
            raise Hold("stale or expired target ownership")

    def _live(self, pending):
        if pending is None:
            raise Hold("fresh authenticated reconciliation required")
        now = self.target.clock.wall()
        elapsed = self.target.clock.monotonic() - pending.monotonic
        if pending.challenge.issued != now or not 0 <= elapsed < CHALLENGE_NS:
            raise Hold("operation challenge expired or clock moved")
        return now

    @_audited
    def begin(self, *, holder, broker):
        self._pending = None
        with transaction(self.target.path) as db:
            row = self.target._row(db)
            self.target._journal(row)
            now = self.target.clock.wall()
            challenge = Challenge(scope=self.target.root.scope, deployment=self.target.deployment,
                                  broker=broker, holder=holder, issued=now,
                                  generation=row["generation"], nonce=secrets.token_hex(32))
            self._owner(row, challenge, now)
        self._pending = Pending(challenge, self.target.clock.monotonic())
        return challenge

    @_audited
    def reconcile(self, holder_proof, cut: Cut, signed_status, chain, subject, operation):
        pending = self._pending
        now = self._live(pending)
        if pending.plan is not None:
            raise Hold("operation challenge already reconciled")
        challenge = pending.challenge
        trust = self.target.root.appraise(chain, now)
        if holder_proof.key != challenge.holder:
            raise Hold("wrong holder proof")
        agent = trust.authenticate(holder_proof, "agent-proof", challenge, "agent", now)
        head = cut.body.checkpoint
        if head.epoch != now - 1 or cut.body.nonce != challenge.nonce:
            raise Hold("coverage is stale or belongs to a different challenge")
        quorum(cut.signatures, "coverage", cut.body, trust.witnesses(now), REQUIRED_WITNESSES)
        verify_archive(cut.leaves, head, trust)
        journal = canonical(Journal(coverage=cut.body, signatures=cut.signatures, leaves=cut.leaves))
        with transaction(self.target.path) as db:
            row = self.target._row(db)
            self._owner(row, challenge, self._live(pending))
            prior = self.target._journal(row)
            if prior:
                if prior.checkpoint.trust not in trust.versions:
                    raise Hold("delegation rollback or fork")
                if head.epoch < prior.checkpoint.epoch:
                    raise Hold("checkpoint rollback")
                try:
                    check_extension(prior.checkpoint, cut.leaves, head)
                except Hold:
                    fork = ForkRecord(accepted=prior.coverage, accepted_signatures=prior.signatures,
                                      conflicting=cut.body, conflicting_signatures=cut.signatures)
                    self.target._pin(row, fork=fork)
                    raise
            holds = set(json.loads(row["status_holds"])) if prior and head == prior.checkpoint else set()
            status_problem = None
            try:
                if signed_status is None:
                    raise Hold("independent Evidence status unavailable")
                body = signed_status.body
                status_key = trust.authenticate(signed_status.signature, "status", body, "status", now)
                expected = status_for(head, cut.leaves, subject, trust, now, challenge.nonce)
                if body != expected or now >= body.expires:
                    if body.subject == subject and body.checkpoint == commitment(head) and body.nonce == challenge.nonce:
                        holds.add(commitment(subject))
                    raise Hold("Evidence status disagreement or expiry")
                if commitment(subject) in holds:
                    raise Hold("known signed Evidence disagreement")
            except Hold as exc:
                status_problem = exc

            # Preserve authenticated history even when Evidence status is unavailable.
            # A crash between these stores leaves an anchor mismatch and denies recovery.
            db.execute("UPDATE target SET journal = ?, status_holds = ?", (journal, json.dumps(sorted(holds))))
            self.target._pin(self.target._row(db))
            self.target.audit(db, "reconciled", commitment(head))
            fence, lease = row["fence"], row["lease"]

        if status_problem:
            raise status_problem
        mesh, appraisal = assess(cut.leaves, subject, trust, now)
        if not mesh or appraisal.outcome != "current":
            reason = appraisal.outcome if appraisal.outcome != "current" else "mesh withdrawal"
            raise Hold(f"new authority denied: {reason}")
        deadline = min(lease, body.expires, appraisal.ends, agent.ends, status_key.ends,
                       trust.current.ends, trust.cuts.get(agent.key, agent.ends),
                       trust.cuts.get(status_key.key, status_key.ends))
        plan = Plan(challenge=challenge, subject=subject, checkpoint=commitment(head),
                    status=commitment(body), trust=trust.head, fence=fence,
                    operation=operation, expires=deadline)
        self._live(pending)
        self._pending = Pending(challenge, pending.monotonic, plan, trust)
        return plan

    @_audited
    def apply(self, plan, approval):
        pending, self._pending = self._pending, None
        now = self._live(pending)
        if plan != pending.plan or not now < plan.expires or approval.key != self.operator:
            raise Hold("exact current local approval required")
        trust = pending.trust
        trust.authenticate(approval, "approval", plan, "operator", now)
        with transaction(self.target.path) as db:
            row = self.target._row(db)
            now = self._live(pending)
            self._owner(row, plan.challenge, now)
            journal = self.target._journal(row)
            if (journal is None or plan.checkpoint != commitment(journal.checkpoint)
                    or plan.fence != row["fence"] or now >= plan.expires):
                raise Hold("checkpoint or target fence changed before commit")
            if commitment(plan.subject) in json.loads(row["status_holds"]):
                raise Hold("known signed Evidence disagreement")
            if db.execute("INSERT OR IGNORE INTO used VALUES (?)", (plan.challenge.nonce,)).rowcount != 1:
                raise Hold("operation already consumed")
            if plan.operation == "restrict":
                db.execute("UPDATE target SET restricted = 1, fence = fence + 1")
            else:
                grant = trust.grant(plan.challenge.holder, "agent", now)
                lease = min(trust.current.ends, grant.ends, now + LEASE_SECONDS,
                            trust.cuts.get(grant.key, grant.ends))
                if lease <= row["lease"]:
                    raise Hold("renewal would not extend authority")
                db.execute("UPDATE target SET lease = ?, fence = fence + 1", (lease,))
            self.target.audit(db, plan.operation, json.dumps({
                "plan": plan.model_dump(mode="json"),
                "approval": approval.model_dump(mode="json"),
            }, sort_keys=True, separators=(",", ":")))
            self._live(pending)
            updated = self.target._row(db)
            self.target._pin(updated)
            self._live(pending)
        return self.target._snapshot(updated)

    @_audited
    def disconnect(self):
        self._pending = None
        with transaction(self.target.path) as db:
            self.target.audit(db, "isolated", "discarded pending authority")
