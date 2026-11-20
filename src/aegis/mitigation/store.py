"""SQLite target adapter. Target mutations, fencing and audit share one commit."""

from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
import json
from pathlib import Path
import secrets
import sqlite3
from threading import Event, RLock
import time

from ..ownership import Action, CommandProof, OwnershipHome
from .observer import Observation
from .policy import (
    Approval, Denied, EVIDENCE_MAX_AGE_NS, LocalOperator, MIN_LEASE_MS,
    OBSERVATION_WINDOW_NS, Plan, TARGETS,
)


@dataclass(frozen=True)
class RouteState:
    mode: str
    fence: int
    deadline_ns: int | None = None
    ownership_utc_window: tuple[int, int] | None = None
    target: str | None = None


class TargetStore:
    def __init__(self, path: Path, operator: LocalOperator, *, authorize=None,
                 status_current=None, require_identity: bool = False) -> None:
        if (authorize is None) != (status_current is None):
            raise ValueError("guarded writes require a local freshness check")
        if require_identity and authorize is None:
            raise ValueError("identity-fenced writes require local evidence authorization")
        self.path = path
        self._operator = operator
        self._outage = Event()
        self._authority_loss = Event()
        self._commit_lock = RLock()
        self._authorize = authorize
        self._status_current = status_current
        self._require_identity = require_identity
        self.ownership = OwnershipHome(self)

    @contextmanager
    def _authorized_write(self, plan: Plan, action: Action, command: CommandProof | None,
                          target: str | None = None, approval: Approval | None = None,
                          grant: str | None = None):
        if self._authorize is None and plan.evidence_binding is not None:
            raise Denied("evidence-bound plan requires local authorization")
        authorization = self._authorize(plan) if self._authorize is not None else nullcontext()
        with authorization as evidence, self._commit_lock, self._transaction(write=True) as db:
            row = self.ownership.read(db)
            assignment = None
            if self._require_identity:
                if plan.evidence_binding is None:
                    raise Denied("identity-fenced write requires an evidence-bound plan")
                assignment = self.ownership.authorize_target(db, row, plan, action, target, command)
            elif row is not None or plan.ownership_binding is not None or command is not None:
                raise Denied("enrolled target requires the identity-fenced writer")
            if self._status_current is not None and not self._status_current():
                raise Denied("local status expired before the target transaction")
            if self._authority_loss.is_set():
                raise Denied("native authority loss was already latched")
            yield db, evidence
            # The approval is part of the protected transaction, including its
            # final deadline. A staged target change and command receipt roll
            # back together when the approval expires during the operation.
            if approval is not None:
                if action == "begin":
                    self._operator.check(plan, approval, time.monotonic_ns())
                else:
                    self._operator.check_grant(plan, approval, target, grant, time.monotonic_ns())
            if self._status_current is not None and not self._status_current():
                raise Denied("local status expired before the target commit")
            if self._authority_loss.is_set():
                raise Denied("native authority loss was already latched")
            if assignment is not None:
                self.ownership.recheck_target(db, assignment, command)
                rollout = self._rollout(db)
                owner_deadlines = self.ownership.deadlines(self.ownership.read(db))
                if owner_deadlines is None:
                    raise Denied("ownership expired before the target commit")
                deadline = min(plan.expires_ns, command.body.expires_ns, owner_deadlines[0])
                if approval is not None:
                    deadline = min(deadline, approval.expires_ns)
                if rollout is not None:
                    deadline = min(deadline, self._effective_deadline(rollout))
                if time.monotonic_ns() >= deadline:
                    raise Denied("approved rollout expired before the target commit")

    def create(self) -> None:
        if self.path.exists():
            raise Denied("fixture store already exists")
        with self._transaction(write=True, create=True) as db:
            db.execute("CREATE TABLE lab (id TEXT NOT NULL)")
            db.execute("INSERT INTO lab VALUES (?)", (secrets.token_hex(16),))
            db.execute(
                "CREATE TABLE target (id TEXT PRIMARY KEY, fence INTEGER NOT NULL, mode TEXT NOT NULL)"
            )
            db.executemany("INSERT INTO target VALUES (?, 0, 'open')", ((target,) for target in TARGETS))
            db.execute("""
                CREATE TABLE rollout (
                    id INTEGER PRIMARY KEY CHECK (id = 1), plan TEXT NOT NULL,
                    phase TEXT NOT NULL, deadline_ns INTEGER NOT NULL,
                    changed_ns INTEGER NOT NULL, evidence_ns INTEGER
                )
            """)
            db.execute("""
                CREATE TABLE audit (
                    seq INTEGER PRIMARY KEY, at_ns INTEGER NOT NULL, event TEXT NOT NULL,
                    plan TEXT NOT NULL, detail TEXT NOT NULL
                )
            """)

    @contextmanager
    def _transaction(self, *, write: bool = False, create: bool = False,
                     read_only: bool = False):
        db = None
        try:
            mode = "rwc" if create else "ro" if read_only else "rw"
            db = sqlite3.connect(f"{self.path.as_uri()}?mode={mode}", uri=True, timeout=0.2)
            db.row_factory = sqlite3.Row
            if create:
                db.execute("PRAGMA journal_mode = WAL")
            if read_only:
                db.execute("PRAGMA query_only = ON")
            else:
                db.execute("PRAGMA synchronous = FULL")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except sqlite3.Error:
            if not read_only:
                self._outage.set()
            raise
        finally:
            if db is not None:
                db.close()

    @staticmethod
    def _lab_id(db: sqlite3.Connection) -> str:
        return db.execute("SELECT id FROM lab").fetchone()[0]

    @staticmethod
    def _rollout(db: sqlite3.Connection) -> sqlite3.Row | None:
        return db.execute("SELECT * FROM rollout").fetchone()

    @staticmethod
    def _targets(db: sqlite3.Connection) -> dict[str, RouteState]:
        return {
            row["id"]: RouteState(row["mode"], row["fence"])
            for row in db.execute("SELECT * FROM target ORDER BY id")
        }

    @staticmethod
    def _audit(db: sqlite3.Connection, now: int, event: str, plan: str, **detail) -> None:
        db.execute(
            "INSERT INTO audit (at_ns, event, plan, detail) VALUES (?, ?, ?, ?)",
            (now, event, plan, json.dumps(detail, sort_keys=True)),
        )

    def inventory(self) -> tuple[str, dict[str, RouteState]]:
        with self._transaction(read_only=True) as db:
            return self._lab_id(db), self._targets(db)

    def history(self) -> list[dict]:
        with self._transaction(read_only=True) as db:
            return [dict(row) | {"detail": json.loads(row["detail"])} for row in db.execute(
                "SELECT * FROM audit ORDER BY seq"
            )]

    def _active(self, db: sqlite3.Connection, now: int, plan: Plan) -> sqlite3.Row:
        plan.validate(self._lab_id(db), now)
        rollout = self._rollout(db)
        if (
            self._outage.is_set()
            or self._authority_loss.is_set()
            or rollout is None
            or rollout["plan"] != plan.digest
            or rollout["phase"] not in {"applying", "expanding", "confirmed"}
            or now >= self._effective_deadline(rollout)
        ):
            raise Denied("lease inactive, evidence stale, or target state uncertain")
        return rollout

    @staticmethod
    def _effective_deadline(rollout: sqlite3.Row) -> int:
        if rollout["phase"] in {"expanding", "confirmed"}:
            return min(rollout["deadline_ns"], rollout["evidence_ns"] + EVIDENCE_MAX_AGE_NS)
        return rollout["deadline_ns"]

    def begin(self, plan: Plan, approval: Approval, baseline: Observation, *,
              command: CommandProof | None = None) -> None:
        with self._authorized_write(plan, "begin", command, approval=approval) as (db, evidence_context):
            now = time.monotonic_ns()
            lab_id = self._lab_id(db)
            plan.validate(lab_id, now)
            self._operator.check(plan, approval, now)
            targets = self._targets(db)
            expected = tuple(zip(plan.targets, plan.expected_fences, strict=True))
            if (
                self._outage.is_set()
                or self._rollout(db) is not None
                or tuple(targets) != TARGETS
                or any(targets[target] != RouteState("open", fence) for target, fence in expected)
            ):
                raise Denied("preflight state changed or fixture has already been used")
            self._check_observation(db, baseline, "open", expected, 0, now)
            deadline = min(now + plan.lease_ms * 1_000_000, approval.expires_ns)
            if deadline - now < MIN_LEASE_MS * 1_000_000:
                raise Denied("approval has insufficient time remaining")
            db.execute(
                "INSERT INTO rollout VALUES (1, ?, 'applying', ?, ?, NULL)",
                (plan.digest, deadline, now),
            )
            self._audit(db, now, "leased", plan.digest, deadline_ns=deadline, targets=plan.targets,
                        evidence_binding=plan.evidence_binding, evidence_context=evidence_context)

    def restrict(self, plan: Plan, approval: Approval, target: str, grant: str, *,
                 command: CommandProof | None = None) -> None:
        with self._authorized_write(plan, "restrict", command, target,
                                    approval=approval, grant=grant) as (db, _):
            now = time.monotonic_ns()
            rollout = self._active(db, now, plan)
            self._operator.check_grant(plan, approval, target, grant, now)
            index = plan.targets.index(target)
            if (index == 0 and rollout["phase"] != "applying") or (
                index > 0 and rollout["phase"] != "expanding"
            ):
                raise Denied("canary or expansion gate is closed")
            fence = plan.expected_fences[index]
            updated = db.execute(
                "UPDATE target SET mode = 'restricted', fence = fence + 1 "
                "WHERE id = ? AND fence = ? AND mode = 'open'",
                (target, fence),
            )
            if updated.rowcount != 1:
                raise Denied("target fence changed or capability already consumed")
            db.execute("UPDATE rollout SET changed_ns = ?", (now,))
            self._audit(db, now, "restricted", plan.digest, target=target, fence=fence + 1)

    def record_protection(self, plan: Plan, evidence: Observation, *, canary: bool = False,
                          command: CommandProof | None = None) -> None:
        action = "verify-canary" if canary else "verify-health"
        with self._authorized_write(plan, action, command) as (db, _):
            now = time.monotonic_ns()
            rollout = self._active(db, now, plan)
            phase = rollout["phase"]
            if (canary and phase != "applying") or (not canary and phase == "applying"):
                raise Denied("unexpected observation stage")
            targets = self._targets(db)
            scope = plan.targets[:1] if canary else plan.targets
            expected = tuple((target, targets[target].fence) for target in scope)
            if any(targets[target].mode != "restricted" for target in scope):
                raise Denied("required target has not been restricted")
            self._check_observation(db, evidence, "restricted", expected, rollout["changed_ns"], now)
            if phase == "confirmed" and evidence.finished_ns <= rollout["evidence_ns"]:
                raise Denied("health observation was already recorded")
            db.execute(
                "UPDATE rollout SET phase = ?, evidence_ns = ?",
                ("expanding" if canary else "confirmed", evidence.finished_ns),
            )
            event = {"applying": "canary_verified", "expanding": "confirmed", "confirmed": "health_verified"}[phase]
            self._audit(db, now, event, plan.digest, fences=expected, requests=evidence.requests,
                        started_ns=evidence.started_ns, finished_ns=evidence.finished_ns)

    def _check_observation(
        self, db: sqlite3.Connection, evidence: Observation, mode: str,
        expected: tuple[tuple[str, int], ...], after: int, now: int,
    ) -> None:
        if (
            evidence.lab_id != self._lab_id(db)
            or evidence.mode != mode
            or evidence.fences != expected
            or evidence.requests != 6 * len(expected)
            or not after <= evidence.started_ns <= evidence.finished_ns <= now
            or evidence.finished_ns - evidence.started_ns < OBSERVATION_WINDOW_NS
            or now - evidence.finished_ns >= EVIDENCE_MAX_AGE_NS
        ):
            raise Denied("incomplete, stale or wrong-generation HTTP evidence")

    def status(self) -> str:
        with self._transaction(read_only=True) as db:
            rollout = self._rollout(db)
            if self._outage.is_set() or self._authority_loss.is_set():
                return "recovery_required"
            if rollout is None:
                return "ready"
            phase = rollout["phase"]
            if phase in {"applying", "expanding", "confirmed"}:
                if (time.monotonic_ns() >= self._effective_deadline(rollout)
                        or self._route_ownership(db, rollout) is None
                        or (self._status_current is not None and not self._status_current())):
                    return "recovery_required"
            return phase

    def _route_ownership(self, db, rollout) -> tuple[int | None, tuple[int, int] | None] | None:
        row = self.ownership.read(db)
        if row is None:
            return None if self._require_identity else (None, None)
        if not self._require_identity:
            return None
        if rollout is None:
            return None, None
        if row["rollout_generation"] != row["generation"]:
            return None
        return self.ownership.deadlines(row)

    @contextmanager
    def route(self, target: str, *, marker: bool):
        # Observation has no write privilege. The watchdog owns durable denial;
        # a route can still fail closed before its transaction becomes visible.
        with self._transaction(read_only=True) as db:
            row = db.execute("SELECT fence, mode FROM target WHERE id = ?", (target,)).fetchone()
            if row is None:
                raise Denied("proxy target absent from its enrolled inventory")
            rollout = self._rollout(db)
            deadline = self._effective_deadline(rollout) if rollout is not None else None
            ownership = self._route_ownership(db, rollout)
            if self._outage.is_set() or self._authority_loss.is_set() or ownership is None or (deadline is not None and (
                time.monotonic_ns() >= deadline
                or (self._status_current is not None and not self._status_current())
            )):
                yield RouteState("quarantined", row["fence"], target=target)
            else:
                ownership_ns, ownership_utc_window = ownership
                if deadline is not None and ownership_ns is not None:
                    deadline = min(deadline, ownership_ns)
                yield RouteState(row["mode"], row["fence"], deadline, ownership_utc_window, target)

    def response_permitted(self, state: RouteState) -> bool:
        if state.target is not None:
            # A fresh, read-only snapshot rejects a response prepared before
            # a local fence or quarantine committed. This does not turn the
            # observer into a writer or claim remote-to-local atomicity.
            try:
                with self._transaction(read_only=True) as db:
                    row = db.execute("SELECT fence, mode FROM target WHERE id = ?",
                                     (state.target,)).fetchone()
                    rollout = self._rollout(db)
                    if (row is None or row["fence"] != state.fence or row["mode"] != state.mode
                            or self._route_ownership(db, rollout) is None):
                        return False
            except (Denied, sqlite3.Error):
                return False
        if state.ownership_utc_window is not None:
            start, end = state.ownership_utc_window
            if not start <= time.time_ns() < end:
                return False
        return not self._outage.is_set() and (
            state.deadline_ns is None or (
                time.monotonic_ns() < state.deadline_ns
                and (self._status_current is None or self._status_current())
            )
        )

    def quarantine(self, reason: str, *, restart: bool = False) -> tuple[tuple[str, int], ...]:
        with self._transaction(write=True) as db:
            rollout = self._rollout(db)
            if rollout is None:
                raise Denied("no leased fixture to roll back")
            targets = self._targets(db)
            if tuple(targets) != TARGETS:
                raise Denied("cannot establish complete rollback scope")
            if rollout["phase"] not in {"recovery_required", "safe_hold"}:
                now = time.monotonic_ns()
                db.execute("UPDATE target SET mode = 'quarantined', fence = fence + 1")
                db.execute("UPDATE rollout SET phase = 'recovery_required', changed_ns = ?", (now,))
                self._audit(db, now, "quarantined", rollout["plan"], reason=reason)
                targets = self._targets(db)
            elif restart:
                now = time.monotonic_ns()
                db.execute("UPDATE rollout SET phase = 'recovery_required', changed_ns = ?", (now,))
                self._audit(db, now, "recovery_recheck", rollout["plan"], reason=reason)
            return tuple((target, targets[target].fence) for target in TARGETS)

    def quarantine_if_authority_lost(self) -> bool:
        """Latch a deny-only hold without a serving or observer request.

        Trust appraisal is sampled before the writer lock. The local loss
        latch and protected commit share a process mutex; the durable hold
        shares the SQLite writer lock with protected mutations.
        """
        with self._transaction(read_only=True) as db:
            rollout = self._rollout(db)
            if rollout is None or rollout["phase"] not in {"applying", "expanding", "confirmed"}:
                return False
        try:
            status_lost = self._status_current is not None and not self._status_current()
        except Exception:
            status_lost = True
        with self._commit_lock:
            if status_lost:
                # No guarded mutation can commit between this local latch and
                # the durable hold: both use this process-local commit lock.
                self._authority_loss.set()
            with self._transaction(write=True) as db:
                rollout = self._rollout(db)
                if rollout is None or rollout["phase"] not in {"applying", "expanding", "confirmed"}:
                    return False
                ownership = self._route_ownership(db, rollout)
                if ownership is not None and not self._authority_loss.is_set():
                    return False
                targets = self._targets(db)
                if tuple(targets) != TARGETS:
                    raise Denied("cannot establish complete quarantine scope")
                now = time.monotonic_ns()
                db.execute("UPDATE target SET mode = 'quarantined', fence = fence + 1")
                db.execute("UPDATE rollout SET phase = 'recovery_required', changed_ns = ?", (now,))
                reason = "ownership lost" if ownership is None else "native Trust status lost"
                self._audit(db, now, "quarantined", rollout["plan"], reason=reason)
                return True

    def record_recovery(self, evidence: Observation) -> None:
        with self._transaction(write=True) as db:
            now = time.monotonic_ns()
            rollout = self._rollout(db)
            targets = self._targets(db)
            if (
                rollout is None
                or rollout["phase"] not in {"recovery_required", "safe_hold"}
                or any(targets[target].mode != "quarantined" for target in TARGETS)
            ):
                raise Denied("no durable quarantine to verify")
            expected = tuple((target, targets[target].fence) for target in TARGETS)
            self._check_observation(db, evidence, "quarantined", expected, rollout["changed_ns"], now)
            if rollout["phase"] == "recovery_required":
                db.execute("UPDATE rollout SET phase = 'safe_hold' WHERE id = 1")
                self._audit(db, now, "safe_hold", rollout["plan"], fences=expected, requests=evidence.requests)
        # Clear a process-local outage only after the durable state is restrictive.
        self._outage.clear()

    def record_recovery_failure(self, reason: str) -> None:
        with self._transaction(write=True) as db:
            rollout = self._rollout(db)
            if rollout is not None and rollout["phase"] in {"recovery_required", "safe_hold"}:
                db.execute("UPDATE rollout SET phase = 'recovery_required' WHERE id = 1")
                self._audit(db, time.monotonic_ns(), "recovery_unobserved", rollout["plan"], reason=reason)
