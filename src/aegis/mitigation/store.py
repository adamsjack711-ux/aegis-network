"""SQLite target adapter. Target mutations, fencing and audit share one commit."""

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import secrets
import sqlite3
from threading import Event
import time

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


class TargetStore:
    def __init__(self, path: Path, operator: LocalOperator, *, authorize=None,
                 status_current=None) -> None:
        if (authorize is None) != (status_current is None):
            raise ValueError("guarded writes require a local freshness check")
        self.path = path
        self._operator = operator
        self._outage = Event()
        self._authorize = authorize
        self._status_current = status_current

    @contextmanager
    def _authorized_write(self, plan: Plan):
        if self._authorize is None:
            if plan.evidence_binding is not None:
                raise Denied("evidence-bound plan requires local authorization")
            with self._transaction(write=True) as db:
                yield db, None
        else:
            with self._authorize(plan) as evidence, self._transaction(write=True) as db:
                if not self._status_current():
                    raise Denied("local status expired before the target transaction")
                yield db, evidence
                if not self._status_current():
                    raise Denied("local status expired before the target commit")

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
    def _transaction(self, *, write: bool = False, create: bool = False):
        db = None
        try:
            mode = "rwc" if create else "rw"
            db = sqlite3.connect(f"{self.path.as_uri()}?mode={mode}", uri=True, timeout=0.2)
            db.row_factory = sqlite3.Row
            if create:
                db.execute("PRAGMA journal_mode = WAL")
            db.execute("PRAGMA synchronous = FULL")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except sqlite3.Error:
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
        with self._transaction() as db:
            return self._lab_id(db), self._targets(db)

    def history(self) -> list[dict]:
        with self._transaction() as db:
            return [dict(row) | {"detail": json.loads(row["detail"])} for row in db.execute(
                "SELECT * FROM audit ORDER BY seq"
            )]

    def _active(self, db: sqlite3.Connection, now: int, plan: Plan) -> sqlite3.Row:
        plan.validate(self._lab_id(db), now)
        rollout = self._rollout(db)
        if (
            self._outage.is_set()
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

    def begin(self, plan: Plan, approval: Approval, baseline: Observation) -> None:
        with self._authorized_write(plan) as (db, evidence_context):
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

    def restrict(self, plan: Plan, approval: Approval, target: str, grant: str) -> None:
        with self._authorized_write(plan) as (db, _):
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

    def record_protection(self, plan: Plan, evidence: Observation, *, canary: bool = False) -> None:
        with self._authorized_write(plan) as (db, _):
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
        with self._transaction() as db:
            rollout = self._rollout(db)
            if self._outage.is_set():
                return "recovery_required"
            if rollout is None:
                return "ready"
            phase = rollout["phase"]
            if phase in {"applying", "expanding", "confirmed"}:
                if (time.monotonic_ns() >= self._effective_deadline(rollout)
                        or (self._status_current is not None and not self._status_current())):
                    return "recovery_required"
            return phase

    @contextmanager
    def route(self, target: str, *, marker: bool):
        # Serialize marker admission and response with target writes. Benign traffic
        # cannot disclose the marker and uses a read transaction.
        with self._transaction(write=marker) as db:
            row = db.execute("SELECT fence, mode FROM target WHERE id = ?", (target,)).fetchone()
            if row is None:
                raise Denied("proxy target absent from its enrolled inventory")
            rollout = self._rollout(db)
            deadline = self._effective_deadline(rollout) if rollout is not None else None
            if self._outage.is_set() or (deadline is not None and (
                time.monotonic_ns() >= deadline
                or (self._status_current is not None and not self._status_current())
            )):
                yield RouteState("quarantined", row["fence"])
            else:
                yield RouteState(row["mode"], row["fence"], deadline)

    def response_permitted(self, state: RouteState) -> bool:
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
