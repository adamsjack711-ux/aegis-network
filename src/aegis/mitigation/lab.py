"""Local rollout orchestration and private fixture lifecycle."""

from contextlib import ExitStack
from dataclasses import replace
import fcntl
from pathlib import Path
import secrets
import sqlite3
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time

from .http_lab import RunningServer, start_fixture, start_proxy
from .observer import HttpObserver, ObservationError
from .policy import APPROVAL_WINDOW_NS, Approval, Denied, LocalOperator, MARKER_PATH, Plan, TARGETS, TEMPLATE
from .store import TargetStore


class Controller:
    def __init__(self, store: TargetStore, operator: LocalOperator, observer: HttpObserver) -> None:
        self.store = store
        self.operator = operator
        self.observer = observer

    def prepare(self, lease_ms: int, *, binding: str | None = None,
                valid_until_ns: int | None = None) -> Plan:
        lab_id, targets = self.store.inventory()
        if tuple(targets) != TARGETS or self.store.status() != "ready":
            raise Denied("enrolled lab inventory is unavailable or already used")
        now = time.monotonic_ns()
        plan = Plan(lab_id, secrets.token_hex(16), TEMPLATE, MARKER_PATH, TARGETS,
                    tuple(targets[target].fence for target in TARGETS), lease_ms, now + APPROVAL_WINDOW_NS)
        if (binding is None) != (valid_until_ns is None):
            raise Denied("evidence binding and its deadline must be supplied together")
        if valid_until_ns is not None:
            plan = replace(plan, evidence_binding=binding, expires_ns=min(plan.expires_ns, valid_until_ns))
        plan.validate(lab_id, now)
        return plan

    def start(self, plan: Plan, approval: Approval) -> None:
        lab_id, _ = self.store.inventory()
        now = time.monotonic_ns()
        plan.validate(lab_id, now)
        self.operator.check(plan, approval, now)
        baseline = self.observer.observe("open", tuple(zip(plan.targets, plan.expected_fences, strict=True)))
        self.store.begin(plan, approval, baseline)

    def restrict(self, plan: Plan, approval: Approval, target: str) -> None:
        grant = self.operator.grant(plan, approval, target)
        self.store.restrict(plan, approval, target, grant)

    def verify(self, plan: Plan, *, canary: bool = False) -> None:
        scope = tuple(zip(plan.targets, plan.expected_fences, strict=True))
        if canary:
            scope = scope[:1]
        evidence = self.observer.observe("restricted", tuple((target, fence + 1) for target, fence in scope))
        self.store.record_protection(plan, evidence, canary=canary)

    def execute(self, plan: Plan, approval: Approval) -> None:
        self.start(plan, approval)
        try:
            canary, *remaining = plan.targets
            self.restrict(plan, approval, canary)
            self.verify(plan, canary=True)
            for target in remaining:
                self.restrict(plan, approval, target)
            self.verify(plan)
        except (Denied, ObservationError, sqlite3.Error) as exc:
            status = self.rollback(f"rollout interrupted: {exc}")
            raise Denied(f"rollout interrupted, recovery status {status}: {exc}") from exc

    def rollback(self, reason: str) -> str:
        try:
            fences = self.store.quarantine(reason)
            self.store.record_recovery(self.observer.observe("quarantined", fences))
            return "safe_hold"
        except (Denied, ObservationError, sqlite3.Error) as exc:
            try:
                self.store.record_recovery_failure(str(exc))
            except sqlite3.Error:
                pass
            return "recovery_required"

    def monitor(self, plan: Plan, stop: Event) -> None:
        while not stop.wait(0.05):
            try:
                status = self.store.status()
                if status == "safe_hold":
                    return
                if status == "confirmed":
                    self.verify(plan)
                    continue
                reason = f"health monitor saw status {status}"
            except (Denied, ObservationError, sqlite3.Error) as exc:
                reason = f"health observation failed: {exc}"
            if self.rollback(reason) == "safe_hold":
                return


class Lab:
    """One disposable, statically enrolled inventory; no enforcement API."""

    def __init__(self, state_path: Path, *, authorize=None, status_current=None) -> None:
        self.operator = LocalOperator()
        self.store = TargetStore(state_path.resolve(), self.operator, authorize=authorize,
                                 status_current=status_current)
        self.upstreams: dict[str, RunningServer] = {}
        self.proxies: dict[str, RunningServer] = {}
        self.endpoints: dict[str, tuple[str, int]] = {}
        self._resources = ExitStack()
        self._stop = Event()
        self._monitor: Thread | None = None

    def __enter__(self):
        with ExitStack() as owned:
            lock = owned.enter_context(self.store.path.with_suffix(".lock").open("a"))
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Denied("another lab owns this fixture store") from exc
            restarting = self.store.path.exists()
            if not restarting:
                self.store.create()
            lab_id, targets = self.store.inventory()
            if tuple(targets) != TARGETS:
                raise Denied("lab inventory differs from compiled manifest")
            if restarting and self.store.status() != "ready":
                self.store.quarantine("restart reconciliation before proxy admission", restart=True)
            socket_dir = Path(owned.enter_context(TemporaryDirectory(prefix="aegis-3b-", dir="/tmp")))
            for index, target in enumerate(TARGETS):
                socket_path = socket_dir / f"{index}.sock"
                fixture = self.upstreams[target] = start_fixture(target, socket_path)
                owned.callback(fixture.close)
                proxy = self.proxies[target] = start_proxy(lab_id, target, socket_path, self.store)
                owned.callback(proxy.close)
                self.endpoints[target] = proxy.server.server_address
            self.observer = HttpObserver(lab_id, self.endpoints)
            self.controller = Controller(self.store, self.operator, self.observer)
            if restarting and self.store.status() != "ready":
                self.controller.rollback("restart reconciliation")
            self._resources = owned.pop_all()
        return self

    def execute(self, plan: Plan, approval: Approval) -> int:
        self.controller.execute(plan, approval)
        confirmed_ns = time.monotonic_ns()
        self._monitor = Thread(target=self.controller.monitor, args=(plan, self._stop), daemon=True)
        self._monitor.start()
        return confirmed_ns

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._monitor is not None:
            self._monitor.join()
        self._resources.close()
