"""Target-owned denial and last-check limits in the disposable native writer."""

from contextlib import closing, nullcontext
from dataclasses import replace
import sqlite3
from threading import Event, Thread
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from aegis.mitigation.lab import Lab
from aegis.mitigation.policy import Denied, LocalOperator, TARGETS
from aegis.mitigation.store import TargetStore
from aegis.ownership import IdentitySession, lease_proof


PRINCIPAL = "spiffe://aegis.test/workload/native-writer"


def snapshot(path):
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as db:
        return (db.execute("SELECT id, fence, mode FROM target ORDER BY id").fetchall(),
                db.execute("SELECT phase, plan FROM rollout").fetchall(),
                db.execute("SELECT event, plan, detail FROM audit ORDER BY seq").fetchall())


def wait_for_hold(store, seconds=2):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        _, targets = store.inventory()
        if all(state.mode == "quarantined" for state in targets.values()):
            return tuple((target, state.fence) for target, state in targets.items())
        time.sleep(.005)
    pytest.fail("idle native writer did not durably quarantine")


def active_lab(tmp_path, *, status_current=lambda: True):
    path = tmp_path / "target.sqlite"
    provision = TargetStore(path, LocalOperator())
    provision.create()
    key = Ed25519PrivateKey.generate()
    provision.ownership.enroll(str(uuid4()), PRINCIPAL, key.public_key(), ("broker-a", "broker-b"))
    home = provision.ownership
    assignment = home.accept(lease_proof("claim", home.candidate("broker-a"), key),
                             peer_principal=PRINCIPAL, broker="broker-a")
    lab = Lab(path, authorize=lambda plan: nullcontext({"binding": plan.evidence_binding}),
              status_current=status_current, require_identity=True)
    return lab, home, IdentitySession(assignment, key)


def confirm(lab, session):
    plan = lab.controller.prepare(3000, binding="0" * 64,
                                  valid_until_ns=time.monotonic_ns() + 4_000_000_000)
    plan = replace(plan, ownership_binding=session.assignment.binding)
    approval = lab.operator.approve(plan, plan.digest)
    controller = lab.controller
    controller.start(plan, approval, command=session.command("begin", plan.digest))
    controller.restrict(plan, approval, TARGETS[0],
                        command=session.command("restrict", plan.digest, TARGETS[0]))
    controller.verify(plan, canary=True, command=session.command("verify-canary", plan.digest))
    for target in TARGETS[1:]:
        controller.restrict(plan, approval, target,
                            command=session.command("restrict", plan.digest, target))
    controller.verify(plan, command=session.command("verify-health", plan.digest))
    assert lab.store.status() == "confirmed"
    return plan, approval


def test_idle_ownership_loss_precedes_side_effect_free_observation(tmp_path):
    lab, home, session = active_lab(tmp_path)
    with lab:
        plan, approval = confirm(lab, session)
        home.fence(session.assignment.generation)
        fences = wait_for_hold(lab.store)
        before = snapshot(lab.store.path)
        lab.observer.observe("quarantined", fences)
        assert snapshot(lab.store.path) == before
        assert [row["event"] for row in lab.store.history()].count("quarantined") == 1
        with pytest.raises(Denied):
            lab.store.restrict(plan, approval, TARGETS[1],
                               lab.operator.grant(plan, approval, TARGETS[1]),
                               command=session.command("restrict", plan.digest, TARGETS[1]))


def test_same_generation_restore_and_restart_keep_hold(tmp_path):
    lab, home, session = active_lab(tmp_path)
    with lab:
        plan, approval = confirm(lab, session)
        # A local owner outage is represented by a missing current broker.
        # Restore the same generation after the watcher has latched denial.
        with lab.store._transaction(write=True) as db:
            db.execute("UPDATE ownership SET broker = NULL WHERE id = 1")
        fences = wait_for_hold(lab.store)
        with lab.store._transaction(write=True) as db:
            db.execute("UPDATE ownership SET broker = 'broker-a' WHERE id = 1")
        assert snapshot(lab.store.path)[0] == [(target, fence, "quarantined") for target, fence in fences]
    with lab.__class__(lab.store.path, authorize=lambda plan: nullcontext({}),
                       status_current=lambda: True, require_identity=True) as restarted:
        assert all(state.mode == "quarantined" for state in restarted.store.inventory()[1].values())
        assert restarted.store.status() in {"recovery_required", "safe_hold"}
        with pytest.raises(Denied):
            restarted.store.begin(plan, approval,
                                  restarted.observer.observe("quarantined", fences),
                                  command=session.command("begin", plan.digest))


def test_idle_native_status_loss_precedes_probe_and_survives_recovery(tmp_path):
    status = {"current": True}
    lab, _, session = active_lab(tmp_path, status_current=lambda: status["current"])
    with lab:
        plan, approval = confirm(lab, session)
        status["current"] = False
        fences = wait_for_hold(lab.store)
        before = snapshot(lab.store.path)
        lab.observer.observe("quarantined", fences)
        assert snapshot(lab.store.path) == before
        status["current"] = True
        assert all(state.mode == "quarantined" for state in lab.store.inventory()[1].values())
        with pytest.raises(Denied):
            lab.store.record_protection(plan, lab.observer.observe("quarantined", fences),
                                        command=session.command("verify-health", plan.digest))
    with lab.__class__(lab.store.path, authorize=lambda plan: nullcontext({}),
                       status_current=lambda: True, require_identity=True) as restarted:
        assert all(state.mode == "quarantined" for state in restarted.store.inventory()[1].values())


def test_read_only_route_snapshot_rechecks_concurrent_owner_transfer(tmp_path):
    lab, home, session = active_lab(tmp_path)
    with lab:
        confirm(lab, session)
        with lab.store.route(TARGETS[0], marker=False) as state:
            assert state.mode == "restricted"
            finished = Event()
            transfer = Thread(target=lambda: (home.fence(session.assignment.generation), finished.set()))
            transfer.start()
            assert finished.wait(2), "read-only route must not block the owner transaction"
            assert not lab.store.response_permitted(state)
            transfer.join(2)
        fences = wait_for_hold(lab.store)
        before = snapshot(lab.store.path)
        lab.observer.observe("quarantined", fences)
        assert snapshot(lab.store.path) == before


def test_transfer_requires_fresh_plan_and_approval(tmp_path):
    lab, home, old = active_lab(tmp_path)
    with lab:
        plan, approval = confirm(lab, old)
        home.fence(old.assignment.generation)
        fences = wait_for_hold(lab.store)
        new = IdentitySession(home.accept(lease_proof("claim", home.candidate("broker-b"), old.key),
                                          peer_principal=PRINCIPAL, broker="broker-b"), old.key)
        with pytest.raises(Denied):
            lab.store.record_protection(plan, lab.observer.observe("quarantined", fences),
                                        command=new.command("verify-health", plan.digest))
        observed_hold = lab.observer.observe("quarantined", fences)
        new_plan = replace(plan, nonce=uuid4().hex,
                           expected_fences=tuple(fence for _, fence in fences),
                           ownership_binding=new.assignment.binding,
                           expires_ns=min(plan.expires_ns, time.monotonic_ns() + 2_000_000_000))
        before = snapshot(lab.store.path)
        with pytest.raises(Denied, match="invalid or expired local approval"):
            lab.store.begin(new_plan, approval, observed_hold,
                            command=new.command("begin", new_plan.digest))
        fresh_approval = lab.operator.approve(new_plan, new_plan.digest)
        with pytest.raises(Denied, match="preflight state changed"):
            lab.store.begin(new_plan, fresh_approval, observed_hold,
                            command=new.command("begin", new_plan.digest))
        assert snapshot(lab.store.path) == before
        assert new.assignment.generation > old.assignment.generation
        assert approval.plan_digest == plan.digest


def test_approval_expiry_after_staging_rolls_back_target_and_receipt(tmp_path, monkeypatch):
    second, _, second_session = active_lab(tmp_path)
    with second:
        plan = second.controller.prepare(3000, binding="0" * 64,
                                         valid_until_ns=time.monotonic_ns() + 4_000_000_000)
        plan = replace(plan, ownership_binding=second_session.assignment.binding)
        approval = second.operator.approve(plan, plan.digest)
        second.controller.start(plan, approval,
                                command=second_session.command("begin", plan.digest))
        original = second.operator.check_grant
        checks = 0

        def expire_at_commit(p, a, target, grant, now):
            nonlocal checks
            checks += 1
            return original(p, a, target, grant, a.expires_ns if checks == 2 else now)

        monkeypatch.setattr(second.operator, "check_grant", expire_at_commit)
        before = snapshot(second.store.path)
        with pytest.raises(Denied, match="invalid or expired local approval"):
            second.controller.restrict(plan, approval, TARGETS[0],
                                       command=second_session.command("restrict", plan.digest, TARGETS[0]))
        assert checks == 2
        assert snapshot(second.store.path) == before


def test_trust_status_expiry_between_check_and_commit_rolls_back(tmp_path):
    lab, _, session = active_lab(tmp_path)
    with lab:
        plan, _ = confirm(lab, session)
        evidence = lab.observer.observe("restricted", tuple((target, 1) for target in TARGETS))
        lab._stop.set()
        lab._authority_watch.join(2)
        checks = 0

        def expires_after_staging():
            nonlocal checks
            checks += 1
            return checks == 1

        lab.store._status_current = expires_after_staging
        before = snapshot(lab.store.path)
        with pytest.raises(Denied, match="local status expired before the target commit"):
            lab.store.record_protection(plan, evidence,
                                        command=session.command("verify-health", plan.digest))
        assert checks == 2
        assert snapshot(lab.store.path) == before


def test_remote_failure_immediately_after_last_check_has_bounded_gap(tmp_path, monkeypatch):
    lab, home, session = active_lab(tmp_path)
    with lab:
        plan, _ = confirm(lab, session)
        checked, resume = Event(), Event()
        original = lab.store.ownership.recheck_target

        def last_check(db, assignment, command):
            original(db, assignment, command)
            checked.set()
            assert resume.wait(2)

        monkeypatch.setattr(lab.store.ownership, "recheck_target", last_check)
        failure = []

        def write():
            try:
                lab.store.record_protection(plan, lab.observer.observe("restricted", ((TARGETS[0], 1),
                                                                                       (TARGETS[1], 1),
                                                                                       (TARGETS[2], 1))),
                                            command=session.command("verify-health", plan.digest))
            except Exception as exc:
                failure.append(exc)

        worker = Thread(target=write)
        worker.start()
        assert checked.wait(2)
        # A remote failure cannot enter the local SQLite transaction until
        # this writer releases it. No cross-machine atomicity is claimed.
        fence_done = Event()
        transfer = Thread(target=lambda: (home.fence(session.assignment.generation), fence_done.set()))
        transfer.start()
        assert not fence_done.wait(.02)
        resume.set()
        worker.join(2)
        transfer.join(2)
        assert not failure
        assert fence_done.is_set()
        wait_for_hold(lab.store)


def test_remote_status_failure_just_after_last_status_check_is_not_atomic(tmp_path, monkeypatch):
    lab, _, session = active_lab(tmp_path)
    with lab:
        plan, _ = confirm(lab, session)
        evidence = lab.observer.observe("restricted", tuple((target, 1) for target in TARGETS))
        remote_current = True
        lab.store._status_current = lambda: remote_current
        original = lab.store.ownership.recheck_target

        def remote_cut_after_status_check(db, assignment, command):
            nonlocal remote_current
            original(db, assignment, command)
            remote_current = False

        monkeypatch.setattr(lab.store.ownership, "recheck_target", remote_cut_after_status_check)
        lab.store.record_protection(plan, evidence,
                                    command=session.command("verify-health", plan.digest))
        events = [row["event"] for row in lab.store.history()]
        assert "health_verified" in events
        if "quarantined" in events:
            assert events.index("health_verified") < events.index("quarantined")
        assert lab.store.status() == "recovery_required"


def test_native_status_latch_serializes_with_inflight_protected_write(tmp_path, monkeypatch):
    status = {"current": True}
    lab, _, session = active_lab(tmp_path, status_current=lambda: status["current"])
    with lab:
        plan, _ = confirm(lab, session)
        evidence = lab.observer.observe("restricted", tuple((target, 1) for target in TARGETS))
        checked, resume = Event(), Event()
        original = lab.store.ownership.recheck_target

        def pause_after_last_owner_check(db, assignment, command):
            original(db, assignment, command)
            checked.set()
            assert resume.wait(2)

        monkeypatch.setattr(lab.store.ownership, "recheck_target", pause_after_last_owner_check)
        failure = []

        def write():
            try:
                lab.store.record_protection(plan, evidence,
                                            command=session.command("verify-health", plan.digest))
            except Exception as exc:
                failure.append(exc)

        worker = Thread(target=write)
        worker.start()
        assert checked.wait(2)
        status["current"] = False
        time.sleep(.05)
        assert snapshot(lab.store.path)[1][0][0] == "confirmed"
        resume.set()
        worker.join(2)
        assert not failure
        wait_for_hold(lab.store)
        events = [row["event"] for row in lab.store.history()]
        assert events[-2:] == ["health_verified", "quarantined"]
