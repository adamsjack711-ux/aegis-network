from dataclasses import replace
from http.client import HTTPConnection
import multiprocessing
import os
from pathlib import Path
import sqlite3
from threading import Barrier, Thread
import time

import pytest

from aegis.mitigation.lab import Lab
from aegis.mitigation.observer import HttpObserver, ObservationError
from aegis.mitigation.policy import Approval, Denied, MARKER_PATH, TARGETS
from aegis.mitigation.store import TargetStore


@pytest.fixture
def lab(tmp_path):
    with Lab(tmp_path / "lab.db") as running:
        yield running


def approve(lab, lease_ms=3000):
    plan = lab.controller.prepare(lease_ms)
    return plan, lab.operator.approve(plan, plan.digest)


def get(lab, target, path):
    client = HTTPConnection(*lab.endpoints[target], timeout=1)
    try:
        client.request("GET", path)
        response = client.getresponse()
        return response.status, response.read(), response.getheader("X-Lab-Fence")
    finally:
        client.close()


def assert_quarantined(lab):
    for target in TARGETS:
        assert get(lab, target, MARKER_PATH)[:2] == (503, b"fixture quarantined")
        assert get(lab, target, "/ok")[:2] == (503, b"fixture quarantined")


def wait_for(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    pytest.fail("expected local state transition did not occur")


def test_real_http_protection_canary_order_and_rollback(lab):
    for target in TARGETS:
        assert get(lab, target, MARKER_PATH) == (200, f"{target}:{MARKER_PATH}".encode(), "0")
    plan, approval = approve(lab)
    lab.execute(plan, approval)
    assert lab.store.status() == "confirmed"
    for target in TARGETS:
        assert get(lab, target, MARKER_PATH) == (403, b"fixture route restricted", "1")
        assert get(lab, target, "/ok") == (200, f"{target}:/ok".encode(), "1")
        assert get(lab, target, "/health") == (200, f"{target}:/health".encode(), "1")
        for path in ("/other", f"{MARKER_PATH}?sample=1", f"/{MARKER_PATH}"):
            assert get(lab, target, path)[0] == 404
    assert [item["event"] for item in lab.store.history()[:6]] == [
        "leased", "restricted", "canary_verified", "restricted", "restricted", "confirmed",
    ]
    confirmed = lab.store.history()[5]["detail"]
    assert confirmed["fences"] == [[target, 1] for target in TARGETS]
    assert confirmed["requests"] == 18
    assert lab.controller.rollback("operator stop") == "safe_hold"
    assert_quarantined(lab)
    with pytest.raises(Denied):
        lab.controller.restrict(plan, approval, "canary")


def test_preflight_and_authorization_reject_out_of_scope_and_replay(lab):
    for lease in (0, 30_001, True):
        with pytest.raises(Denied):
            lab.controller.prepare(lease)
    plan, approval = approve(lab)
    with pytest.raises(Denied):
        lab.operator.approve(plan, "other review digest")
    for changed_plan in (
        replace(plan, lab_id="another-lab"),
        replace(plan, template="another-template"),
        replace(plan, path="/ok"),
        replace(plan, targets=("canary",)),
        replace(plan, lease_ms=500),
    ):
        with pytest.raises(Denied):
            lab.controller.start(changed_plan, approval)
    forged = Approval(plan.digest, approval.expires_ns, "0" * 64)
    expired = replace(approval, expires_ns=time.monotonic_ns() - 1)
    for invalid in (forged, expired):
        with pytest.raises(Denied):
            lab.controller.start(plan, invalid)
    assert not lab.store.history()
    lab.controller.start(plan, approval)
    with pytest.raises(Denied, match="already been used"):
        lab.controller.start(plan, approval)
    with pytest.raises(Denied, match="expansion gate"):
        lab.controller.restrict(plan, approval, "replica-a")
    token = lab.operator.grant(plan, approval, "replica-a")
    with pytest.raises(Denied, match="does not cover"):
        lab.store.restrict(plan, approval, "canary", token)
    lab.controller.restrict(plan, approval, "canary")
    with pytest.raises(Denied, match="already consumed"):
        lab.controller.restrict(plan, approval, "canary")
    assert get(lab, "replica-a", MARKER_PATH)[0] == 200


def test_changed_preflight_and_unhealthy_baseline_do_not_lease(lab):
    plan, approval = approve(lab)
    with pytest.raises(ObservationError, match="fence 1"):
        stale = replace(plan, expected_fences=(1, 0, 0))
        lab.controller.start(stale, lab.operator.approve(stale, stale.digest))
    lab.upstreams["replica-b"].close()
    with pytest.raises(ObservationError, match="replica-b"):
        lab.execute(plan, approval)
    assert lab.store.status() == "ready"
    assert not lab.store.history()


def test_concurrent_grant_consumption_has_one_winner(lab):
    plan, approval = approve(lab)
    lab.controller.start(plan, approval)
    ready = Barrier(3)
    outcomes = []

    def apply():
        ready.wait(timeout=2)
        try:
            lab.controller.restrict(plan, approval, "canary")
        except Denied:
            outcomes.append("denied")
        else:
            outcomes.append("applied")

    workers = [Thread(target=apply) for _ in range(2)]
    for worker in workers:
        worker.start()
    ready.wait(timeout=2)
    for worker in workers:
        worker.join(timeout=2)
    assert sorted(outcomes) == ["applied", "denied"]
    assert get(lab, "canary", MARKER_PATH) == (403, b"fixture route restricted", "1")


def test_incomplete_misrouted_or_stale_evidence_cannot_confirm(lab):
    plan, approval = approve(lab)
    lab.controller.start(plan, approval)
    lab.controller.restrict(plan, approval, "canary")
    lab.controller.verify(plan, canary=True)
    lab.controller.restrict(plan, approval, "replica-a")
    with pytest.raises(ObservationError, match="replica-b"):
        lab.controller.verify(plan)
    stale = lab.observer.observe("restricted", (("canary", 1), ("replica-a", 1)))
    lab.controller.restrict(plan, approval, "replica-b")
    with pytest.raises(Denied, match="incomplete"):
        lab.store.record_protection(plan, stale)
    lab_id, _ = lab.store.inventory()
    wrong = HttpObserver(lab_id, lab.endpoints | {"replica-b": lab.endpoints["canary"]})
    with pytest.raises(ObservationError, match="replica-b"):
        wrong.observe("restricted", tuple((target, 1) for target in TARGETS))
    assert lab.store.status() == "expanding"
    lab.controller.verify(plan)
    assert lab.store.status() == "confirmed"


def test_live_monitor_rolls_back_after_upstream_outage(lab):
    plan, approval = approve(lab)
    lab.execute(plan, approval)
    lab.upstreams["replica-a"].close()
    wait_for(lambda: lab.store.status() == "safe_hold")
    assert_quarantined(lab)
    records = lab.store.history()
    failure = next(item for item in records if item["event"] == "quarantined")
    assert "health observation failed" in failure["detail"]["reason"]
    assert "replica-a" in failure["detail"]["reason"]


def test_proxy_outage_does_not_count_as_safe_hold(lab):
    plan, approval = approve(lab)
    lab.controller.execute(plan, approval)
    lab.proxies["replica-b"].close()
    assert lab.controller.rollback("proxy observation lost") == "recovery_required"
    assert lab.store.status() == "recovery_required"
    for target in TARGETS[:2]:
        assert get(lab, target, MARKER_PATH)[0] == 503
    assert [item["event"] for item in lab.store.history()][-2:] == [
        "quarantined", "recovery_unobserved",
    ]


def test_nonresponsive_store_fails_closed_and_latches_until_verified(lab):
    plan, approval = approve(lab)
    lab.controller.start(plan, approval)
    lab.controller.restrict(plan, approval, "canary")
    original = lab.store.path
    lab.store.path = original.with_name("unavailable.db")
    try:
        for target in TARGETS:
            assert get(lab, target, MARKER_PATH)[:2] == (503, b"fixture state unavailable")
        assert lab.controller.rollback("store outage") == "recovery_required"
    finally:
        lab.store.path = original
    assert lab.store.status() == "recovery_required"
    assert_quarantined(lab)
    assert lab.controller.rollback("store restored") == "safe_hold"
    assert_quarantined(lab)


def test_expiry_quarantines_entire_partial_rollout_without_controller(lab):
    plan, approval = approve(lab, lease_ms=300)
    lab.controller.start(plan, approval)
    lab.controller.restrict(plan, approval, "canary")
    assert get(lab, "replica-b", MARKER_PATH)[0] == 200
    wait_for(lambda: lab.store.status() == "recovery_required")
    assert_quarantined(lab)
    with pytest.raises(Denied, match="lease inactive"):
        lab.controller.restrict(plan, approval, "replica-b")
    assert lab.controller.rollback("expired lease") == "safe_hold"


def test_stale_health_evidence_fails_closed_without_monitor(lab):
    plan, approval = approve(lab)
    lab.controller.execute(plan, approval)
    assert lab.store.status() == "confirmed"
    wait_for(lambda: lab.store.status() == "recovery_required")
    assert_quarantined(lab)
    assert lab.controller.rollback("stopped observer") == "safe_hold"


class _DieBeforeCommit(TargetStore):
    @staticmethod
    def _audit(db, now, event, plan, **detail):
        TargetStore._audit(db, now, event, plan, **detail)
        if event == "restricted":
            os._exit(71)


def _crash_during_apply(path, operator, plan, approval, target, before_commit):
    store_type = _DieBeforeCommit if before_commit else TargetStore
    store = store_type(path, operator)
    store.restrict(plan, approval, target, operator.grant(plan, approval, target))
    os._exit(72)


@pytest.mark.parametrize("before_commit", [True, False])
def test_process_crash_during_expansion_recovers_without_reopening(tmp_path, before_commit):
    path = tmp_path / "lab.db"
    with Lab(path) as lab:
        plan, approval = approve(lab, lease_ms=5000)
        lab.controller.start(plan, approval)
        lab.controller.restrict(plan, approval, "canary")
        lab.controller.verify(plan, canary=True)
        child = multiprocessing.get_context("spawn").Process(
            target=_crash_during_apply,
            args=(Path(path), lab.operator, plan, approval, "replica-a", before_commit),
        )
        child.start()
        try:
            child.join(timeout=4)
            assert child.exitcode == (71 if before_commit else 72)
        finally:
            if child.is_alive():
                child.kill()
                child.join()
            child.close()
        assert lab.store.status() == "expanding"
        assert get(lab, "canary", MARKER_PATH)[0] == 403
        assert get(lab, "replica-a", MARKER_PATH)[0] == (200 if before_commit else 403)
        assert get(lab, "replica-b", MARKER_PATH)[0] == 200
        assert [
            item["detail"]["target"] for item in lab.store.history() if item["event"] == "restricted"
        ] == (["canary"] if before_commit else ["canary", "replica-a"])
    with Lab(path) as restarted:
        assert restarted.store.status() == "safe_hold"
        assert_quarantined(restarted)
        _, target_states = restarted.store.inventory()
        assert [state.fence for state in target_states.values()] == [2, (1 if before_commit else 2), 1]
        assert restarted.controller.rollback("idempotent retry") == "safe_hold"
        assert restarted.store.inventory()[1] == target_states
        with pytest.raises(Denied):
            restarted.controller.start(plan, approval)


def test_only_one_listener_set_can_own_an_inventory(lab):
    with pytest.raises(Denied, match="another lab owns"):
        with Lab(lab.store.path):
            pytest.fail("a second listener set started")


@pytest.mark.parametrize("broken_target", ["canary", "replica-b"])
def test_rollout_automatically_quarantines_if_stage_health_fails(lab, monkeypatch, broken_target):
    plan, approval = approve(lab)
    restrict = lab.controller.restrict

    def restrict_then_break_upstream(plan, approval, target):
        restrict(plan, approval, target)
        if target == broken_target:
            lab.upstreams[target].close()

    monkeypatch.setattr(lab.controller, "restrict", restrict_then_break_upstream)
    with pytest.raises(Denied, match="recovery status safe_hold"):
        lab.execute(plan, approval)
    assert_quarantined(lab)
    audit = lab.store.history()
    events = [record["event"] for record in audit]
    assert "confirmed" not in events
    if broken_target == "canary":
        assert events == ["leased", "restricted", "quarantined", "safe_hold"]
    else:
        assert events == [
            "leased", "restricted", "canary_verified", "restricted", "restricted",
            "quarantined", "safe_hold",
        ]


def test_stale_canary_evidence_fences_delayed_expansion(lab):
    plan, approval = approve(lab)
    lab.controller.start(plan, approval)
    lab.controller.restrict(plan, approval, "canary")
    lab.controller.verify(plan, canary=True)
    wait_for(lambda: lab.store.status() == "recovery_required")
    with pytest.raises(Denied, match="evidence stale"):
        lab.controller.restrict(plan, approval, "replica-a")
    assert_quarantined(lab)
