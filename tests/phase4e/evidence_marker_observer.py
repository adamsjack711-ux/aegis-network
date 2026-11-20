"""Independently observe the disposable Evidence-bound B marker transaction."""

import asyncio
from contextlib import ExitStack, closing
import json
import sqlite3
from time import monotonic_ns, time_ns
from types import SimpleNamespace

import pytest

from aegis.identity_lab import evidence_fixture as fixture
from aegis.identity_lab.evidence_fixture import EvidenceApproval, EvidenceBoundTarget, sign_evidence_approval
from aegis.identity_lab.protocol import Denied, principal
from aegis.identity_lab.transport import Peer
from test_evidence_fixture import native_appraisal
from test_fencing import claim, plan, recover


FULL_DEADLINES = hasattr(fixture.NativeAppraisal, "_deadline_under_guard")
WALL_FAULTS = {"credential-after-status", "peer-after-status", "command-after-status", "wall-rollback"}
NEEDS_FULL_DEADLINES = pytest.mark.skipif(not FULL_DEADLINES, reason="requires the complete deadline guard")


def snapshot(path, queries):
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        return {name: db.execute(sql).fetchall() for name, sql in queries.items()}


def marker_state(path):
    return snapshot(path, {
        "marker": "SELECT version, value FROM marker",
        "receipts": "SELECT generation, marker FROM receipts ORDER BY rowid",
    })


def test_B_deadline_after_status_predicate_without_writer(monkeypatch, record_property):
    """Historical control over an in-memory clock and the private deadline predicate."""
    now = 9

    def status_current():
        nonlocal now
        now = 10
        return True

    appraisal = SimpleNamespace(plan=SimpleNamespace(expires_ns=12),
                                gate=SimpleNamespace(status_current=status_current))
    approval = SimpleNamespace(expires_ns=10)
    monkeypatch.setattr(fixture, "monotonic_ns", lambda: now)
    with ExitStack() as guards:
        timing = {}
        if FULL_DEADLINES:
            wall = time_ns()
            timing = {"assignment_issued_ns": wall, "identity_deadline_ns": wall + 1_000_000_000,
                      "native_deadline_ns": 10}
        pending = fixture._PendingWrite(None, approval, appraisal, guards, **timing)
        try:
            pending.check_current()
            denied = False
        except Denied:
            denied = True
    record_property("b_predicate_deadline", json.dumps({
        "before_status_ns": 9, "after_status_ns": now, "exclusive_cutoff_ns": 10, "denied": denied,
    }))
    assert now == 10 and denied


@pytest.mark.parametrize("fault", [
    "healthy", "wrong-cut", "former-assignment", "approval-after-ownership",
    "native-plan-after-ownership", "approval-after-status",
    pytest.param("native-fresh-after-status", marks=NEEDS_FULL_DEADLINES),
    pytest.param("credential-after-status", marks=NEEDS_FULL_DEADLINES),
    pytest.param("peer-after-status", marks=NEEDS_FULL_DEADLINES),
    pytest.param("command-after-status", marks=NEEDS_FULL_DEADLINES),
    pytest.param("wall-rollback", marks=NEEDS_FULL_DEADLINES),
])
def test_B_local_marker_and_receipt_containment(lab, native_appraisal, tmp_path, fault, monkeypatch, record_property):
    appraisal, _ = native_appraisal
    target_name = "target-a"
    assignment = claim(lab)
    request = plan(lab, assignment, target_name)
    path = lab.database(target_name)
    row, = snapshot(path, {"fence": "SELECT body FROM record"})["fence"]
    target = EvidenceBoundTarget(target_name, path, lab.policy, lab.client(target_name), lab.endpoints,
                                 boot=json.loads(row[0])["boot"])
    peer = Peer(principal(assignment.broker), "0" * 64, assignment.expires_ns)
    if fault == "credential-after-status":
        request = request.model_copy(update={"credential_until_ns": request.command.body.expires_ns - 500_000_000})
    elif fault == "peer-after-status":
        peer = Peer(principal(assignment.broker), "0" * 64, request.command.body.expires_ns - 500_000_000)
    asyncio.run(appraisal.gate.refresh())
    with appraisal.verified_cut() as cut:
        if fault == "wrong-cut":
            cut = cut.model_copy(update={"mesh_checkpoint_sha256": "0" * 64})
        cutoff = appraisal.plan.expires_ns
        if fault in {"approval-after-ownership", "approval-after-status"}:
            cutoff -= 500_000_000
        elif fault == "native-plan-after-ownership":
            cutoff += 500_000_000
        body = EvidenceApproval(mutation=request.command.body.mutation, cut=cut,
                                native_plan_sha256=appraisal.plan.digest, expires_ns=cutoff)
    approval = sign_evidence_approval(body, lab.approval)
    if fault == "former-assignment":
        recover(lab)
        claim(lab, "agent-b", "broker-b")
    before = marker_state(path)
    native_queries = {
        "targets": "SELECT id, fence, mode FROM target ORDER BY id",
        "audit": "SELECT event, plan FROM audit ORDER BY seq",
        "rollouts": "SELECT plan, phase FROM rollout",
    }
    native_path = tmp_path / "native" / "native-plan-fixture.sqlite"
    before_native = snapshot(native_path, native_queries)
    assert before_native["audit"] == before_native["rollouts"] == []
    trace = []
    outcome = "allowed"
    after_denial = None

    if fault in {"wrong-cut", "former-assignment"}:
        with pytest.raises(Denied) as denial:
            target.write_verified(peer, request, approval, appraisal)
        outcome = str(denial.value)
        assert ("cut differs" if fault == "wrong-cut" else "durable fence") in outcome
        after_denial = marker_state(path)
        assert after_denial == before
    else:
        if fault == "healthy":
            with pytest.raises(Denied, match="Evidence-bound entry point"):
                target.write(peer, request)
            assert marker_state(path) == before
        else:
            effective = min(body.expires_ns, appraisal.plan.expires_ns)
            if fault == "native-fresh-after-status":
                assert appraisal.gate._fresh_until < effective
                effective = appraisal.gate._fresh_until
            assert monotonic_ns() < effective
            if fault in WALL_FAULTS:
                choices = {"credential-after-status": request.credential_until_ns, "peer-after-status": peer.expires_ns,
                           "command-after-status": request.command.body.expires_ns,
                           "wall-rollback": assignment.issued_ns - 1}
                wall_after = choices[fault]
                if fault != "wall-rollback":
                    assert time_ns() < wall_after == min(request.approval.body.expires_ns, request.credential_until_ns,
                                                          peer.expires_ns, assignment.expires_ns,
                                                          request.command.body.expires_ns)
            require_current = target.require_current
            native_status = appraisal.gate.status_current

            def checked_owner(owner):
                require_current(owner)
                trace.append("ownership-current")
                # Independent transaction sees no staged mutation or receipt.
                assert marker_state(path) == before

            def checked_status():
                result = native_status()
                if trace:
                    assert result
                    trace.append("native-status-current")
                return result

            def clock_ns():
                event = "native-status-current" if fault.endswith("-after-status") else "ownership-current"
                return effective if fault not in WALL_FAULTS and event in trace else monotonic_ns()

            with monkeypatch.context() as patches:
                patches.setattr(target, "require_current", checked_owner)
                patches.setattr(appraisal.gate, "status_current", checked_status)
                patches.setattr(fixture, "monotonic_ns", clock_ns)
                reason = "exclusive deadline"
                if fault in WALL_FAULTS:
                    patches.setattr(fixture, "time_ns",
                                    lambda: wall_after if "native-status-current" in trace else time_ns())
                    reason = "identity validity window"
                with pytest.raises(Denied, match=reason) as denial:
                    target.write_verified(peer, request, approval, appraisal)
            expected_trace = ["ownership-current"]
            if fault.endswith("-after-status") or fault in WALL_FAULTS:
                expected_trace.append("native-status-current")
            assert trace == expected_trace
            outcome = str(denial.value)
            after_denial = marker_state(path)
            assert after_denial == before
        # Retry with the same exact signed command and no controlled deadline advance.
        asyncio.run(appraisal.gate.refresh())
        target.write_verified(peer, request, approval, appraisal)
        observed = marker_state(path)
        assert observed["marker"] == [(before["marker"][0][0] + 1, "observing")]
        assert observed["receipts"] == [(assignment.generation, "observing")]

    assert snapshot(native_path, native_queries) == before_native
    record_property("b_marker_containment", json.dumps({
        "fault": fault, "decision": outcome, "trace": trace, "before": before,
        "after_denial": after_denial, "final": marker_state(path),
        "native_audit_rows": len(before_native["audit"]), "native_rollout_rows": len(before_native["rollouts"]),
    }, sort_keys=True))
