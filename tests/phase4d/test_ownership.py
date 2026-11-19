"""Adversarial identity checks against the actual durable target adapter."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, closing, nullcontext
from dataclasses import replace
from multiprocessing import get_context
import os
import sqlite3
import subprocess
from threading import Event
from time import monotonic_ns, time_ns
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import nats
import pytest

from aegis import ownership
from aegis.identity import IdentityLease
from aegis.mitigation.observer import Observation
from aegis.mitigation.policy import (
    Denied, LocalOperator, MARKER_PATH, OBSERVATION_WINDOW_NS, Plan, TARGETS, TEMPLATE,
)
from aegis.mitigation.store import TargetStore
from aegis.ownership import IdentitySession, LeaseProof, lease_proof

PRINCIPAL = "spiffe://aegis.test/workload/lab-agent"
BROKERS = "broker-a", "broker-b"


def target_store(path, operator, *, status_current=lambda: True):
    return TargetStore(path, operator, require_identity=True,
                       authorize=lambda plan: nullcontext({"binding": plan.evidence_binding}),
                       status_current=status_current)


@pytest.fixture
def enrolled(tmp_path):
    operator = LocalOperator()
    store = target_store(tmp_path / "target.db", operator)
    store.create()
    key = Ed25519PrivateKey.generate()
    store.ownership.enroll(str(uuid4()), PRINCIPAL, key.public_key(), BROKERS)
    return store, operator, key


def accept(home, proof):
    return home.accept(proof, peer_principal=PRINCIPAL, broker=proof.body.assignment.broker)


def claim(store, key, broker):
    home = store.ownership
    return IdentitySession(accept(home, lease_proof("claim", home.candidate(broker), key)), key)


def records(store):
    with closing(sqlite3.connect(f"{store.path.as_uri()}?mode=ro", uri=True)) as db:
        return db.execute("SELECT action, generation, broker, plan, target FROM ownership_audit "
                          "ORDER BY seq").fetchall()


def plan_for(session):
    return Plan(session.assignment.fixture, uuid4().hex, TEMPLATE, MARKER_PATH, TARGETS,
                (0, 0, 0), 2_000, monotonic_ns() + 3_000_000_000, "0" * 64,
                session.assignment.binding)


def baseline(plan):
    finished = monotonic_ns()
    return Observation(plan.lab_id, "open", tuple(zip(plan.targets, plan.expected_fences, strict=True)),
                       finished - OBSERVATION_WINDOW_NS, finished, 6 * len(plan.targets))


def broker_worker(path, broker, raw, claims_ready, results):
    # Each simulated broker has its own process and opens the one provisioned home.
    key = Ed25519PrivateKey.from_private_bytes(raw)
    home = TargetStore(path, LocalOperator()).ownership
    proof = lease_proof("claim", home.candidate(broker), key)
    claims_ready.wait(timeout=5)
    try:
        assignment = accept(home, proof)
    except Denied:
        results.put((broker, None))
    else:
        results.put((broker, assignment.generation))


def test_simultaneous_cross_broker_claims_have_one_durable_winner(enrolled):
    store, _, key = enrolled
    process = get_context("spawn")
    ready, results = process.Barrier(2), process.Queue()
    contenders = [
        process.Process(target=broker_worker, args=(store.path, broker, key.private_bytes_raw(), ready, results))
        for broker in BROKERS
    ]
    for contender in contenders:
        contender.start()
    try:
        outcomes = dict(results.get(timeout=8) for _ in contenders)
        assert set(outcomes) == set(BROKERS)
        assert list(outcomes.values()).count(1) == list(outcomes.values()).count(None) == 1
        winner = next(broker for broker in BROKERS if outcomes[broker] == 1)
        loser = next(broker for broker in BROKERS if broker != winner)
        home = TargetStore(store.path, LocalOperator()).ownership
        assert home.check(home.candidate(winner)) > monotonic_ns()
        with pytest.raises(Denied, match="stale"):
            home.check(home.candidate(loser))
        assert records(store) == [("enroll", 0, None, None, None), ("claim", 1, winner, None, None)]
    finally:
        for contender in contenders:
            contender.join(timeout=5)
            if contender.is_alive():
                contender.kill()
                contender.join()
    assert all(contender.exitcode == 0 for contender in contenders)


@pytest.mark.parametrize("fault", ["workload", "broker", "unenrolled-broker", "key", "deployment", "fixture", "expired"])
def test_unentitled_claims_leave_home_unassigned(enrolled, monkeypatch, fault):
    store, _, key = enrolled
    home = store.ownership
    offer = home.candidate(BROKERS[0])
    peer, broker, signing_key = PRINCIPAL, BROKERS[0], key
    if fault == "workload":
        peer = "spiffe://aegis.test/workload/lookalike"
    elif fault == "broker":
        broker = BROKERS[1]
    elif fault == "unenrolled-broker":
        broker = "broker-other"
        offer = offer.model_copy(update={"broker": broker})
    elif fault == "key":
        signing_key = Ed25519PrivateKey.generate()
    elif fault == "deployment":
        offer = offer.model_copy(update={"deployment": str(uuid4())})
    elif fault == "fixture":
        offer = offer.model_copy(update={"fixture": uuid4().hex})
    proof = lease_proof("claim", offer, signing_key)
    if fault == "expired":
        monkeypatch.setattr(ownership, "monotonic_ns", lambda: proof.body.expires_ns)
    with pytest.raises(Denied):
        home.accept(proof, peer_principal=peer, broker=broker)
    assert home.candidate(BROKERS[0]).generation == 0
    assert records(store) == [("enroll", 0, None, None, None)]


def test_renewal_requires_current_broker_new_proof_and_the_lease_domain(enrolled):
    store, operator, key = enrolled
    session = claim(store, key, BROKERS[0])
    home = target_store(store.path, operator).ownership
    before = home.check(session.assignment)
    renewal = lease_proof("renew", session.assignment, key)
    assert accept(home, renewal) == session.assignment
    renewed = home.check(session.assignment)
    assert renewed > before
    with pytest.raises(Denied, match="consumed"):
        accept(home, renewal)
    with pytest.raises(Denied, match="current broker"):
        accept(home, lease_proof("renew", home.candidate(BROKERS[1]), key))
    command = session.command("begin", plan_for(session).digest)
    for repackaged in (command, LeaseProof.model_construct(body=command.body, signature=command.signature)):
        with pytest.raises(Denied, match="lease request proof"):
            accept(home, repackaged)
    assert home.check(session.assignment) == renewed
    assert [row[:3] for row in records(store)] == [
        ("enroll", 0, None), ("claim", 1, BROKERS[0]), ("renew", 1, BROKERS[0]),
    ]


def test_expired_owner_cannot_renew_or_survive_reassignment(enrolled, monkeypatch):
    store, operator, key = enrolled
    session = claim(store, key, BROKERS[0])
    home = store.ownership
    before = home.check(session.assignment)
    plan = plan_for(session)
    approval = operator.approve(plan, plan.digest)
    store.begin(plan, approval, baseline(plan), command=session.command("begin", plan.digest))
    monkeypatch.setattr(ownership, "monotonic_ns", lambda: before)
    with pytest.raises(Denied, match="expired"):
        home.check(session.assignment)
    with pytest.raises(Denied, match="current broker"):
        accept(home, lease_proof("renew", session.assignment, key))
    for target in TARGETS:
        with store.route(target, marker=True) as state:
            assert state.mode == "quarantined"
    new = claim(store, key, BROKERS[1])
    assert new.assignment.generation == session.assignment.generation + 1
    with pytest.raises(Denied, match="stale"):
        home.check(session.assignment)
    assert [entry["event"] for entry in store.history()] == ["leased"]
    assert records(store)[-1][:3] == ("claim", 2, BROKERS[1])


def test_clock_regression_holds_until_operator_fences(enrolled, monkeypatch):
    store, _, key = enrolled
    before = time_ns()
    session = claim(store, key, BROKERS[0])
    home = store.ownership
    with monkeypatch.context() as clocks:
        clocks.setattr(ownership, "time_ns", lambda: before - 1)
        with pytest.raises(Denied, match="clock is uncertain"):
            home.check(session.assignment)
        with pytest.raises(Denied, match="clock is uncertain"):
            claim(store, key, BROKERS[1])
    home.fence(session.assignment.generation)
    assert claim(store, key, BROKERS[1]).assignment.generation > session.assignment.generation


def test_rotation_and_retirement_invalidate_old_keys_across_reopen(enrolled):
    store, operator, key = enrolled
    old = claim(store, key, BROKERS[0])
    plan = plan_for(old)
    approval = operator.approve(plan, plan.digest)
    new_key = Ed25519PrivateKey.generate()
    home = store.ownership
    assert home.rotate(old.assignment.generation, new_key.public_key()) == 2
    home = target_store(store.path, operator).ownership
    with pytest.raises(Denied, match="stale generation"):
        home.fence(old.assignment.generation)
    with pytest.raises(Denied, match="unused instance key"):
        home.rotate(2, key.public_key())
    with pytest.raises(Denied, match="instance key"):
        accept(home, lease_proof("claim", home.candidate(BROKERS[1]), key))
    with pytest.raises(Denied, match="stale"):
        store.begin(plan, approval, baseline(plan), command=old.command("begin", plan.digest))
    new = claim(store, new_key, BROKERS[1])
    assert home.retire(new.assignment.generation) == 4
    reopened = target_store(store.path, operator)
    with pytest.raises(Denied, match="retired"):
        reopened.ownership.check(new.assignment)
    with pytest.raises(Denied, match="cannot overwrite"):
        reopened.ownership.enroll(new.assignment.deployment, PRINCIPAL, key.public_key(), BROKERS)
    assert reopened.history() == []
    assert [(action, generation) for action, generation, *_ in records(reopened)] == [
        ("enroll", 0), ("claim", 1), ("rotate", 2), ("claim", 3), ("retire", 4),
    ]


def test_target_rejects_bad_intents_and_approval_without_consuming_anything(enrolled):
    store, operator, key = enrolled
    session = claim(store, key, BROKERS[0])
    plan = plan_for(session)
    approval = operator.approve(plan, plan.digest)
    command = session.command("begin", plan.digest)
    impersonator = IdentitySession(session.assignment, Ed25519PrivateKey.generate())
    for rejected in (
        None,
        impersonator.command("begin", plan.digest),
        session.command("begin", "1" * 64),
        session.command("begin", plan.digest, TARGETS[0]),
        session.command("verify-canary", plan.digest),
    ):
        with pytest.raises(Denied):
            store.begin(plan, approval, baseline(plan), command=rejected)
    with pytest.raises(Denied):
        store.begin(plan, replace(approval, token="forged"), baseline(plan), command=command)
    unbound = replace(plan, evidence_binding=None)
    with pytest.raises(Denied, match="evidence-bound"):
        store.begin(unbound, operator.approve(unbound, unbound.digest), baseline(unbound),
                    command=session.command("begin", unbound.digest))
    legacy_plan = replace(plan, ownership_binding=None, evidence_binding=None)
    legacy_approval = operator.approve(legacy_plan, legacy_plan.digest)
    with pytest.raises(Denied, match="identity-fenced writer"):
        TargetStore(store.path, operator).begin(legacy_plan, legacy_approval, baseline(legacy_plan))
    assert store.history() == []
    assert [row[0] for row in records(store)] == ["enroll", "claim"]
    assert all(state.mode == "open" and state.fence == 0 for state in store.inventory()[1].values())

    store.begin(plan, approval, baseline(plan), command=command)
    peer_grant = operator.grant(plan, approval, TARGETS[1])
    with pytest.raises(Denied, match="canary or expansion"):
        store.restrict(plan, approval, TARGETS[1], peer_grant,
                       command=session.command("restrict", plan.digest, TARGETS[1]))
    grant = operator.grant(plan, approval, TARGETS[0])
    action = session.command("restrict", plan.digest, TARGETS[0])
    store.restrict(plan, approval, TARGETS[0], grant, command=action)
    reopened = target_store(store.path, operator)
    with pytest.raises(Denied, match="consumed"):
        reopened.restrict(plan, approval, TARGETS[0], grant, command=action)
    assert [entry["event"] for entry in reopened.history()] == ["leased", "restricted"]
    assert records(reopened)[-2:] == [
        ("begin", 1, BROKERS[0], plan.digest, None),
        ("restrict", 1, BROKERS[0], plan.digest, TARGETS[0]),
    ]
    assert tuple(state.fence for state in reopened.inventory()[1].values()) == (1, 0, 0)


def test_fenced_broker_and_previous_review_cannot_lease_after_failover(enrolled):
    store, operator, key = enrolled
    old = claim(store, key, BROKERS[0])
    old_plan = plan_for(old)
    old_approval = operator.approve(old_plan, old_plan.digest)
    home = store.ownership
    old_request = lease_proof("renew", old.assignment, key)
    assert home.fence(old.assignment.generation) == 2

    reopened = target_store(store.path, operator)
    new = claim(reopened, key, BROKERS[1])
    assert new.assignment.generation == 3
    with pytest.raises(Denied, match="generation"):
        accept(reopened.ownership, old_request)
    with pytest.raises(Denied, match="stale"):
        reopened.begin(old_plan, old_approval, baseline(old_plan),
                       command=old.command("begin", old_plan.digest))
    with pytest.raises(Denied, match="exact approved plan"):
        reopened.begin(old_plan, old_approval, baseline(old_plan),
                       command=new.command("begin", old_plan.digest))
    new_plan = replace(old_plan, ownership_binding=new.assignment.binding)
    new_command = new.command("begin", new_plan.digest)
    with pytest.raises(Denied):
        reopened.begin(new_plan, old_approval, baseline(new_plan), command=new_command)
    assert reopened.history() == []
    approval = operator.approve(new_plan, new_plan.digest)
    reopened.begin(new_plan, approval, baseline(new_plan), command=new_command)
    assert records(reopened)[-1] == ("begin", 3, BROKERS[1], new_plan.digest, None)


def test_expiry_before_commit_rolls_back_effect_and_command_receipt(enrolled, monkeypatch):
    store, operator, key = enrolled
    session = claim(store, key, BROKERS[0])
    plan = plan_for(session)
    approval = operator.approve(plan, plan.digest)
    store.begin(plan, approval, baseline(plan), command=session.command("begin", plan.digest))
    command = session.command("restrict", plan.digest, TARGETS[0])
    grant = operator.grant(plan, approval, TARGETS[0])
    checks = 0

    def expire_after_staged_write():
        nonlocal checks
        checks += 1
        if checks == 2:
            monkeypatch.setattr(ownership, "monotonic_ns", lambda: command.body.expires_ns)
        return True

    reopened = target_store(store.path, operator, status_current=expire_after_staged_write)
    with pytest.raises(Denied, match="expired before the target commit"):
        reopened.restrict(plan, approval, TARGETS[0], grant, command=command)
    assert checks == 2
    assert [entry["event"] for entry in reopened.history()] == ["leased"]
    assert [row[0] for row in records(reopened)] == ["enroll", "claim", "begin"]
    assert reopened.inventory()[1][TARGETS[0]].fence == 0


def test_transfer_barrier_serializes_with_the_actual_target_mutation(enrolled):
    store, operator, key = enrolled
    session = claim(store, key, BROKERS[0])
    plan = plan_for(session)
    approval = operator.approve(plan, plan.digest)
    store.begin(plan, approval, baseline(plan), command=session.command("begin", plan.digest))
    command = session.command("restrict", plan.digest, TARGETS[0])
    grant = operator.grant(plan, approval, TARGETS[0])

    writer_locked, transfer_started = Event(), Event()

    def wait_inside_write():
        writer_locked.set()
        assert transfer_started.wait(timeout=2)
        return True

    def fence_owner():
        assert writer_locked.wait(timeout=2)
        transfer_started.set()
        return store.ownership.fence(session.assignment.generation)

    writer = target_store(store.path, operator, status_current=wait_inside_write)
    with ThreadPoolExecutor(max_workers=2) as executor:
        write = executor.submit(writer.restrict, plan, approval, TARGETS[0], grant, command=command)
        transfer = executor.submit(fence_owner)
        write.result(timeout=3)
        assert transfer.result(timeout=3) == 2

    assert [row[:3] for row in records(store)][-2:] == [
        ("restrict", 1, BROKERS[0]), ("fence", 2, None),
    ]
    assert claim(store, key, BROKERS[1]).assignment.generation == 3
    with pytest.raises(Denied, match="stale"):
        store.restrict(plan, approval, TARGETS[0], grant, command=command)
    assert [row["event"] for row in store.history()] == ["leased", "restricted"]


def test_required_profile_denies_unenrolled_replacement_database(enrolled, tmp_path):
    store, operator, key = enrolled
    session = claim(store, key, BROKERS[0])
    plan = plan_for(session)
    approval = operator.approve(plan, plan.digest)
    replacement = target_store(tmp_path / "empty.db", operator)
    replacement.create()

    with pytest.raises(Denied, match="unenrolled"):
        replacement.ownership.check(session.assignment)
    with pytest.raises(Denied, match="enrolled command proof"):
        replacement.begin(plan, approval, baseline(plan), command=session.command("begin", plan.digest))
    for target in TARGETS:
        with replacement.route(target, marker=True) as state:
            assert state.mode == "quarantined"
    assert replacement.history() == []


@asynccontextmanager
async def live_broker():
    name = f"aegis-t3-{uuid4().hex}"
    subprocess.run(["docker", "run", "--detach", "--rm", "--pull", "never", "--name", name,
                    "--publish", "127.0.0.1::4222", "nats:2.10-alpine", "-js"],
                   check=True, capture_output=True, timeout=30)
    try:
        address = subprocess.check_output(["docker", "port", name, "4222/tcp"], text=True,
                                          timeout=10).strip()
        connection = await nats.connect(f"nats://{address}", allow_reconnect=False, connect_timeout=2)
        try:
            yield connection.jetstream()
        finally:
            await connection.close()
    finally:
        subprocess.run(["docker", "rm", "--force", name], check=True, capture_output=True, timeout=30)


@pytest.mark.skipif(os.getenv("AEGIS_PHASE4D_T3_LIVE") != "1",
                    reason="set AEGIS_PHASE4D_T3_LIVE=1 for two disposable loopback NATS brokers")
def test_live_independent_jetstream_leases_cannot_override_home(enrolled):
    store, operator, key = enrolled

    async def run():
        async with live_broker() as broker_a, live_broker() as broker_b:
            old = claim(store, key, BROKERS[0])
            id_a, id_b = await asyncio.gather(
                IdentityLease.claim(broker_a, old.assignment.deployment),
                IdentityLease.claim(broker_b, old.assignment.deployment),
            )
            await asyncio.gather(id_a.ensure(), id_b.ensure())
            with pytest.raises(Denied, match="current authoritative broker"):
                claim(store, key, BROKERS[1])
            old_plan = plan_for(old)
            old_approval = operator.approve(old_plan, old_plan.digest)
            store.ownership.fence(old.assignment.generation)
            new = claim(store, key, BROKERS[1])
            await asyncio.gather(id_a.ensure(), id_b.ensure())
            with pytest.raises(Denied, match="stale"):
                store.begin(old_plan, old_approval, baseline(old_plan),
                            command=old.command("begin", old_plan.digest))
            assert store.history() == []
            new_plan = plan_for(new)
            store.begin(new_plan, operator.approve(new_plan, new_plan.digest), baseline(new_plan),
                        command=new.command("begin", new_plan.digest))
            assert records(store)[-1] == ("begin", 3, BROKERS[1], new_plan.digest, None)
            assert [row["event"] for row in store.history()] == ["leased"]

    asyncio.run(run())
