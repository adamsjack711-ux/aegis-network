from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from shutil import copyfile
import sqlite3
from threading import Barrier
from time import monotonic, sleep, time_ns
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from aegis.artifact import Finding, sign, verify
from aegis.identity_lab.protocol import (
    Admission, Assignment, Denied, Fence, Mutation, SessionRequest, Stamp, Unavailable, Write,
    approve, command, make_claim, principal,
)
from aegis.identity_lab.services import Target
from aegis.identity_lab.transport import AuthenticationFailed, Endpoint, Peer


def offer(lab, agent, broker, generation=None):
    if generation is None:
        generation = lab.call("operator", "home", "/status")["generation"]
    return make_claim(lab.policy, agent, broker, generation, lab.instances[agent])


def claim(lab, agent="agent-a", broker="broker-a", credential=None, proof=None):
    raw = lab.call(credential or agent, broker, "/claim", proof or offer(lab, agent, broker))
    return Assignment.model_validate(raw)


def anchor(lab):
    return Stamp.model_validate(lab.call("operator", "anchor", "/stamp"))


def recover(lab):
    return lab.call("operator", "home", "/recover", anchor(lab))


def read(lab, target="target-a"):
    return lab.call("observer", target, "/read")


def plan(lab, assignment, target="target-a", key=None):
    mutation = Mutation(assignment=assignment, target=target, marker="observing",
                        expected_version=read(lab, target)["version"])
    return Write(command=command(mutation, key or lab.instances[assignment.agent]),
                 approval=approve(mutation, lab.approval),
                 credential_until_ns=assignment.expires_ns)


def raw_receipts(lab, target="target-a"):
    path = lab.database(target)
    with sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True) as db:
        return db.execute("SELECT generation,marker FROM receipts ORDER BY rowid").fetchall()


def test_simultaneous_authenticated_broker_claims(lab):
    gate = Barrier(2)

    def contender(agent, broker):
        proof = offer(lab, agent, broker, 0)
        gate.wait(timeout=2)
        try:
            return claim(lab, agent, broker, proof=proof)
        except Denied:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(contender, agent, broker) for agent, broker in zip(lab.agents, lab.brokers)]
        winners = [result for future in futures if (result := future.result()) is not None]
    assert len(winners) == 1
    winner, = winners
    assert winner.generation == 1
    assert all(read(lab, target)["generation"] == 1 for target in lab.targets)
    assert lab.call(winner.agent, winner.broker, "/session", SessionRequest(agent=winner.agent)) == winner.model_dump()


def test_former_owner_signed_command_denied_at_actual_writer(lab):
    former = claim(lab)
    valid = plan(lab, former)
    lab.call("agent-a", "broker-a", "/write", valid)
    with pytest.raises(Denied, match="already committed"):
        lab.call("agent-a", "broker-a", "/write", valid)
    pending = plan(lab, former)
    assert read(lab)["effective"] == "observing"
    recover(lab)
    successor = claim(lab, "agent-b", "broker-b")
    assert successor.generation > former.generation
    before = read(lab)
    assert before["marker"] == "quarantined"
    with pytest.raises(Denied, match="durable fence"):
        lab.call("broker-a", "target-a", "/write", pending)
    with pytest.raises(Denied, match="durable fence"):
        lab.call("agent-a", "broker-a", "/write", pending)
    assert read(lab) == before
    assert raw_receipts(lab) == [(former.generation, "observing")]
    lab.call("agent-b", "broker-b", "/write", plan(lab, successor))
    assert raw_receipts(lab)[-1] == (successor.generation, "observing")


def test_distinct_leaf_with_same_uri_and_separate_proof_key(lab):
    proof = offer(lab, "agent-a", "broker-a")
    with pytest.raises(Denied, match="transport key"):
        claim(lab, credential="lookalike", proof=proof)
    forged = make_claim(lab.policy, "agent-a", "broker-a", 0, lab.instances["agent-b"])
    with pytest.raises(Denied, match="signature"):
        claim(lab, proof=forged)
    assert claim(lab, proof=proof).generation == 1


def test_expired_leaf_during_recovery_and_rotated_key(lab):
    former = claim(lab)
    recover(lab)
    fresh = offer(lab, "agent-a", "broker-b")
    with pytest.raises(AuthenticationFailed):
        claim(lab, "agent-a", "broker-b", credential="expired", proof=fresh)
    assert not lab.expired_peer_accepted("broker-b", fresh)
    assert lab.call("operator", "home", "/status")["phase"] == "vacant"
    successor = claim(lab, "agent-a", "broker-b", credential="rotated", proof=fresh)
    assert successor.agent == former.agent and successor.generation > former.generation
    assert lab.call("rotated", "broker-b", "/session", SessionRequest(agent="agent-a")) == successor.model_dump()
    with pytest.raises(Denied):
        lab.call("agent-a", "broker-a", "/session", SessionRequest(agent="agent-a"))


def test_broker_loss_and_reconciliation(lab):
    old = claim(lab)
    first = offer(lab, "agent-b", "broker-b")
    held = plan(lab, old)
    lab.partition("broker-a")
    with pytest.raises(Unavailable):
        lab.call("agent-a", "broker-a", "/session", SessionRequest(agent="agent-a"))
    with pytest.raises(Denied, match="active"):
        claim(lab, "agent-b", "broker-b", proof=first)
    recover(lab)
    new = claim(lab, "agent-b", "broker-b")
    lab.heal("broker-a")
    with pytest.raises(Denied, match="durable fence"):
        lab.call("agent-a", "broker-a", "/write", held)
    with pytest.raises(Denied, match="active"):
        claim(lab, proof=offer(lab, "agent-a", "broker-a"))
    lab.call("agent-b", "broker-b", "/write", plan(lab, new))


def test_stale_home_snapshot_and_independent_anchor(lab, tmp_path):
    old = claim(lab)
    lab.stop("home")
    snapshot = tmp_path / "stale.sqlite"
    copyfile(lab.database("home"), snapshot)
    lab.start("home")
    recover(lab)
    current = claim(lab, "agent-b", "broker-b")
    write = plan(lab, current)
    lab.stop("home")
    copyfile(snapshot, lab.database("home"))
    lab.start("home")
    with pytest.raises(Unavailable, match="independent anchor"):
        lab.call("operator", "home", "/status")
    with pytest.raises((Denied, Unavailable), match="independent anchor|held writer"):
        lab.call("agent-b", "broker-b", "/write", write)
    with pytest.raises(Unavailable, match="independent anchor"):
        claim(lab, proof=offer(lab, "agent-a", "broker-a", old.generation))
    assert raw_receipts(lab) == []
    recovered = recover(lab)
    assert recovered["generation"] > current.generation
    replacement = claim(lab)
    assert replacement.generation > recovered["generation"]
    lab.call("agent-a", "broker-a", "/write", plan(lab, replacement))


def test_target_restarts_during_partial_transfer(lab):
    old = claim(lab)
    pending = plan(lab, old, "target-b")
    recover(lab)
    lab.stop("target-b")
    attempt = offer(lab, "agent-b", "broker-b")
    with pytest.raises(Unavailable):
        claim(lab, "agent-b", "broker-b", proof=attempt)
    state = lab.call("operator", "home", "/status")
    assert state["phase"] == "preparing"
    assert read(lab, "target-a")["generation"] == state["generation"] > old.generation
    lab.stop("target-a")
    lab.start("target-a")
    assert read(lab, "target-a")["generation"] == state["generation"]
    lab.start("target-b")
    before = read(lab, "target-b")
    pending = pending.model_copy(update={"command": command(pending.approval.body.mutation,
                                                            lab.instances["agent-a"])})
    with pytest.raises(Denied, match="restart requires a fresh home fence"):
        lab.call("broker-a", "target-b", "/write", pending)
    assert read(lab, "target-b") == before
    retry = offer(lab, "agent-b", "broker-b", attempt.body.expected_generation)
    new = claim(lab, "agent-b", "broker-b", proof=retry)
    assert new.generation == state["generation"]
    assert all(read(lab, t)["generation"] == new.generation for t in lab.targets)


def test_old_approval_cannot_authorize_new_generation(lab):
    old = claim(lab)
    former_approval = plan(lab, old).approval
    recover(lab)
    latest = claim(lab)
    new = plan(lab, latest)
    with pytest.raises(Denied, match="exact target and assignment"):
        lab.call("agent-a", "broker-a", "/write", new.model_copy(update={"approval": former_approval}))
    assert raw_receipts(lab) == []
    lab.call("agent-a", "broker-a", "/write", new)


def test_broker_and_signing_roles_are_separate(lab):
    proposal = offer(lab, "agent-a", "broker-a")
    forwarded = Admission(proof=proposal, credential_until_ns=time_ns() + 30_000_000_000)
    for caller in ("agent-a", "broker-b", "observer"):
        with pytest.raises(Denied, match="TLS identity"):
            lab.call(caller, "home", "/claim", forwarded)
    wrong_server = Endpoint(lab.endpoints["broker-b"].host, lab.endpoints["broker-b"].port, "broker-a")
    with pytest.raises(AuthenticationFailed, match="server URI"):
        lab.client("agent-a").call(wrong_server, "/claim", proposal)
    assigned = claim(lab, proof=proposal)
    artifact_key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    finding = Finding(
        schema_version="1.0", artifact_id=uuid4(), publisher_id="synthetic-publisher", sequence=1,
        issued_at=now, expires_at=now + timedelta(seconds=60), vulnerability_id="LAB-MARKER",
        software={"purl": "pkg:generic/aegis-synthetic", "affected_versions": ["1.0"]},
        evidence=[{"uri": "urn:aegis:fixture", "sha256": "0" * 64, "method": "source-review"}],
        applicability="authorized-lab", mitigation_template="lab-marker",
    )
    verify(sign(finding, artifact_key), artifact_key.public_key(), now)
    with pytest.raises(ValueError, match="invalid signature"):
        verify(sign(finding, lab.instances["agent-a"]), artifact_key.public_key(), now)
    with pytest.raises(Denied, match="signature"):
        lab.call("agent-a", "broker-a", "/write", plan(lab, assigned, key=artifact_key))
    invalid = plan(lab, assigned)
    fake_approval = approve(invalid.approval.body.mutation, lab.instances["agent-a"])
    with pytest.raises(Denied, match="signature"):
        lab.call("agent-a", "broker-a", "/write", invalid.model_copy(update={"approval": fake_approval}))
    fence = Fence(assignment=assigned, target="target-a")
    for route in ("/fence", "/retire"):
        with pytest.raises(Denied, match="TLS identity"):
            lab.call("broker-a", "target-a", route, fence)
    with pytest.raises(Denied, match="TLS identity"):
        lab.call("target-b", "home", "/authority", fence)
    assert raw_receipts(lab) == []


@pytest.mark.parametrize("lab", [2_000_000_000], indirect=True)
def test_lease_expiry_allows_new_broker_without_operator(lab):
    old = claim(lab)
    sleep(max(0, (old.expires_ns - time_ns()) / 1_000_000_000))
    assert all(row["fence"]["loss"]["reason"] == "expired" for row in wait_held(lab).values())
    assert read(lab)["effective"] == "quarantined"
    new = claim(lab, "agent-b", "broker-b")
    assert new.deployment == old.deployment and new.generation == old.generation + 1
    assert all(read(lab, target)["generation"] == new.generation for target in lab.targets)


def test_restored_anchor_cannot_reset_newer_home_floor(lab, tmp_path):
    old = claim(lab)
    lab.stop("anchor")
    snapshot = tmp_path / "anchor.sqlite"
    copyfile(lab.database("anchor"), snapshot)
    lab.start("anchor")
    recover(lab)
    assigned = claim(lab, "agent-b", "broker-b")
    lab.stop("anchor")
    copyfile(snapshot, lab.database("anchor"))
    lab.start("anchor")
    assert anchor(lab).generation == old.generation < assigned.generation
    with pytest.raises(Unavailable, match="local ownership floor"):
        recover(lab)
    with pytest.raises((Denied, Unavailable), match="independent anchor|held writer"):
        lab.call("agent-b", "broker-b", "/write", plan(lab, assigned))
    assert raw_receipts(lab) == []


def test_restarted_writer_holds_after_same_generation_restore(lab, tmp_path):
    assigned = claim(lab)
    request = plan(lab, assigned)
    snapshot = tmp_path / "target.sqlite"
    with sqlite3.connect(lab.database("target-a")) as live, sqlite3.connect(snapshot) as backup:
        live.backup(backup)
    lab.call("agent-a", "broker-a", "/write", request)
    assert raw_receipts(lab) == [(assigned.generation, "observing")]
    lab.stop("target-a")
    copyfile(snapshot, lab.database("target-a"))
    lab.start("target-a")
    assert read(lab)["generation"] == assigned.generation
    assert read(lab)["effective"] == "quarantined"
    with pytest.raises(Denied, match="restart requires a fresh home fence"):
        lab.call("broker-a", "target-a", "/write", request)
    assert raw_receipts(lab) == []
    recover(lab)
    successor = claim(lab, "agent-b", "broker-b")
    lab.call("agent-b", "broker-b", "/write", plan(lab, successor))
    assert raw_receipts(lab) == [(successor.generation, "observing")]


def disk_state(lab, target):
    with closing(sqlite3.connect(lab.database(target).as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        raw, = db.execute("SELECT body FROM record").fetchone()
        version, marker = db.execute("SELECT version,value FROM marker").fetchone()
        receipts = db.execute("SELECT generation,marker FROM receipts ORDER BY rowid").fetchall()
    return {"fence": json.loads(raw) if raw is not None else None, "version": version,
            "marker": marker, "receipts": receipts}


def wait_held(lab, targets=None, *, timeout=3):
    targets = targets or lab.targets
    until = monotonic() + timeout
    while monotonic() < until:
        state = {target: disk_state(lab, target) for target in targets}
        if all(row["fence"]["held"] for row in state.values()):
            return state
        sleep(0.01)
    raise AssertionError(f"durable hold did not appear: {state}")


def test_lost_anchor_latches_quarantine_before_any_serving_request(lab):
    assigned = claim(lab)
    prior = {}
    for target in lab.targets:
        lab.call("agent-a", "broker-a", "/write", plan(lab, assigned, target))
        prior[target] = plan(lab, assigned, target)
        assert disk_state(lab, target)["marker"] == "observing"
    lab.stop("anchor")
    # There is no /read, write, broker operation or health check in this window.
    held = wait_held(lab)
    for target, row in held.items():
        assert row["marker"] == "quarantined"
        assert row["fence"]["loss"]["reason"] == "authority-unavailable"
        assert row["receipts"] == [(assigned.generation, "observing")]
        assert read(lab, target)["effective"] == "quarantined"
        assert disk_state(lab, target) == row

    lab.start("anchor")
    assert lab.call("operator", "home", "/status")["generation"] == assigned.generation
    for target, request in prior.items():
        with pytest.raises(Denied, match="held writer requires a new generation"):
            lab.call("agent-a", "broker-a", "/write", request)
        assert disk_state(lab, target) == held[target]
    recover(lab)
    successor = claim(lab, "agent-b", "broker-b")
    for target in lab.targets:
        fresh = plan(lab, successor, target)
        with pytest.raises(Denied, match="exact target and assignment"):
            lab.call("agent-b", "broker-b", "/write",
                     fresh.model_copy(update={"approval": prior[target].approval}))
        lab.call("agent-b", "broker-b", "/write", fresh)
        assert raw_receipts(lab, target)[-1] == (successor.generation, "observing")


def test_serving_denial_does_not_commit_hold_while_writer_lock_is_owned(lab):
    assigned = claim(lab)
    for target in lab.targets:
        lab.call("agent-a", "broker-a", "/write", plan(lab, assigned, target))
    with closing(sqlite3.connect(lab.database("target-a"))) as lock:
        lock.execute("BEGIN IMMEDIATE")
        lab.stop("anchor")
        before = disk_state(lab, "target-a")
        response = read(lab, "target-a")
        assert response["effective"] == "quarantined" and response["marker"] == "observing"
        assert not before["fence"]["held"] and disk_state(lab, "target-a") == before
        lock.rollback()
    assert len(wait_held(lab)) == 2


def test_live_retirement_waits_for_all_target_barriers(lab):
    old = claim(lab)
    lab.call("agent-a", "broker-a", "/write", plan(lab, old))
    prior = plan(lab, old)
    lab.stop("target-b")
    with pytest.raises(Unavailable):
        recover(lab)
    still_active = lab.call("operator", "home", "/status")
    assert still_active["phase"] == "active" and still_active["generation"] == old.generation
    assert disk_state(lab, "target-a")["fence"]["loss"]["reason"] == "retired"
    with pytest.raises(Denied, match="held writer"):
        lab.call("broker-a", "target-a", "/write", prior)
    lab.start("target-b")
    assert recover(lab)["generation"] > old.generation
    assert disk_state(lab, "target-b")["fence"]["held"]



@pytest.mark.parametrize("failure", ["home-unavailable", "watchdog-denial"])
def test_final_write_guard_rolls_back_buffered_effect_and_receipt(lab, monkeypatch, failure):
    assigned = claim(lab)
    request = plan(lab, assigned)
    before = disk_state(lab, "target-a")
    writer = Target("target-a", lab.database("target-a"), lab.policy, lab.client("target-a"),
                    lab.endpoints, boot=before["fence"]["boot"])
    checked = writer.require_current

    def lose_authority(assignment):
        # The protected marker and receipt have been staged but remain invisible to
        # another SQLite connection at the moment the last authority check runs.
        assert disk_state(lab, "target-a") == before
        if failure == "home-unavailable":
            raise Unavailable("simulated authority loss during writer transaction")
        checked(assignment)
        writer.remember_loss(assignment, "authority-unavailable")

    monkeypatch.setattr(writer, "require_current", lose_authority)
    peer = Peer(principal("broker-a"), "", assigned.expires_ns)
    with pytest.raises(Unavailable if failure == "home-unavailable" else Denied):
        writer.write(peer, request)
    after = disk_state(lab, "target-a")
    assert after["marker"] == "quarantined" and after["receipts"] == []
    assert after["version"] == before["version"]
    if failure == "home-unavailable":
        assert after["fence"]["held"]



def test_commit_refuses_to_wait_on_reader_after_authorizing(lab):
    assigned = claim(lab)
    request = plan(lab, assigned)
    before = disk_state(lab, "target-a")
    with closing(sqlite3.connect(lab.database("target-a").as_uri() + "?mode=ro", uri=True)) as reader:
        reader.execute("BEGIN")
        assert reader.execute("SELECT value FROM marker").fetchone() == ("quarantined",)
        with pytest.raises(Unavailable, match="durable store unavailable"):
            lab.call("agent-a", "broker-a", "/write", request)
        assert reader.execute("SELECT COUNT(*) FROM receipts").fetchone() == (0,)
    assert disk_state(lab, "target-a") == before
    lab.call("agent-a", "broker-a", "/write", request)
    assert raw_receipts(lab) == [(assigned.generation, "observing")]
