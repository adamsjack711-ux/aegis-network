"""Run the Phase 4E-C adversarial cases over distinct local service processes."""

from contextlib import closing
from dataclasses import replace
from pathlib import Path
import shutil
import sqlite3
from tempfile import TemporaryDirectory
import time

import pytest

from aegis.evidence.runner import ENVIRONMENT_SHA256
from aegis.journal.protocol import Clock, Cut, JournalBlocked, digest, vote
from aegis.phase4e.history import receipt_coverage
from aegis.phase4e.protocol import Floor, Leaf, SignedStatus, View, message, view_binding
from aegis.phase4e.service import load_policy
from aegis.phase4e.status import Gate, finding_wire
from scripts.phase4e_lab import Lab


@pytest.fixture
def lab():
    # Darwin limits Unix socket paths to 103 bytes.
    with TemporaryDirectory(prefix="p4e-", dir="/tmp") as path, Lab(Path(path)) as running:
        yield running


def healthy(lab):
    finding, bundle = lab.seed()
    cut = lab.seal_latest()
    lab.policy.journal.check_cut(cut)
    assert lab.status(finding, bundle).body.outcome == "reproduced"
    return finding, bundle, cut


def test_direct_receipt_withholding_and_independent_proof(lab):
    finding, bundle, old = healthy(lab)
    withdrawal = lab.mesh_withdrawal(finding)
    leaf = lab.receive(withdrawal, ("mesh-review", "old"), ("w0", "w1", "w2"))
    with pytest.raises(JournalBlocked, match="quorum"):
        lab.status(finding, bundle)

    epoch = leaf.receipt.admission.epoch
    withheld = lab.propose(epoch)
    assert len(lab.seal(withheld, allow_failure=True).votes) == 1
    now = lab.policy.journal.cutoff(epoch) + lab.policy.journal.merge_seconds
    assert receipt_coverage(lab.policy, leaf, None, None, (), now) == "missing-proof"
    with pytest.raises(JournalBlocked):
        lab.status(finding, bundle)

    index, _ = lab.append(leaf)
    cut = lab.seal(lab.propose(epoch + 1))
    assert cut.head.size > old.head.size
    path = lab.archive[1].call(f"/proof/{cut.head.size}/{index}")
    proof = tuple(bytes.fromhex(node) for node in path)
    assert receipt_coverage(lab.policy, leaf, cut, index, proof, now) == "included-late"
    assert receipt_coverage(lab.policy, leaf, cut, index, proof[:-1], now) == "missing-proof"
    assert lab.status(finding, bundle).body.reason == "mesh-withdrawn"


def test_evidence_revocation_blocks_peer_commit_after_canary(lab):
    finding, bundle, _ = healthy(lab)
    plan = lab.status(finding, bundle).binding
    with closing(sqlite3.connect(lab.path / "disposable-writer.db")) as writer:
        writer.execute("CREATE TABLE restrictions (target TEXT PRIMARY KEY, expires REAL)")
        expires = time.monotonic() + 60

        def protect(target):
            status = lab.status(finding, bundle)
            with lab.gate.authorize(status, plan), writer:
                writer.execute("INSERT INTO restrictions VALUES (?, ?)", (target, expires))
                lab.gate.require_current(status)

        protect("canary")
        with closing(sqlite3.connect(lab.path / "disposable-writer.db")) as independent_readback:
            assert independent_readback.execute("SELECT target, expires FROM restrictions").fetchall() == [
                ("canary", expires),
            ]
        assert expires > time.monotonic()
        leaf = lab.receive(lab.evidence_withdrawal(bundle), ("review", "lab-v1"))
        with pytest.raises(JournalBlocked):
            protect("peer")
        lab.append(leaf)
        lab.seal(lab.propose(leaf.receipt.admission.epoch))
        assert lab.status(finding, bundle).body.reason == "revoked"
        with pytest.raises(JournalBlocked):
            protect("peer")
        assert writer.execute("SELECT target, expires FROM restrictions").fetchall() == [("canary", expires)]


def test_obsolete_positive_status_even_with_publisher_signature(lab):
    finding, bundle, original = healthy(lab)
    previous = lab.status(finding, bundle)
    next_cut = lab.seal(lab.propose(original.head.epoch + 1))
    assert next_cut.head.root == original.head.root

    def obsolete(challenge):
        body = previous.body.model_copy(update={"challenge": digest(challenge)})
        return SignedStatus(body=body, signature=lab.keys["status"].sign(message("status", body)).hex())

    with pytest.raises(JournalBlocked, match="disagrees"):
        Gate(lab.reader, obsolete, "lab-writer").refresh(
            finding, bundle, expected_environment=ENVIRONMENT_SHA256,
        )
    assert Floor.model_validate_json(lab.reader.pin.read()).verified == next_cut.signed
    status = lab.status(finding, bundle)
    with lab.gate.authorize(status, status.binding):
        lab.gate.require_current(status)
    with pytest.raises(JournalBlocked):
        with lab.gate.authorize(status, status.binding):
            pytest.fail("verified status could be reused for a second write")


def test_role_credentials_and_signed_scope_cannot_be_substituted(lab):
    finding, bundle, _ = healthy(lab)
    withdrawal = lab.evidence_withdrawal(bundle)
    publisher = lab.admissions["research", "lab-v1"]["w0"]
    verifier = lab.admissions["verifier-a", "lab-v1"]["w0"]
    for endpoint in (publisher, verifier, lab.operators["w0"]):
        with pytest.raises(OSError, match="403"):
            endpoint.call("/admit", Leaf, withdrawal)
    with pytest.raises(OSError, match="403"):
        publisher.call("/seal", data={})
    with pytest.raises(ValueError, match="material pin"):
        lab.status(finding, replace(bundle, objects=bundle.objects | {"subject": b"x"}))
    with pytest.raises(OSError, match="403"):
        gate = Gate(lab.reader, lab.publisher.status, "other-writer")
        gate.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256)
    wrong_environment = lab.gate.refresh(finding, bundle, expected_environment="f" * 64)
    assert wrong_environment.body.reason == "scope-mismatch"
    with pytest.raises(JournalBlocked):
        lab.gate.require_current(wrong_environment)


def test_quorum_loss_and_isolation_deadline(lab):
    finding, bundle, _ = healthy(lab)
    lab.stop("w3")
    earlier = lab.status(finding, bundle)
    assert earlier.body.outcome == "reproduced"
    lab.stop("w2")
    with pytest.raises(JournalBlocked, match="quorum"):
        lab.status(finding, bundle)
    with pytest.raises(JournalBlocked):
        lab.gate.require_current(earlier)
    lab.start("w2")
    active = lab.status(finding, bundle)
    for name in ("w0", "w1", "w2", "status"):
        lab.stop(name)
    time.sleep(max(0, active.deadline - time.monotonic()) + 0.02)
    with pytest.raises(JournalBlocked):
        lab.gate.require_current(active)
    with pytest.raises(JournalBlocked):
        lab.status(finding, bundle)


def test_mirror_reconciles_archive_corruption_and_old_witness_restore(lab):
    finding, bundle, original = healthy(lab)
    old = lab.path / "before.db"
    shutil.copyfile(lab.path / "w0.db", old)
    leaf = lab.receive(lab.evidence_withdrawal(bundle), ("review", "lab-v1"))
    lab.append(leaf)
    cut = lab.seal(lab.propose(leaf.receipt.admission.epoch))
    mirror_db = lab.path / "mirror.db"
    mirror_backup = mirror_db.read_bytes()
    for path in (lab.path / "arc.db", mirror_db):
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("UPDATE leaves SET wire = X'7B7D' WHERE position = 0")
    with pytest.raises(JournalBlocked, match="no archive"):
        lab.status(finding, bundle)
    assert Floor.model_validate_json(lab.reader.pin.read()).pending == cut.signed
    mirror_db.write_bytes(mirror_backup)
    assert lab.status(finding, bundle).body.reason == "revoked"
    lab.stop("w0")
    shutil.copyfile(old, lab.path / "w0.db")
    with pytest.raises(RuntimeError, match="protected pin"):
        lab.start("w0")

    # A restored reader still uses the separately retained floor. Supply a
    # cryptographically current but obsolete cut to exercise rollback explicitly.
    reader = lab.new_reader()

    def old_view(name):
        return lambda challenge: forged_view(lab, name, challenge, original.signed)

    reader.witnesses = {name: old_view(name) for name in lab.names}
    gate = Gate(reader, lab.publisher.status, "lab-writer")
    with pytest.raises(JournalBlocked, match="rolls back"):
        gate.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256)
    assert Floor.model_validate_json(reader.pin.read()).verified == cut.signed


def forged_view(lab, name, challenge, signed):
    key = lab.keys[name]
    return View(signed=signed, coverage=vote(name, key, signed),
                signature=key.sign(message("view", view_binding(challenge, signed))).hex())


def test_fork_intersection_and_two_colluders(lab):
    finding, bundle, original = healthy(lab)
    extra, _ = lab.fixture(sequence=2)
    leaf = lab.receive(finding_wire(extra), ("author", "mesh"), ("w0", "w1", "w2"))
    lab.append(leaf, indexes=(0,))
    epoch = leaf.receipt.admission.epoch
    left = lab.propose(epoch, index=0)
    right = lab.propose(epoch, index=1)
    lab.policy.journal.check_cut(lab.seal(left, ("w0", "w1", "w2")))
    assert len(lab.seal(right, ("w0", "w1", "w2", "w3"), allow_failure=True).votes) == 1

    # Two arbitrary signers can certify both forks with disjoint honest
    # partners. This violates f=1 even when keys and enrollment names differ.
    fake = tuple(sorted((vote(name, lab.keys[name], right) for name in ("w0", "w1", "w3")),
                        key=lambda v: v.operator))
    lab.policy.journal.check_cut(Cut(signed=right, votes=fake))
    lab.reader.witnesses["w0"] = lambda challenge: forged_view(lab, "w0", challenge, right)
    with pytest.raises(JournalBlocked, match="conflicting signed checkpoints"):
        lab.status(finding, bundle)
    assert Floor.model_validate_json(lab.reader.pin.read()).fork is not None

    config = lab.config | {"witnesses": lab.config["witnesses"] | {
        "w1": lab.config["witnesses"]["w1"] | {"domain": lab.config["witnesses"]["w0"]["domain"]},
    }}
    with pytest.raises(ValueError, match="separate authority domains"):
        load_policy(config)


def test_historical_withdrawal_replay_and_key_rotation():
    with TemporaryDirectory(prefix="p4e-", dir="/tmp") as path, Lab(Path(path), retirement=10) as lab:
        finding, bundle = lab.seed()
        wire = lab.mesh_withdrawal(finding)
        leaf = lab.receive(wire, ("mesh-review", "old"))
        evidence_wire = lab.evidence_withdrawal(bundle)
        evidence_leaf = lab.receive(evidence_wire, ("review", "lab-v1"))
        lab.append(leaf)
        lab.append(evidence_leaf)
        lab.seal(lab.propose(evidence_leaf.receipt.admission.epoch))
        assert lab.status(finding, bundle).body.reason == "mesh-withdrawn"

        time.sleep(max(0, lab.retired - time.time()) + 0.02)
        with pytest.raises(OSError, match="409"):
            lab.admissions["mesh-review", "old"]["w0"].call("/admit", Leaf, wire)
        with pytest.raises(OSError, match="409"):
            lab.admissions["review", "lab-v1"]["w0"].call("/admit", Leaf, evidence_wire)
        recovered = lab.operators["w0"].call(
            f"/receipts/{leaf.receipt.admission.epoch}/{leaf.receipt.admission.event}", Leaf,
        )
        assert recovered.wire == wire
        next_wire = lab.mesh_withdrawal(finding, key="new", sequence=2)
        next_leaf = lab.receive(next_wire, ("mesh-review", "new"))
        lab.append(next_leaf)
        new_evidence = lab.receive(lab.evidence_withdrawal(bundle, "lab-v2"), ("review", "lab-v2"))
        lab.append(new_evidence)
        lab.seal(lab.propose(new_evidence.receipt.admission.epoch))
        reader = lab.new_reader()
        restarted = Gate(reader, lab.publisher.status, "lab-writer")
        verified = restarted.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256)
        assert verified.body.reason == "mesh-withdrawn"


def test_withdrawal_reserve_and_durable_exhaustion(tmp_path, monkeypatch):
    from aegis.journal.storage import EMPTY_CHAIN, SQLitePin
    from aegis.phase4e import history

    monkeypatch.setattr(history, "MAX_ORDINARY", 0)
    monkeypatch.setattr(history, "MAX_RECORDS", 1)
    lab = Lab(tmp_path)
    try:
        finding, _ = lab.fixture()
        pin = SQLitePin(tmp_path / "pin.db", "w0")
        pin.provision(EMPTY_CHAIN)
        args = ("w0", lab.keys["w0"], lab.policy, Clock(), tmp_path / "w0.db", pin, ())
        witness = history.Witness(*args)
        with closing(witness.ledger):
            with pytest.raises(JournalBlocked, match="capacity"):
                witness.admit(finding_wire(finding), ("publish", "author", "mesh"))
            role = "revoke", "mesh-review", "old"
            first = lab.mesh_withdrawal(finding)
            witness.admit(first, role)
            with pytest.raises(JournalBlocked, match="capacity"):
                witness.admit(lab.mesh_withdrawal(finding, sequence=2), role)
        restarted = history.Witness(*args)
        with closing(restarted.ledger), pytest.raises(JournalBlocked, match="awaiting"):
            assert restarted.exhausted
            restarted.view(None)
    finally:
        lab.stack.close()
