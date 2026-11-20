"""Regression for partial withdrawal intake in the isolated common-cut shadow profile."""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from aegis.evidence.runner import ENVIRONMENT_SHA256
from aegis.journal.protocol import JournalBlocked, digest, vote
from aegis.phase4e.protocol import Leaf, SignedStatus, Wire, WithdrawalView, message, withdrawal_binding
from aegis.phase4e.status import Gate
from scripts.phase4e_lab import Lab


def seal_three(lab):
    finding, bundle = lab.seed()
    head = lab.propose(int(lab.reader.clock.sample().upper // lab.epoch_width))
    cut = lab.seal(head, ("w1", "w2", "w3"))
    assert len(cut.votes) == 3
    lab.policy.journal.check_cut(cut)
    positive = lab.status(finding, bundle)
    assert positive.body.outcome == "reproduced"
    return finding, bundle, positive


def direct(lab, wire):
    return lab.admissions["review", "lab-v1"]["w0"].call("/admit", Leaf, wire)


def witness_view(lab, challenge, leaves):
    signature = lab.keys["w0"].sign(message("withdrawal-view.v2", withdrawal_binding(challenge, "w0", leaves)))
    return WithdrawalView(witness="w0", leaves=leaves, signature=signature.hex())


@pytest.mark.parametrize(("profile", "expected"), [("checkpoint-v1", "reproduced"), ("withdrawal-v2", "inconclusive")])
def test_one_witness_withdrawal_overrides_the_same_checkpoint(profile, expected):
    with TemporaryDirectory(prefix="p4e-vote-", dir="/tmp") as path, Lab(Path(path), profile=profile) as lab:
        finding, bundle, previous = seal_three(lab)
        leaf = direct(lab, lab.evidence_withdrawal(bundle))
        assert len(leaf.receipt.votes) == 1
        result = lab.status(finding, bundle)
        assert result.body.head == previous.body.head
        assert result.body.outcome == expected
        if profile == "withdrawal-v2":
            assert result.body.reason == "revoked"
            with pytest.raises(JournalBlocked):
                with lab.gate.authorize(result, previous.binding):
                    pytest.fail("an old approval became usable after withdrawal")


def test_four_fresh_lanes_even_if_three_checkpoint_signers_available():
    with TemporaryDirectory(prefix="p4e-off-", dir="/tmp") as path, Lab(Path(path), profile="withdrawal-v2") as lab:
        finding, bundle, positive = seal_three(lab)
        lab.stop("w0")  # No quorum voter was stopped.
        with pytest.raises(JournalBlocked, match="all enrolled witnesses"):
            lab.status(finding, bundle)
        with pytest.raises(JournalBlocked):
            lab.gate.require_current(positive)
        lab.start("w0")
        assert lab.status(finding, bundle).body.outcome == "reproduced"


def test_authenticated_snapshot_replay_and_forged_withdrawal_cannot_latch():
    with TemporaryDirectory(prefix="p4e-proof-", dir="/tmp") as path, Lab(Path(path), profile="withdrawal-v2") as lab:
        finding, bundle, _ = seal_three(lab)
        other = lab.evidence.bundle("unrelated exact scope")
        unrelated = direct(lab, lab.evidence_withdrawal(other))
        assert lab.status(finding, bundle).body.outcome == "reproduced"

        # The witness can sign a snapshot and a receipt, but lacks the revoker's
        # signature over a changed body naming the target bundle.
        tampered = Wire.from_bytes("evidence", unrelated.wire.raw.replace(other.sha256.encode(), bundle.sha256.encode()))
        admission = unrelated.receipt.admission.model_copy(update={"event": digest(tampered)})
        forged = Leaf(wire=tampered, receipt={
            "admission": admission, "votes": (vote("w0", lab.keys["w0"], admission),),
        })
        lane = lab.reader.withdrawals
        original = lane.sources["w0"]
        issued = lab.evidence_withdrawal(bundle)
        admission = admission.model_copy(update={"event": digest(issued)})
        wrong_witness = Leaf(wire=issued, receipt={
            "admission": admission, "votes": (vote("w1", lab.keys["w1"], admission),),
        })
        for invalid in (forged, wrong_witness):
            lane.sources["w0"] = lambda challenge: witness_view(lab, challenge, (invalid,))
            with pytest.raises(JournalBlocked, match="all enrolled witnesses"):
                lab.status(finding, bundle)
        assert set(lane.records) == {unrelated.receipt.admission.event}

        captured = []

        def capture(challenge):
            captured.append(original(challenge))
            return captured[0]

        lane.sources["w0"] = capture
        assert lab.status(finding, bundle).body.outcome == "reproduced"
        lane.sources["w0"] = lambda _: captured[0]
        with pytest.raises(JournalBlocked, match="all enrolled witnesses"):
            lab.status(finding, bundle)


def test_single_receipt_survives_missing_lane_retraction_and_rollback():
    with TemporaryDirectory(prefix="p4e-pin-", dir="/tmp") as path, Lab(Path(path), profile="withdrawal-v2") as lab:
        finding, bundle, positive = seal_three(lab)
        path = Path(lab.reader_settings["withdrawals"]["db"])
        old = path.read_bytes()
        leaf = direct(lab, lab.evidence_withdrawal(bundle))
        lab.stop("w3")
        observer = lab.new_reader()
        independent_gate = Gate(observer, lab.publisher.status, "lab-writer")
        with pytest.raises(JournalBlocked, match="all enrolled witnesses"):
            independent_gate.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256)
        assert leaf.receipt.admission.event in observer.withdrawals.records
        with pytest.raises(JournalBlocked):
            lab.gate.require_current(positive)
        lab.start("w3")
        lab.stop("w0")
        lab.start("w0")

        restarted = lab.new_reader()
        restarted.withdrawals.sources["w0"] = lambda challenge: witness_view(lab, challenge, ())
        gate = Gate(restarted, lab.publisher.status, "lab-writer")
        assert gate.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256).body.reason == "revoked"

        def obsolete_positive(challenge):
            body = positive.body.model_copy(update={"challenge": digest(challenge)})
            signature = lab.keys["status"].sign(message("status", body)).hex()
            return SignedStatus(body=body, signature=signature)

        gate.fetch_status = obsolete_positive
        with pytest.raises(JournalBlocked, match="disagrees"):
            gate.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256)

        restarted.withdrawals.ledger.close()
        observer.withdrawals.ledger.close()
        lab.reader.withdrawals.ledger.close()
        path.write_bytes(old)
        with pytest.raises(JournalBlocked, match="protected pin"):
            lab.new_reader()
