from concurrent.futures import ThreadPoolExecutor
import shutil
import sqlite3

import pytest

from aegis.evidence.records import digest
from aegis.trust_lab.evaluator import Evaluator, ForkRecord
from aegis.trust_lab.history import Admission, Appraisal, Leaf, Subject, Witness
from aegis.trust_lab.identity import Compromise, Hold, commitment

from trust_fixtures import Scenario


@pytest.fixture
def lab(tmp_path):
    return Scenario(tmp_path)


def test_healthy_write_is_fenced_audited_and_one_use(lab):
    lab.seed()
    plan = lab.prepare()
    assert plan.subject == lab.subject
    assert lab.apply(plan)["restricted"] == 1
    assert lab.target.snapshot()["fence"] == 1
    with pytest.raises(Hold, match="fresh authenticated"):
        lab.apply(plan)
    assert [event for _, event, _ in lab.target.events()] == [
        "transfer", "reconciled", "restrict", "hold",
    ]


def test_withheld_receipted_withdrawal_blocks_a_quorum_with_one_colluder(lab):
    lab.seed()
    healthy = lab.prepare()
    lab.apply(healthy)
    cached = lab.leaves
    withdrawal = lab.event("withdraw", "mesh-withdrawal", "revoker")
    lab.admit(withdrawal)

    # The already closed epoch has no claim over this new admission.
    challenge = lab.begin()
    old_cut = lab.cut(challenge, leaves=cached)
    assert lab.reconcile(challenge, old_cut, status=lab.status(old_cut)).expires == lab.clock.wall() + 1
    lab.clock.advance()
    challenge = lab.begin()
    censored = lab.cut(challenge, leaves=cached, signers=("w1", "w2", "w3"))
    malicious = lab.sign("w0", "coverage", censored.body)
    assert tuple(s.key for s in censored.signatures) == ("w3",)
    censored = censored.model_copy(update={"signatures": (*censored.signatures, malicious)})
    with pytest.raises(Hold, match="missing quorum"):
        lab.reconcile(challenge, censored)

    # An independent archive can recover the full cut, which installs the denial.
    challenge = lab.begin()
    complete = lab.cut(challenge)
    with pytest.raises(Hold, match="mesh withdrawal"):
        lab.reconcile(challenge, complete, status=lab.status(complete))
    assert lab.target.snapshot()["fence"] == 1
    assert lab.target.snapshot()["restricted"] == 1


def test_complete_checkpoint_with_omitted_leaf_holds(lab):
    lab.seed()
    challenge = lab.begin()
    cut = lab.cut(challenge)
    incomplete = cut.model_copy(update={"leaves": cut.leaves[:-1]})
    with pytest.raises(Hold, match="incomplete archive"):
        lab.reconcile(challenge, incomplete, status=lab.status(cut))
    assert lab.target.snapshot()["fence"] == 0
    assert lab.apply(lab.prepare())["restricted"] == 1


@pytest.mark.parametrize("bad_key", ["publisher", "duplicate"])
def test_unauthorized_or_duplicate_witness_is_rejected(lab, bad_key):
    lab.seed()
    challenge = lab.begin()
    valid = lab.cut(challenge)
    signatures = valid.signatures[:2]
    extra = lab.sign(bad_key, "coverage", valid.body) if bad_key != "duplicate" else signatures[0]
    bad = valid.model_copy(update={"signatures": (*signatures, extra)})
    with pytest.raises(Hold, match="duplicate or unauthorized"):
        lab.reconcile(challenge, bad, status=lab.status(valid))
    assert lab.target.snapshot()["fence"] == 0


def test_same_epoch_fork_requires_broken_fault_bound_and_latches(lab):
    lab.seed()
    prefix = lab.leaves

    def fork(event, honest):
        body, signature = lab.witnesses[honest].admit(event, lab.chain)
        forged = tuple(lab.sign(key, "admission", body) for key in ("w0", "w1"))
        return (*prefix, Leaf(body=body, event=event, signatures=(signature, *forged)))

    left = fork(lab.event("left", "finding", "publisher", subject=Subject(
        finding=digest(b"left"), evidence=digest(b"evidence"))), "w2")
    right = fork(lab.event("right", "finding", "publisher", subject=Subject(
        finding=digest(b"right"), evidence=digest(b"evidence"))), "w3")
    lab.clock.advance()

    def split_cut(challenge, branch, honest):
        cut = lab.cut(challenge, leaves=branch, signers=(honest,))
        assert len(cut.signatures) == 1
        bad = tuple(lab.sign(key, "coverage", cut.body) for key in ("w0", "w1"))
        return cut.model_copy(update={"signatures": (*cut.signatures, *bad)})

    challenge = lab.begin()
    cut = split_cut(challenge, left, "w2")
    lab.reconcile(challenge, cut, status=lab.status(cut))
    challenge = lab.begin()
    bad = split_cut(challenge, right, "w3")
    with pytest.raises(Hold, match="fork"):
        lab.reconcile(challenge, bad, status=lab.status(bad))
    with pytest.raises(Hold, match="latched history fork"):
        lab.begin(Evaluator(lab.target, "operator"))
    with sqlite3.connect(lab.target.anchor) as db:
        wire = db.execute("SELECT fork FROM anchor").fetchone()[0]
    record = ForkRecord.model_validate_json(wire)
    assert record.accepted == cut.body and record.conflicting == bad.body
    assert record.accepted_signatures == cut.signatures and record.conflicting_signatures == bad.signatures
    assert lab.target.snapshot()["fence"] == 0


def test_witness_restart_preserves_receipts_and_missing_state_cannot_sign(lab):
    lab.seed()
    old_leaves = lab.leaves
    lab.admit(lab.event("withdraw", "mesh-withdrawal", "revoker"))
    original = lab.witnesses["w0"]
    reopened = Witness(original.path, "w0", lab.keys["w0"], lab.root, lab.clock)
    lab.witnesses["w0"] = reopened
    lab.clock.advance()
    challenge = lab.begin()
    withheld = lab.cut(challenge, leaves=old_leaves, signers=())
    with pytest.raises(Hold, match="receipted event missing"):
        reopened.endorse(withheld.body, old_leaves, lab.chain)
    original.path.unlink()
    with pytest.raises(sqlite3.OperationalError):
        reopened.endorse(withheld.body, old_leaves, lab.chain)
    fresh = lab.cut(challenge, signers=("w1", "w2", "w3"))
    assert len(fresh.signatures) == 3


def test_cross_broker_collision_and_transfer_fence(lab):
    lab.seed()
    earlier = lab.prepare()
    with pytest.raises(Hold, match="stale or expired target ownership"):
        lab.begin(Evaluator(lab.target, "operator"), broker="west")
    with pytest.raises(Hold, match="not enrolled"):
        lab.target.transfer(expected=1, holder="agent-b", broker="east", chain=lab.chain)

    def compete(holder):
        try:
            return lab.target.transfer(expected=1, holder=holder, broker="west", chain=lab.chain)
        except Hold:
            return None

    with ThreadPoolExecutor(2) as workers:
        results = list(workers.map(compete, ("agent-a", "agent-b")))
    assert sorted(r for r in results if r is not None) == [2]
    assert lab.target.snapshot()["fence"] == 0
    with pytest.raises(Hold, match="stale or expired target ownership"):
        lab.apply(earlier)
    winner = ("agent-a", "agent-b")[results.index(2)]
    assert lab.apply(lab.prepare(holder=winner, broker="west"))["generation"] == 2


def test_two_local_operations_cannot_reuse_a_target_fence(lab):
    lab.seed()
    other = Evaluator(lab.target, "operator")
    a, b = lab.prepare(), lab.prepare(other)
    lab.apply(a)
    with pytest.raises(Hold, match="target fence changed"):
        lab.apply(b, other)
    assert lab.target.snapshot()["fence"] == 1


def test_stale_or_forged_approval_never_commits(lab):
    lab.seed()
    plan = lab.prepare()
    stale = lab.approve(plan)
    new = lab.prepare()
    with pytest.raises(Hold, match="invalid signature"):
        lab.evaluator.apply(new, stale)
    new = lab.prepare()
    with pytest.raises(Hold, match="exact current local approval"):
        lab.evaluator.apply(new, lab.sign("publisher", "approval", new))
    assert lab.target.snapshot()["fence"] == 0


@pytest.mark.parametrize(("kind", "role", "reason"), [
    ("evidence-withdrawal", "revoker", "withdrawn"),
    ("contradiction", "verifier2", "contested"),
])
def test_evidence_denials_survive_event_expiry(lab, kind, role, reason):
    lab.seed()
    lab.admit(lab.event("denial", kind, role, expires=lab.clock.wall() + 1))
    lab.clock.advance(2)
    with pytest.raises(Hold, match=reason):
        lab.prepare()
    assert lab.target.snapshot()["fence"] == 0


def test_expired_positive_evidence_denies_new_authority(lab):
    lab.seed(expires=102)
    assert lab.prepare().expires == 102
    lab.clock.advance()
    with pytest.raises(Hold, match="unknown"):
        lab.prepare()
    assert lab.target.snapshot()["fence"] == 0


def test_signed_status_disagreement_blocks_pending_write_for_same_cut(lab):
    lab.seed()
    old = lab.prepare()
    other = Evaluator(lab.target, "operator")
    challenge = lab.begin(other)
    cut = lab.cut(challenge)
    valid = lab.status(cut)
    body = valid.body.model_copy(update={"appraisal": Appraisal(outcome="withdrawn")})
    disagreement = valid.model_copy(update={"body": body, "signature": lab.sign("status", "status", body)})
    with pytest.raises(Hold, match="status disagreement"):
        lab.reconcile(challenge, cut, status=disagreement, evaluator=other)
    with pytest.raises(Hold, match="known signed Evidence disagreement"):
        lab.apply(old)
    lab.clock.advance()
    assert lab.apply(lab.prepare())["restricted"] == 1


@pytest.mark.parametrize("mode", ["other-scope", "old-version", "expired", "wrong-issuer", "unavailable"])
def test_status_is_independent_fresh_and_exact(lab, mode):
    lab.seed()
    challenge = lab.begin()
    cut = lab.cut(challenge)
    signed = lab.status(cut)
    if mode == "other-scope":
        signed = lab.status(cut, subject=Subject(finding=lab.subject.finding, evidence=digest(b"other")))
    elif mode in {"old-version", "expired"}:
        change = {"version": signed.body.version - 1} if mode == "old-version" else {"expires": lab.clock.wall()}
        body = signed.body.model_copy(update=change)
        signed = signed.model_copy(update={"body": body, "signature": lab.sign("status", "status", body)})
    elif mode == "wrong-issuer":
        signed = lab.status(cut, key="publisher")
    else:
        signed = None
    with pytest.raises(Hold, match="Evidence status|lacks current scoped role"):
        lab.reconcile(challenge, cut, status=signed)
    assert lab.target.snapshot()["fence"] == 0


def test_offline_renewal_reconnect_and_holder_authentication(lab):
    lab.seed()
    lab.apply(lab.prepare())
    lab.clock.advance()
    cached_renewal = lab.prepare(operation="renew")
    before = lab.target.snapshot()
    lab.evaluator.disconnect()
    with pytest.raises(Hold, match="fresh authenticated"):
        lab.apply(cached_renewal)
    challenge = lab.begin()
    empty = lab.cut(challenge, signers=())
    with pytest.raises(Hold, match="missing quorum"):
        lab.reconcile(challenge, empty, operation="renew")
    assert lab.target.snapshot() == before

    challenge = lab.begin()
    cut = lab.cut(challenge)
    with pytest.raises(Hold, match="wrong holder proof"):
        lab.evaluator.reconcile(lab.sign("agent-b", "agent-proof", challenge), cut,
                                lab.status(cut), lab.chain, lab.subject, "renew")
    challenge = lab.begin()
    with pytest.raises(Hold, match="different challenge"):
        lab.reconcile(challenge, cut, status=lab.status(cut), operation="renew")
    assert lab.apply(lab.prepare(operation="renew"))["lease"] > before["lease"]


def test_monotonic_expiry_when_wall_clock_has_not_advanced(lab):
    lab.seed()
    plan = lab.prepare(operation="renew")
    lab.clock.ns += 1_000_000_000
    with pytest.raises(Hold, match="challenge expired"):
        lab.apply(plan)
    assert lab.target.snapshot()["lease"] == 110


def test_offline_reconnect_replays_old_withdrawal_after_key_rotation(lab):
    lab.seed()
    lab.apply(lab.prepare())
    lab.evaluator.disconnect()
    lab.admit(lab.event("old-withdrawal", "mesh-withdrawal", "revoker"))
    lab.clock.advance()
    old = lab.chain
    lab.grants = [grant for grant in lab.grants if grant.key != "revoker"]
    lab.add_key("revoker2", "revoker", starts=lab.clock.wall())
    lab.rotate()
    with pytest.raises(Hold, match="mesh withdrawal"):
        lab.prepare()
    fake_backdated = lab.event("backdated", "mesh-withdrawal", "revoker", issued=100)
    with pytest.raises(Hold, match="lacks current scoped role"):
        lab.witnesses["w0"].admit(fake_backdated, lab.chain)
    with pytest.raises(Hold, match="unavailable witness state"):
        lab.witnesses["w0"].admit(fake_backdated, old)
    assert lab.target.snapshot()["fence"] == 1


def test_compromise_cut_preserves_uncertain_historical_denial(lab):
    lab.seed()
    lab.admit(lab.event("negative", "evidence-withdrawal", "revoker"))
    lab.clock.advance()
    with pytest.raises(Hold, match="withdrawn"):
        lab.prepare()
    lab.clock.advance()
    lab.rotate(compromises=(Compromise(key="revoker", cutoff=101),))
    with pytest.raises(Hold, match="contested"):
        lab.prepare()
    assert lab.target.snapshot()["fence"] == 0


def test_untrusted_delegation_update_cannot_rotate_roles(lab):
    lab.seed()
    lab.rotate(signers=("root0",))
    with pytest.raises(Hold, match="missing quorum"):
        lab.root.appraise(lab.chain, lab.clock.wall())


def test_backdated_envelope_cannot_substitute_for_quorum_admission(lab):
    lab.seed()
    cut_start = lab.clock.wall()
    event = lab.event("ghost", "mesh-withdrawal", "revoker", issued=100)
    body = Admission(scope=event.body.scope, event=commitment(event), epoch=100, trust=lab.trust.head)
    ghost = Leaf(body=body, event=event, signatures=(lab.sign("w0", "admission", body),))
    head = lab.cut(lab.begin(), leaves=(*lab.leaves, ghost))
    assert lab.clock.wall() == cut_start
    assert not head.signatures


@pytest.mark.parametrize("loss", ["prior-backup", "removed-journal", "old-generation", "missing-anchor"])
def test_failed_or_incomplete_restoration_fails_closed(lab, loss):
    backup = lab.path / "prior.sqlite"
    if loss == "old-generation":
        lab.seed()
        lab.prepare()
    shutil.copyfile(lab.target.path, backup)
    if loss == "old-generation":
        lab.target.transfer(expected=1, holder="agent-b", broker="west", chain=lab.chain)
    else:
        lab.seed()
        lab.apply(lab.prepare())
    if loss in {"prior-backup", "old-generation"}:
        shutil.copyfile(backup, lab.target.path)
    elif loss == "missing-anchor":
        lab.target.anchor.unlink()
    else:
        with sqlite3.connect(lab.target.path) as db:
            db.execute("UPDATE target SET journal = NULL")
    with pytest.raises(Hold, match="restore mismatch|storage or record unavailable"):
        lab.begin(Evaluator(lab.target, "operator"))


def test_anchor_ahead_of_interrupted_restore_holds_after_restart(lab, monkeypatch):
    lab.seed()
    original = lab.target._pin

    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        raise sqlite3.OperationalError("synthetic crash between durable stores")

    monkeypatch.setattr(lab.target, "_pin", interrupted)
    with pytest.raises(Hold, match="storage or record unavailable"):
        lab.prepare()
    monkeypatch.setattr(lab.target, "_pin", original)
    with pytest.raises(Hold, match="restore mismatch"):
        lab.begin(Evaluator(lab.target, "operator"))
    assert lab.target.snapshot()["fence"] == 0


def test_independent_cut_progresses_without_coordinator_or_fourth_witness(lab):
    lab.seed()
    challenge = lab.begin()
    cut = lab.cut(challenge, signers=("w0", "w1", "w2"))
    plan = lab.reconcile(challenge, cut, status=lab.status(cut))
    assert lab.apply(plan)["restricted"] == 1


@pytest.mark.parametrize("organization", ["publisher", "verifier1"])
def test_evidence_quorum_counts_distinct_non_submitter_organizations(lab, organization):
    lab.add_key("extra-verifier", "verifier", organization=organization)
    lab.rotate()
    lab.admit(lab.event("finding", "finding", "publisher"))
    lab.admit(lab.event("vote", "corroboration", "verifier1"))
    lab.admit(lab.event("extra-vote", "corroboration", "extra-verifier"))
    lab.clock.advance()
    with pytest.raises(Hold, match="unknown"):
        lab.prepare()
    assert lab.target.snapshot()["fence"] == 0


def test_old_seal_cannot_authorize_even_with_current_request_nonce(lab):
    lab.seed()
    old = lab.cut(lab.begin())
    lab.clock.advance()
    challenge = lab.begin()
    rebound = old.body.model_copy(update={"nonce": challenge.nonce})
    stale = old.model_copy(update={"body": rebound})
    with pytest.raises(Hold, match="coverage is stale"):
        lab.reconcile(challenge, stale)
    assert lab.target.snapshot()["fence"] == 0


def test_matching_restore_still_reconciles_and_reapproves(lab):
    lab.seed()
    old = lab.prepare()
    lab.apply(old)
    backup = lab.path / "exact.sqlite"
    shutil.copyfile(lab.target.path, backup)
    shutil.copyfile(backup, lab.target.path)
    restarted = Evaluator(lab.target, "operator")
    with pytest.raises(Hold, match="fresh authenticated"):
        lab.apply(old, restarted)
    assert lab.apply(lab.prepare(restarted), restarted)["fence"] == 2
