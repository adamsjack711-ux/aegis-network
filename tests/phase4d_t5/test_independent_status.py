"""Phase 4C-04 regression. All authorities and worker inputs are disposable fixtures."""

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.evidence import runner, synthetic
from aegis.evidence.records import (
    Attestation, SignedAttestation, SignedManifest, SignedWithdrawal, Trust, Withdrawal, decode, digest,
    sign_record,
)
from aegis.evidence.service import Evidence, Verifier
from aegis.evidence.status import RelyingStatus, StatusProof, StatusWitness
from aegis.evidence.status_protocol import ATTESTATION_TTL, STATUS_TTL, StatusPolicy, WitnessGrant, observe
from aegis.evidence.synthetic import create_lab

COHORT = "lab-blue"


class Fixture:
    def __init__(self, path: Path):
        self.path = path
        self.lab = create_lab(1_800_000_000)
        self.now = self.lab.now
        self.keys = tuple(Ed25519PrivateKey.generate() for _ in range(2))
        self.policy = StatusPolicy("test-stream", COHORT, "research-org", "deployment-owner", self.lab.trust, tuple(
            WitnessGrant(f"witness-{index}", f"separate-custody-{index}", key.public_key())
            for index, key in enumerate(self.keys)
        ))
        self.bundle = self.lab.bundle("synthetic-verification")
        self.witnesses = tuple(self.witness(index, provision=True) for index in range(2))
        self.reader = self.relying(provision=True)

    def clock(self):
        return self.now

    def witness(self, index, *, provision=False, suffix=""):
        return StatusWitness(self.path / f"witness-{index}{suffix}.sqlite", self.policy, f"witness-{index}",
                             self.keys[index], clock=self.clock, provision=provision)

    def relying(self, *, provision=False, audience="deployment-a"):
        return RelyingStatus(self.path / f"{audience}.sqlite", self.policy, audience, clock=self.clock,
                             provision=provision)

    def admit(self, *wires):
        for wire in wires:
            for witness in self.witnesses:
                assert witness.admit(wire) == digest(wire)

    def collect(self, bundle=None):
        bundle = self.bundle if bundle is None else bundle
        return tuple(observe(self.policy, v, bundle, clock=self.clock) for v in self.lab.verifiers)

    def publish(self, bundle=None):
        bundle = self.bundle if bundle is None else bundle
        wires = self.collect(bundle)
        self.admit(bundle.manifest, *wires)
        return wires

    def fetch(self, request: bytes):
        left, right = (witness.endorse(request) for witness in self.witnesses)
        return StatusProof(left.endorsements + right.endorsements, left.records)

    def evaluate(self, bundle=None, fetch: Callable | None = None, reader=None, **expected):
        bundle = self.bundle if bundle is None else bundle
        manifest = decode(SignedManifest, bundle.manifest).body
        pins = {
            "expected_bundle_sha256": bundle.sha256, "expected_claim_sha256": manifest.claim_sha256,
            "expected_environment_sha256": manifest.environment_sha256,
        } | expected
        reader = self.reader if reader is None else reader
        return reader.evaluate(bundle, fetch=fetch or self.fetch, **pins)

    def revoke(self, kind="bundle", issuer="research", pin=None):
        return sign_record(Withdrawal(
            kind="aegis.evidence.withdrawal.v1", issuer="review", key_id="lab-v1", cohort=COHORT,
            record_id=uuid4().hex, issued_at=self.now, expires_at=self.now + 2,
            target_kind=kind, target_issuer=issuer, target_sha256=pin or self.bundle.sha256,
            reason="invalid-evidence",
        ), self.lab.revoker)


@pytest.fixture
def fx(tmp_path):
    return Fixture(tmp_path)


@pytest.mark.parametrize(("marker", "observer", "outcome", "reason"), [
    (True, True, "reproduced", "quorum"),
    (False, True, "not-reproduced", "quorum"),
    (True, False, "inconclusive", "inconclusive-observations"),
])
def test_two_worker_processes_support_each_outcome(fx, marker, observer, outcome, reason):
    bundle = fx.lab.bundle("synthetic outcome matrix", marker=marker, observer=observer)
    votes = fx.publish(bundle)
    result = fx.evaluate(bundle)
    assert (result.outcome, result.reason) == (outcome, reason)
    assert result.head.revision == 3
    assert set(result.attestation_sha256) == {digest(wire) for wire in votes}
    assert (result.binding_sha256 is not None) == (outcome == "reproduced")
    for wire in votes:
        observation = decode(SignedAttestation, wire).body.observation
        assert observation.outcome == outcome
        assert observation.positive_control == observation.negative_control == observer


def test_exact_local_pins_and_material_bytes_are_required(fx):
    fx.publish()
    for field in ("expected_bundle_sha256", "expected_claim_sha256", "expected_environment_sha256"):
        with pytest.raises(ValueError, match="mismatches"):
            fx.evaluate(**{field: "f" * 64})
    altered = replace(fx.bundle, objects=fx.bundle.objects | {"subject": b"inert but different"})
    with pytest.raises(ValueError, match="material pin mismatch"):
        fx.evaluate(altered)
    unrelated = fx.lab.bundle("another claim")
    assert fx.evaluate(unrelated).reason == "missing-bundle"
    other_cohort = fx.lab.bundle("synthetic-verification", cohort="lab-green")
    with pytest.raises(ValueError, match="outside the requested cohort"):
        fx.evaluate(other_cohort)
    other_environment = decode(SignedManifest, fx.bundle.manifest).body.model_copy(
        update={"environment_sha256": "f" * 64},
    )
    wire = sign_record(other_environment, fx.lab.submitter)
    with pytest.raises(ValueError, match="unsupported"):
        fx.evaluate(replace(fx.bundle, sha256=digest(wire), manifest=wire))


def test_reissued_bundle_needs_direct_exact_attestations(fx):
    fx.publish()
    manifest = decode(SignedManifest, fx.bundle.manifest).body.model_copy(update={"record_id": uuid4().hex})
    wire = sign_record(manifest, fx.lab.submitter)
    reissued = replace(fx.bundle, sha256=digest(wire), manifest=wire)
    fx.admit(wire)
    assert fx.evaluate(reissued).reason == "insufficient-corroboration"
    fx.admit(*fx.collect(reissued))
    assert fx.evaluate(reissued).binding_sha256 != fx.evaluate().binding_sha256


def test_phase4b_portability_does_not_supply_direct_target_votes(fx):
    if not hasattr(synthetic, "portability_bundle"):
        pytest.skip("Phase 4B portability is available in the combined checkout")
    fx.policy = replace(fx.policy, profiles=frozenset(runner.PORTABILITY_PROFILES.values()))
    fx.witnesses = tuple(fx.witness(i, provision=True, suffix="-portability") for i in range(2))
    reader = fx.relying(provision=True, audience="deployment-portability")
    source = synthetic.portability_bundle(fx.lab, "same portable claim")
    target = synthetic.portability_bundle(fx.lab, "same portable claim", source_sha256=source.sha256)
    source_votes = fx.publish(source)
    fx.admit(target.manifest)
    assert fx.evaluate(source, reader=reader).outcome == "reproduced"
    assert fx.evaluate(target, reader=reader).reason == "insufficient-corroboration"
    target_votes = fx.collect(target)
    fx.admit(*target_votes)
    result = fx.evaluate(target, reader=reader)
    assert result.outcome == "reproduced"
    assert set(result.attestation_sha256) == {digest(wire) for wire in target_votes}
    assert set(result.attestation_sha256).isdisjoint(map(digest, source_votes))


def test_coordinator_cannot_upgrade_its_signed_claim_or_legacy_assessment(fx):
    # Reproduce the reviewed authority gap using the original co-located collector.
    with Evidence(":memory:", fx.lab.trust, fx.lab.verifiers, clock=fx.clock) as legacy:
        old = legacy.verify(fx.bundle, cohort=COHORT)
    assert old.outcome == "reproduced"
    fx.admit(fx.bundle.manifest)
    assert fx.evaluate().reason == "insufficient-corroboration"
    assert fx.evaluate(fetch=lambda _: StatusProof((), old.attestations)).reason == "withheld-status"

    legit_vote, other_vote = fx.collect()
    forged = sign_record(decode(SignedAttestation, other_vote).body, fx.lab.submitter)
    with pytest.raises(ValueError, match="invalid evidence signature"):
        fx.witnesses[0].admit(forged)
    fx.admit(legit_vote)
    result = fx.evaluate()
    assert (result.outcome, result.reason, result.binding) == ("inconclusive", "insufficient-corroboration", None)


def test_role_key_and_organization_custody_constraints(fx):
    w0, w1 = fx.policy.witnesses
    for bad in (
        replace(w1, organization=w0.organization),
        replace(w1, public_key=w0.public_key),
        replace(w1, organization=fx.policy.coordinator_org),
        replace(w1, public_key=fx.lab.revoker.public_key()),
    ):
        with pytest.raises(ValueError):
            replace(fx.policy, witnesses=(w0, bad))
    with pytest.raises(ValueError):
        replace(fx.policy, local_authority_org=fx.policy.coordinator_org)

    grants = tuple(fx.lab.trust.grants.values())
    verifier = next(grant for grant in grants if grant.role == "verifier")
    duplicate = replace(verifier, issuer="verifier-alias", public_key=Ed25519PrivateKey.generate().public_key())
    policy = replace(fx.policy, trust=Trust([*grants, duplicate]))
    assert duplicate in policy.cohort_grants
    with pytest.raises(ValueError):
        replace(policy, coordinator_org=verifier.organization)
    with pytest.raises(ValueError, match="signer"):
        StatusWitness(fx.path / "forged.sqlite", fx.policy, w0.witness_id, fx.lab.submitter, provision=True)


def test_distinct_keys_in_one_verifier_organization_are_one_vote(fx):
    verifier = fx.lab.verifiers[0]
    other = Verifier("verifier-alias", verifier.key_id, Ed25519PrivateKey.generate())
    grants = fx.lab.trust.grants
    alias = replace(grants[verifier.issuer, verifier.key_id], issuer=other.issuer,
                    public_key=other.private_key.public_key())
    fx.policy = replace(fx.policy, trust=Trust([*grants.values(), alias]))
    fx.witnesses = tuple(fx.witness(i, provision=True, suffix="-alias") for i in range(2))
    reader = fx.relying(provision=True, audience="deployment-alias")
    wires = [observe(fx.policy, signer, fx.bundle, clock=fx.clock) for signer in (verifier, other)]
    fx.admit(fx.bundle.manifest, *wires)
    assert fx.evaluate(reader=reader).reason == "insufficient-corroboration"


def test_missing_duplicate_substituted_and_replayed_status(fx):
    fx.publish()
    cached = []

    def capture(request):
        result = fx.fetch(request)
        cached.append(result)
        return result

    positive = fx.evaluate(fetch=capture)
    assert positive.outcome == "reproduced"
    assert fx.evaluate(fetch=fx.witnesses[0].endorse).reason == "withheld-status"

    def duplicate(request):
        one = fx.witnesses[0].endorse(request)
        return replace(one, endorsements=one.endorsements * 2)

    def corrupt(request):
        proof = fx.fetch(request)
        first, second = proof.endorsements
        offset = first.index(b'"signature":"') + len(b'"signature":"')
        bad = b"0" if first[offset:offset + 1] != b"0" else b"1"
        return replace(proof, endorsements=(first[:offset] + bad + first[offset + 1:], second))

    assert fx.evaluate(fetch=duplicate).reason == "invalid-status"
    assert fx.evaluate(fetch=corrupt).reason == "invalid-status"
    assert fx.evaluate(fetch=lambda _: cached[0]).reason == "invalid-status"
    other = fx.relying(provision=True, audience="deployment-b")
    assert fx.evaluate(fetch=lambda _: cached[0], reader=other).reason == "invalid-status"
    assert fx.evaluate(reader=other).binding_sha256 != positive.binding_sha256


def test_independently_received_withdrawal_cannot_be_omitted(fx):
    fx.publish()
    before = fx.evaluate()
    assert before.outcome == "reproduced"

    withdrawal = fx.revoke()
    assert fx.witnesses[1].admit(withdrawal) == digest(withdrawal)
    assert fx.evaluate(fetch=fx.witnesses[0].endorse).reason == "withheld-status"
    assert fx.evaluate().reason == "divergent-status"
    assert fx.witnesses[0].admit(withdrawal) == digest(withdrawal)

    def omit(request):
        proof = fx.fetch(request)
        return replace(proof, records=tuple(record for record in proof.records if record != withdrawal))

    def substitute(request):
        proof = fx.fetch(request)
        replacement = fx.lab.bundle("an unrelated signed manifest").manifest
        return replace(proof, records=tuple(replacement if record == withdrawal else record for record in proof.records))

    assert fx.evaluate(fetch=omit).reason == "withheld-records"
    assert fx.evaluate(fetch=substitute).reason == "withheld-records"
    after = fx.evaluate()
    assert (after.outcome, after.reason, after.binding) == ("inconclusive", "revoked", None)
    assert after.head.revision == before.head.revision + 1


@pytest.mark.parametrize("kind", ["bundle", "attestation", "verifier-key"])
def test_exact_scoped_revocation_persists_after_expiry_and_restart(fx, kind):
    first, _ = fx.publish()
    if kind == "bundle":
        withdrawal = fx.revoke()
    elif kind == "attestation":
        withdrawal = fx.revoke(kind, fx.lab.verifiers[0].issuer, digest(first))
    else:
        signer = fx.lab.verifiers[0]
        withdrawal = fx.revoke(kind, signer.issuer, digest(signer.private_key.public_key().public_bytes_raw()))
    fx.admit(withdrawal)
    assert fx.evaluate().reason == "revoked"

    fx.now += 2
    fx.witnesses = tuple(fx.witness(index) for index in range(2))
    fx.reader = fx.relying()
    assert fx.evaluate().reason == "revoked"
    late = fx.witness(0, provision=True, suffix="-never-admitted")
    with pytest.raises(ValueError, match="outside its validity"):
        late.admit(withdrawal)
    assert fx.witnesses[0].admit(withdrawal) == digest(withdrawal)


def test_out_of_scope_revoker_and_unknown_signer_do_not_change_status(fx):
    fx.publish()
    before = fx.evaluate()
    body = decode(SignedWithdrawal, fx.revoke()).body
    for wire in (
        sign_record(body, fx.lab.submitter),
        sign_record(body.model_copy(update={"target_issuer": "different-publisher"}), fx.lab.revoker),
        sign_record(body.model_copy(update={"cohort": "lab-green"}), fx.lab.revoker),
    ):
        for witness in fx.witnesses:
            with pytest.raises(ValueError):
                witness.admit(wire)
    assert fx.evaluate().binding_sha256 == before.binding_sha256


def test_status_and_attestation_expire_at_exclusive_boundaries(fx):
    fx.publish()

    def delayed(request):
        proof = fx.fetch(request)
        fx.now += STATUS_TTL
        return proof

    assert fx.evaluate(fetch=delayed).reason == "stale-status"
    fx.now = fx.lab.now + ATTESTATION_TTL - 1
    result = fx.evaluate()
    assert result.outcome == "reproduced"
    assert result.valid_until == fx.lab.now + ATTESTATION_TTL
    fx.now = result.valid_until
    assert fx.evaluate().reason == "stale-evidence"
    fx.now -= 1
    with pytest.raises(ValueError, match="clock regressed"):
        fx.evaluate(reader=fx.relying())


def test_contested_material_survives_expiry_reissue_and_withdrawal(fx):
    fx.publish()
    manifest = decode(SignedManifest, fx.bundle.manifest).body
    fx.now += ATTESTATION_TTL
    new_manifest = manifest.model_copy(update={"record_id": uuid4().hex, "issued_at": fx.now})
    wire = sign_record(new_manifest, fx.lab.submitter)
    reissued = replace(fx.bundle, sha256=digest(wire), manifest=wire)
    first, _ = fx.publish(reissued)
    body = decode(SignedAttestation, first).body
    contrary = Attestation.model_validate(body.model_dump() | {
        "record_id": uuid4().hex,
        "observation": {
            "outcome": "not-reproduced", "reason": "marker-absent", "positive_control": True, "negative_control": True,
        },
    })
    different_vote = sign_record(contrary, fx.lab.verifiers[0].private_key)
    fx.admit(different_vote)
    result = fx.evaluate(reissued)
    assert result.reason == "contested"
    assert len(result.attestation_sha256) == 2 and digest(different_vote) in result.attestation_sha256
    fx.admit(fx.revoke("attestation", body.issuer, digest(different_vote)))
    fx.now += ATTESTATION_TTL
    assert fx.evaluate(reissued, reader=fx.relying()).reason == "contested"
    assert fx.evaluate().reason == "contested"


def test_durable_floor_rejects_older_and_conflicting_certified_views(fx):
    votes = fx.publish()
    old_roster = tuple(fx.witness(i, suffix="-restored", provision=True) for i in range(2))
    for witness in old_roster:
        for wire in (fx.bundle.manifest, *votes):
            witness.admit(wire)
    fx.evaluate()
    fx.admit(fx.revoke())
    assert fx.evaluate().reason == "revoked"

    def source(request):
        a, b = (witness.endorse(request) for witness in old_roster)
        return StatusProof(a.endorsements + b.endorsements, a.records)

    reopened = fx.relying()
    assert fx.evaluate(fetch=source, reader=reopened).reason == "stale-status"
    for witness in old_roster:
        witness.admit(fx.lab.bundle("fork removes the known withdrawal").manifest)
    assert fx.evaluate(fetch=source, reader=reopened).reason == "conflicting-history"
    assert fx.evaluate(reader=fx.relying()).reason == "conflicting-history"


def test_fresh_status_binds_local_review_and_updates_invalidate_it(fx):
    fx.publish()
    original = fx.evaluate()
    assert original.outcome == "reproduced"

    def local_stage(approved_binding):
        current = fx.evaluate()
        return (current.outcome == "reproduced" and current.binding_sha256 == approved_binding
                and current.valid_until is not None and fx.now < current.valid_until)

    assert not local_stage(None)
    fx.now += 1
    assert fx.evaluate().valid_until > original.valid_until
    assert local_stage(original.binding_sha256)
    fx.admit(fx.lab.bundle("unrelated stream update").manifest)
    assert fx.evaluate().outcome == "reproduced"
    assert not local_stage(original.binding_sha256)
    renewed = fx.evaluate().binding_sha256
    assert local_stage(renewed)
    fx.admit(fx.revoke())
    assert not local_stage(renewed)


def test_duplicate_signed_record_identity_conflicts_and_withdrawal_is_retained(fx):
    fx.publish()
    denial = fx.revoke()
    body = decode(SignedWithdrawal, denial).body
    equivocation = sign_record(body.model_copy(update={"reason": "superseded"}), fx.lab.revoker)
    fx.admit(denial, equivocation)
    assert fx.evaluate().reason == "conflicting-history"
    fx.now += 5
    assert fx.evaluate(reader=fx.relying()).reason == "conflicting-history"


def test_capacity_failure_disables_status_durably(fx, monkeypatch):
    fx.publish()
    assert fx.evaluate().outcome == "reproduced"
    monkeypatch.setattr("aegis.evidence.status.MAX_HISTORY", 3)
    assert fx.witnesses[0].admit(fx.revoke()) is None
    assert fx.evaluate().reason == "withheld-status"
    assert fx.witness(0).admit(fx.bundle.manifest) == fx.bundle.sha256
    fx.witnesses = (fx.witness(0), fx.witnesses[1])
    assert fx.evaluate().reason == "withheld-status"
