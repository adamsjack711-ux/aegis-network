from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.evidence import Bundle, Evidence, Grant, Trust, Verifier
from aegis.evidence import runner
from aegis.evidence.records import (
    Attestation, Observation, SignedAttestation, SignedManifest, Withdrawal, decode, digest, sign_record,
)
from aegis.evidence.synthetic import create_lab

COHORT = "lab-blue"
NOW = 1_800_000_000


@pytest.fixture
def lab():
    return create_lab(NOW)


def resign(lab, bundle, **changes):
    body = decode(SignedManifest, bundle.manifest).body.model_copy(update=changes)
    wire = sign_record(body, lab.submitter)
    return replace(bundle, sha256=digest(wire), manifest=wire)


def attestation(bundle, verifier, *, reproduced=True, now=NOW, ttl=20, record_id=None):
    body = Attestation(
        kind="aegis.evidence.attestation.v1", bundle_sha256=bundle.sha256, cohort=COHORT,
        record_id=record_id or uuid4().hex, issuer=verifier.issuer, key_id=verifier.key_id,
        started_at=now, issued_at=now, expires_at=now + ttl,
        observation=Observation(
            outcome="reproduced" if reproduced else "not-reproduced",
            reason="marker-observed" if reproduced else "marker-absent", positive_control=True, negative_control=True,
        ),
    )
    return sign_record(body, verifier.private_key)


def withdraw(lab, kind, issuer, target, *, now=NOW, cohort=COHORT, record_id=None):
    return sign_record(Withdrawal(
        kind="aegis.evidence.withdrawal.v1", target_kind=kind, target_issuer=issuer, target_sha256=target,
        issuer="review", key_id="lab-v1", cohort=cohort, record_id=record_id or uuid4().hex,
        issued_at=now, expires_at=now + 5, reason="invalid-evidence",
    ), lab.revoker)


@pytest.mark.parametrize(("family", "marker", "observer", "outcome"), [
    ("feature-gate", True, True, "reproduced"),
    ("route-toggle", False, True, "not-reproduced"),
    ("service-access", True, False, "inconclusive"),
])
def test_real_workers_and_portable_independent_signatures(lab, family, marker, observer, outcome):
    bundle = lab.bundle("marker case", family=family, marker=marker, observer=observer)
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as origin:
        result = origin.verify(bundle, cohort=COHORT)
    assert result.outcome == outcome
    assert len(result.attestations) == 2
    with Evidence(":memory:", lab.trust, clock=lambda: NOW) as local:
        for wire in result.attestations:
            body = decode(SignedAttestation, wire).body
            assert body.observation.positive_control is observer
            assert body.observation.negative_control is observer
            assert body.bundle_sha256 == bundle.sha256
            accepted = local.accept_attestation(bundle, wire, cohort=COHORT)
        assert accepted.outcome == outcome


def test_exact_scope_cache_and_concurrent_single_flight(lab, monkeypatch):
    bundle = lab.bundle("repeat")
    real_run = runner.run
    calls = []
    gate = Barrier(8)

    def counted(*args):
        calls.append(args[0].cohort)
        return real_run(*args)

    def verify():
        gate.wait(5)
        return service.verify(bundle, cohort=COHORT)

    monkeypatch.setattr(runner, "run", counted)
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as service:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = [pool.submit(verify) for _ in range(8)]
            results = [result.result(timeout=5) for result in results]
        assert all(result == results[0] for result in results)
        assert len(calls) == 2
        assert service.verify(bundle, cohort=COHORT) == results[0]
        cases = [
            lab.bundle("different claim"),
            lab.bundle("repeat", marker=False),
            lab.bundle("repeat", observer=False),
            lab.bundle("repeat", family="route-toggle"),
        ]
        for changed in cases:
            service.verify(changed, cohort=COHORT)
        green = lab.bundle("repeat", cohort="lab-green")
        assert service.verify(green, cohort="lab-green").outcome == "reproduced"
        with pytest.raises(ValueError, match="cohort"):
            service.verify(green, cohort=COHORT)
        with pytest.raises(ValueError, match="exact bundle scope"):
            service.accept_attestation(green, results[0].attestations[0], cohort="lab-green")
        assert len(calls) == 12


@pytest.mark.parametrize("field", ("environment_sha256", "check_sha256", "oracle_sha256"))
def test_unknown_implementation_pins_are_rejected(lab, field):
    bundle = lab.bundle("different implementation")
    modified = resign(lab, bundle, **{field: "0" * 64})
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as service:
        service.verify(bundle, cohort=COHORT)
        with pytest.raises(ValueError, match="unsupported"):
            service.verify(modified, cohort=COHORT)


def test_corrupt_and_unregistered_bundle_materials_rejected_even_if_signed(lab):
    bundle = lab.bundle("material pin")
    body = decode(SignedManifest, bundle.manifest).body
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as service:
        assert service.verify(bundle, cohort=COHORT).outcome == "reproduced"
        with pytest.raises(ValueError, match="manifest digest"):
            service.verify(replace(bundle, sha256="0" * 64), cohort=COHORT)
        for role in bundle.objects:
            objects = dict(bundle.objects)
            objects[role] = b"x" * len(objects[role])
            with pytest.raises(ValueError, match="material pin"):
                service.verify(replace(bundle, objects=objects), cohort=COHORT)
        # An enrolled submitter cannot opt a new opaque material into the fixture registry.
        objects = {**bundle.objects, "recipe": b"inert-unregistered-recipe"}
        recipe = body.materials.recipe.model_copy(update={"sha256": digest(objects["recipe"]), "size": len(objects["recipe"])})
        changed = resign(lab, bundle, materials=body.materials.model_copy(update={"recipe": recipe}))
        with pytest.raises(ValueError, match="not registered"):
            service.verify(replace(changed, objects=objects), cohort=COHORT)
        with pytest.raises(ValueError, match="incomplete"):
            service.verify(replace(bundle, objects={}), cohort=COHORT)
        with pytest.raises(ValueError, match="noncanonical|not canonical"):
            duplicate = bundle.manifest.replace(b'{"body":{', b'{"body":{"cohort":"lab-blue",', 1)
            service.verify(Bundle(digest(duplicate), duplicate, bundle.objects), cohort=COHORT)
        altered = resign(lab, bundle, expires_at=NOW + 300)
        with pytest.raises(ValueError, match="conflicting evidence record ID"):
            service.verify(altered, cohort=COHORT)


def test_forgery_and_conflicting_replay_are_rejected(lab):
    bundle = lab.bundle("signature")
    verifier = lab.verifiers[0]
    impostor = replace(verifier, private_key=Ed25519PrivateKey.generate())
    wire = attestation(bundle, verifier)
    tampered = wire.replace(b'"marker-observed"', b'"marker-absent"').replace(b'"reproduced"', b'"not-reproduced"')
    changed_manifest = bundle.manifest.replace(b'"feature-gate"', b'"route-toggle"')
    with Evidence(":memory:", lab.trust, clock=lambda: NOW) as service:
        with pytest.raises(ValueError, match="invalid evidence signature"):
            service.verify(Bundle(digest(changed_manifest), changed_manifest, bundle.objects), cohort=COHORT)
        for forged in (tampered, attestation(bundle, impostor)):
            with pytest.raises(ValueError, match="invalid evidence signature"):
                service.accept_attestation(bundle, forged, cohort=COHORT)
        wrong_role = Verifier("research", "lab-v1", lab.submitter)
        with pytest.raises(ValueError, match="untrusted issuer, role or cohort"):
            service.accept_attestation(bundle, attestation(bundle, wrong_role), cohort=COHORT)
        first = service.accept_attestation(bundle, wire, cohort=COHORT)
        assert first.outcome == "inconclusive"
        assert service.accept_attestation(bundle, wire, cohort=COHORT) == first
        record_id = decode(SignedAttestation, wire).body.record_id
        with pytest.raises(ValueError, match="conflicting evidence record ID"):
            service.accept_attestation(
                bundle, attestation(bundle, verifier, reproduced=False, record_id=record_id), cohort=COHORT,
            )
        assert service.assess(bundle, cohort=COHORT) == first


def test_independence_uses_pinned_organizations_and_excludes_submitter(lab):
    bundle = lab.bundle("organizations")
    a, b = lab.verifiers
    extra_key = Ed25519PrivateKey.generate()
    extra = Verifier("research-peer", "lab-v1", extra_key)
    existing = lab.trust.grants
    grants = [
        replace(g, organization="shared-verifier") if g.issuer in {a.issuer, b.issuer} else g
        for g in existing.values()
    ]
    grants.append(Grant(extra.issuer, extra.key_id, "research-org", "verifier", extra_key.public_key(),
                        frozenset({COHORT}), NOW, NOW + 100))
    with Evidence(":memory:", Trust(grants), (a, b, extra), clock=lambda: NOW) as service:
        result = service.verify(bundle, cohort=COHORT)
        assert result.outcome == "inconclusive"
        assert len(result.attestations) == 1
        with pytest.raises(ValueError, match="ineligible"):
            service.accept_attestation(bundle, attestation(bundle, extra), cohort=COHORT)
    with pytest.raises(ValueError, match="exactly one"):
        Trust([*grants, replace(grants[-1], issuer="duplicate-public-key")])


def test_expiry_refresh_and_clock_rollback(lab, tmp_path):
    database = tmp_path / "evidence.sqlite"
    now = NOW
    bundle = lab.bundle("expires")
    with Evidence(database, lab.trust, lab.verifiers, clock=lambda: now, attestation_ttl=5) as service:
        first = service.verify(bundle, cohort=COHORT)
        now += 5
        assert service.assess(bundle, cohort=COHORT).outcome == "inconclusive"
        refreshed = service.verify(bundle, cohort=COHORT)
        assert refreshed.outcome == first.outcome == "reproduced"
        assert refreshed.attestations != first.attestations
        now = NOW + 3600
        assert service.verify(bundle, cohort=COHORT).reason == "bundle-not-current"
    now -= 1
    with Evidence(database, lab.trust, lab.verifiers, clock=lambda: now) as reopened:
        with pytest.raises(ValueError, match="clock regressed"):
            reopened.verify(bundle, cohort=COHORT)


def test_scope_contradiction_survives_expiry_restart_and_reissue(lab, tmp_path):
    database = tmp_path / "evidence.sqlite"
    now = NOW
    bundle = lab.bundle("contested")
    reissued = resign(lab, bundle, record_id=uuid4().hex, expires_at=NOW + 100)
    different_scope = lab.bundle("contested", marker=False)
    with Evidence(database, lab.trust, lab.verifiers, clock=lambda: now) as service:
        initial = service.verify(bundle, cohort=COHORT)
        assert initial.outcome == "reproduced"
        assert service.assess(reissued, cohort=COHORT).attestations == ()
        opposite = attestation(reissued, lab.verifiers[0], reproduced=False, ttl=5)
        disputed = service.accept_attestation(reissued, opposite, cohort=COHORT)
        assert disputed.outcome == "inconclusive"
        assert disputed.reason == "contested"
        assert disputed.contradiction[1] == digest(opposite)
        assert disputed.contradiction[0] in {digest(wire) for wire in initial.attestations}
        assert service.verify(bundle, cohort=COHORT).reason == "contested"
        assert service.verify(different_scope, cohort=COHORT).outcome == "not-reproduced"
    now += 10
    with Evidence(database, lab.trust, lab.verifiers, clock=lambda: now) as reopened:
        assert reopened.verify(bundle, cohort=COHORT).contradiction == disputed.contradiction
        further_reissue = resign(lab, bundle, record_id=uuid4().hex)
        assert reopened.verify(further_reissue, cohort=COHORT).reason == "contested"


def test_scoped_withdrawal_before_bundle_and_persistent_tombstones(lab, tmp_path):
    now = NOW
    database = tmp_path / "evidence.sqlite"
    bundle = lab.bundle("withdrawn before delivery")
    wire = withdraw(lab, "bundle", "research", bundle.sha256)
    with Evidence(database, lab.trust, lab.verifiers, clock=lambda: now) as service:
        with pytest.raises(ValueError, match="revoker's scope"):
            service.accept_withdrawal(wire, cohort="lab-green")
        for foreign in (
            withdraw(lab, "bundle", "unknown-publisher", bundle.sha256),
            wire.replace(b'"invalid-evidence"', b'"superseded"'),
        ):
            with pytest.raises(ValueError, match="scope|signature"):
                service.accept_withdrawal(foreign, cohort=COHORT)
        service.accept_withdrawal(wire, cohort=COHORT)
        service.accept_withdrawal(wire, cohort=COHORT)
        body = decode(SignedManifest, bundle.manifest).body
        assert service.assess(bundle, cohort=COHORT).reason == "bundle-withdrawn"
        assert body.cohort == COHORT
    now += 10
    with Evidence(database, lab.trust, lab.verifiers, clock=lambda: now) as reopened:
        assert reopened.verify(bundle, cohort=COHORT).reason == "bundle-withdrawn"
        assert reopened.verify(lab.bundle("different bundle"), cohort=COHORT).outcome == "reproduced"
        with pytest.raises(ValueError, match="validity"):
            reopened.accept_withdrawal(wire, cohort=COHORT)


def test_attestation_and_verifier_key_withdrawal_reappraise(lab):
    bundle = lab.bundle("cached then revoked")
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as service:
        first = service.verify(bundle, cohort=COHORT)
        wire = first.attestations[0]
        issuer = decode(SignedAttestation, wire).body.issuer
        service.accept_withdrawal(withdraw(lab, "attestation", issuer, digest(wire)), cohort=COHORT)
        assert service.assess(bundle, cohort=COHORT).outcome == "inconclusive"
        with pytest.raises(ValueError, match="withdrawn"):
            service.accept_attestation(bundle, wire, cohort=COHORT)
        # The isolated verifier may provide a fresh observation after a specific run is withdrawn.
        new = service.verify(bundle, cohort=COHORT)
        assert new.outcome == "reproduced" and wire not in new.attestations
        grant = lab.trust.grants[(issuer, "lab-v1")]
        key_digest = digest(grant.public_key.public_bytes_raw())
        service.accept_withdrawal(withdraw(lab, "verifier-key", issuer, key_digest), cohort=COHORT)
        assert service.verify(bundle, cohort=COHORT).outcome == "inconclusive"
        green = lab.bundle("cached then revoked", cohort="lab-green")
        assert service.verify(green, cohort="lab-green").outcome == "reproduced"


def test_corrupted_cached_bytes_cannot_vote(lab, tmp_path):
    import sqlite3

    database = tmp_path / "evidence.sqlite"
    bundle = lab.bundle("cache corruption")
    with Evidence(database, lab.trust, lab.verifiers, clock=lambda: NOW) as service:
        original = service.verify(bundle, cohort=COHORT)
    with sqlite3.connect(database) as db:
        db.execute("UPDATE evidence_attestations SET wire=? WHERE issuer='verifier-a'", (b"altered",))
    with Evidence(database, lab.trust, lab.verifiers, clock=lambda: NOW) as reopened:
        assert reopened.assess(bundle, cohort=COHORT).outcome == "inconclusive"
        repaired = reopened.verify(bundle, cohort=COHORT)
        assert repaired.outcome == "reproduced"
        assert repaired.attestations != original.attestations


def test_worker_timeout_and_retry_leave_no_false_negative(lab):
    bundle = lab.bundle("worker timeout")
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW, worker_timeout=0.0001) as service:
        failed = service.verify(bundle, cohort=COHORT)
        assert (failed.outcome, failed.reason, failed.attestations) == ("inconclusive", "worker-unavailable", ())
        service._timeout = 2
        assert service.verify(bundle, cohort=COHORT).outcome == "reproduced"


@pytest.mark.parametrize("failure", ["crash", "invalid-output"])
def test_worker_crash_or_malformed_stdout_never_signed(lab, monkeypatch, failure):
    def broken(command, **kwargs):
        assert kwargs["env"] == {} and kwargs["close_fds"]
        assert command[1:3] == ["-I", "-S"]
        if failure == "crash":
            raise runner.subprocess.CalledProcessError(2, command)
        return runner.subprocess.CompletedProcess(command, 0, stdout=b'{"outcome":"reproduced"}')

    monkeypatch.setattr(runner.subprocess, "run", broken)
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as service:
        result = service.verify(lab.bundle("broken worker"), cohort=COHORT)
        assert (result.outcome, result.reason, result.attestations) == ("inconclusive", "worker-unavailable", ())


def test_withdrawal_during_worker_run_prevents_publication(lab, monkeypatch):
    real_run = runner.run
    started, resume = Event(), Event()

    def paused(*args):
        started.set()
        assert resume.wait(5)
        return real_run(*args)

    monkeypatch.setattr(runner, "run", paused)
    bundle = lab.bundle("withdrawal race")
    wire = withdraw(lab, "bundle", "research", bundle.sha256)
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as service:
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(service.verify, bundle, cohort=COHORT)
            try:
                assert started.wait(5)
                service.accept_withdrawal(wire, cohort=COHORT)
            finally:
                resume.set()
            assert result.result(5).reason == "bundle-withdrawn"


def test_two_separately_operated_verifiers_and_a_read_only_relying_party(lab, monkeypatch):
    bundle = lab.bundle("portable observation")
    copies = []
    for verifier in lab.verifiers:
        with Evidence(":memory:", lab.trust, (verifier,), clock=lambda: NOW) as service:
            result = service.verify(bundle, cohort=COHORT)
            assert result.outcome == "inconclusive"
            copies.extend(result.attestations)

    profile = runner.LOCAL_PROFILE
    monkeypatch.setattr(runner, "LOCAL_PROFILE", replace(profile, environment_sha256="a" * 64))
    with Evidence(":memory:", lab.trust, clock=lambda: NOW, profiles=frozenset({profile})) as relying_party:
        for wire in copies:
            result = relying_party.accept_attestation(bundle, wire, cohort=COHORT)
        assert result.outcome == "reproduced"
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as different_worker:
        assert different_worker.verify(bundle, cohort=COHORT).reason == "worker-unavailable"


def test_observation_requires_controls_and_attestation_respects_local_ttl(lab):
    with pytest.raises(ValueError, match="unhealthy controls"):
        Observation(outcome="reproduced", reason="marker-observed", positive_control=True, negative_control=False)
    bundle = lab.bundle("too-long a lifetime")
    wire = attestation(bundle, lab.verifiers[0], ttl=10)
    with Evidence(":memory:", lab.trust, clock=lambda: NOW, attestation_ttl=9) as service:
        with pytest.raises(ValueError, match="exact bundle scope"):
            service.accept_attestation(bundle, wire, cohort=COHORT)


def test_worker_source_drift_is_inconclusive(lab, tmp_path, monkeypatch):
    corrupted = tmp_path / "worker.py"
    corrupted.write_bytes(b"# truncated synthetic worker source")
    monkeypatch.setattr(runner, "WORKER", corrupted)
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as service:
        result = service.verify(lab.bundle("source corruption"), cohort=COHORT)
        assert (result.outcome, result.reason, result.attestations) == ("inconclusive", "worker-unavailable", ())
