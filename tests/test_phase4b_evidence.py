"""Regression tests for bounded portability and cache invalidation of synthetic evidence."""

import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Event, Lock
from uuid import uuid4

import pytest

from aegis.evidence import Evidence, Trust, runner
from aegis.evidence.records import (
    Observation, SignedAttestation, SignedManifest, Withdrawal, decode, digest, sign_record,
)
from aegis.evidence.synthetic import create_lab, portability_bundle

NOW = 1_800_000_000
COHORT = "lab-blue"
PROFILES = frozenset(runner.PORTABILITY_PROFILES.values())
MATRIX = json.loads(Path(__file__).with_name("fixtures").joinpath("phase4b_portability.json").read_bytes())


@pytest.fixture
def lab():
    return create_lab(NOW)


@pytest.fixture
def pair(lab):
    source = portability_bundle(lab, "marker")
    return source, portability_bundle(lab, "marker", source_sha256=source.sha256)


@pytest.fixture
def attempts(monkeypatch):
    counts = Counter()
    lock = Lock()
    actual_run = runner.run

    def counted(manifest, objects, timeout):
        with lock:
            counts[manifest.cohort, manifest.record_id] += 1
        return actual_run(manifest, objects, timeout)

    monkeypatch.setattr(runner, "run", counted)
    return counts


def open_evidence(lab, database=":memory:", **options):
    defaults = {"clock": lambda: NOW, "profiles": PROFILES}
    return Evidence(database, lab.trust, lab.verifiers, **(defaults | options))


def resign(lab, bundle, **changes):
    body = decode(SignedManifest, bundle.manifest).body
    wire = sign_record(body.model_copy(update={"record_id": uuid4().hex} | changes), lab.submitter)
    return replace(bundle, sha256=digest(wire), manifest=wire)


def contradict(lab, original_wire):
    body = decode(SignedAttestation, original_wire).body
    verifier = next(verifier for verifier in lab.verifiers if verifier.issuer == body.issuer)
    opposite = Observation(outcome="not-reproduced", reason="marker-absent",
                           positive_control=True, negative_control=True)
    return sign_record(body.model_copy(update={
        "record_id": uuid4().hex, "observation": opposite,
    }), verifier.private_key)


def withdrawal(lab, kind, issuer, target):
    return sign_record(Withdrawal(
        kind="aegis.evidence.withdrawal.v1", target_kind=kind, target_issuer=issuer,
        target_sha256=target, issuer="review", key_id="lab-v1", cohort=COHORT,
        record_id=uuid4().hex, issued_at=NOW, expires_at=NOW + 5, reason="invalid-evidence",
    ), lab.revoker)


@pytest.mark.parametrize("case", MATRIX, ids=[case["id"] for case in MATRIX])
def test_scope_matrix(lab, pair, attempts, case):
    source, _ = pair
    target = source if case["id"] == "original" else portability_bundle(
        lab, "marker", source_sha256=source.sha256, **case["changes"],
    )
    with open_evidence(lab) as service:
        first = service.verify(source, cohort=COHORT)
        match = service.assess_compatible(source, target, cohort=COHORT)
        assert (match is not None) == case["compatible"]
        assert sum(attempts.values()) == 2
        if target != source:
            with pytest.raises(ValueError, match="exact bundle scope"):
                service.accept_attestation(target, first.attestations[0], cohort=COHORT)
            assert service.assess(target, cohort=COHORT).outcome == "inconclusive"
        if match:
            assert match.source == first and match.target_sha256 == target.sha256
        exact = service.verify(target, cohort=COHORT)
        assert exact.outcome == case["outcome"]
        assert len(exact.attestations) == 2
        assert {decode(SignedAttestation, wire).body.bundle_sha256 for wire in exact.attestations} == {target.sha256}
        assert service.verify(target, cohort=COHORT) == exact
        assert sum(attempts.values()) == (2 if target == source else 4)
        assert service.assess_compatible(source, target, cohort=COHORT) is None


def test_source_provenance_from_separate_collectors(lab, pair):
    source, target = pair
    wires = []
    for verifier in lab.verifiers:
        with Evidence(":memory:", lab.trust, (verifier,), clock=lambda: NOW, profiles=PROFILES) as collector:
            result = collector.verify(source, cohort=COHORT)
            assert result.outcome == "inconclusive"
            wires.extend(result.attestations)
    with Evidence(":memory:", lab.trust, clock=lambda: NOW, profiles=PROFILES) as relying:
        relying.accept_attestation(source, wires[0], cohort=COHORT)
        assert relying.assess_compatible(source, target, cohort=COHORT) is None
        relying.accept_attestation(source, wires[1], cohort=COHORT)
        match = relying.assess_compatible(source, target, cohort=COHORT)
        assert match.rule == "synthetic-package-label-v1"
        assert set(match.source.attestations) == set(wires)
        assert match.target_sha256 == target.sha256
        assert relying.assess(target, cohort=COHORT).attestations == ()
        reissued = resign(lab, source)
        assert relying.assess_compatible(reissued, target, cohort=COHORT) is None
        assert relying.assess_compatible(target, source, cohort=COHORT) is None


@pytest.mark.parametrize("source_changes", [{"version": "v2"}, {"runtime": "runtime-offline"}])
def test_negative_and_inconclusive_sources_do_not_transfer(lab, source_changes):
    source = portability_bundle(lab, "negative or unresolved", **source_changes)
    target = portability_bundle(lab, "negative or unresolved", source_sha256=source.sha256, **source_changes)
    with open_evidence(lab) as service:
        assert service.verify(source, cohort=COHORT).outcome != "reproduced"
        assert service.assess_compatible(source, target, cohort=COHORT) is None
        assert service.assess(target, cohort=COHORT).attestations == ()


def test_unsupported_and_tampered_targets_remain_unknown(lab, pair):
    source, target = pair
    bad_targets = [
        portability_bundle(lab, "different claim", source_sha256=source.sha256),
        portability_bundle(lab, "marker", source_sha256="1" * 64),
        portability_bundle(lab, "marker", source_sha256=source.sha256, dependency="lock-unknown"),
        portability_bundle(lab, "marker", source_sha256=source.sha256, cohort="lab-green"),
        replace(target, objects={**target.objects, "dependencies": b"lock-v2"}),
        replace(target, manifest=target.manifest[:-1] + b" "),
        *(resign(lab, target, **{pin: "a" * 64})
          for pin in ("environment_sha256", "check_sha256", "oracle_sha256")),
    ]
    with open_evidence(lab) as service:
        assert service.verify(source, cohort=COHORT).outcome == "reproduced"
        for invalid in bad_targets:
            assert service.assess_compatible(source, invalid, cohort=COHORT) is None
    with Evidence(":memory:", lab.trust, lab.verifiers, clock=lambda: NOW) as baseline:
        with pytest.raises(ValueError, match="unsupported"):
            baseline.verify(source, cohort=COHORT)


@pytest.mark.parametrize("separation", ["same-organization", "submitter", "other-cohort", "unknown-key"])
def test_relying_policy_must_trust_two_independent_domains(lab, pair, separation):
    source, target = pair
    with open_evidence(lab) as depot:
        wires = depot.verify(source, cohort=COHORT).attestations
    grants = list(lab.trust.grants.values())
    verifier_idx = next(index for index, grant in enumerate(grants) if grant.issuer == "verifier-b")
    changed = grants[verifier_idx]
    if separation == "unknown-key":
        del grants[verifier_idx]
    else:
        updates = {
            "same-organization": {"organization": "verifier-a"},
            "submitter": {"organization": "research-org"},
            "other-cohort": {"cohorts": frozenset({"lab-green"})},
        }
        grants[verifier_idx] = replace(changed, **updates[separation])
    with Evidence(":memory:", Trust(grants), clock=lambda: NOW, profiles=PROFILES) as local:
        for wire in wires:
            signer = decode(SignedAttestation, wire).body.issuer
            if signer == "verifier-a" or separation == "same-organization":
                local.accept_attestation(source, wire, cohort=COHORT)
            else:
                with pytest.raises(ValueError):
                    local.accept_attestation(source, wire, cohort=COHORT)
        assert local.assess(source, cohort=COHORT).outcome == "inconclusive"
        assert local.assess_compatible(source, target, cohort=COHORT) is None


def test_freshness_is_rechecked_for_source_and_target(lab, pair):
    now = NOW
    source, target = pair
    target = resign(lab, target, expires_at=NOW + 8)
    with open_evidence(lab, clock=lambda: now, attestation_ttl=5) as service:
        initial = service.verify(source, cohort=COHORT)
        assert service.assess_compatible(source, target, cohort=COHORT).source == initial
        now += 5
        assert service.assess_compatible(source, target, cohort=COHORT) is None
        refreshed = service.verify(source, cohort=COHORT)
        assert refreshed.attestations != initial.attestations
        assert service.assess_compatible(source, target, cohort=COHORT).source == refreshed
        now += 3
        assert service.assess_compatible(source, target, cohort=COHORT) is None
        assert service.verify(target, cohort=COHORT).reason == "bundle-not-current"


@pytest.mark.parametrize("target_kind", ["source", "target", "attestation", "verifier-key"])
def test_withdrawals_invalidate_reuse_after_restart(lab, pair, tmp_path, target_kind):
    source, target = pair
    now = NOW
    path = tmp_path / "evidence.sqlite"
    with open_evidence(lab, path, clock=lambda: now) as service:
        first = service.verify(source, cohort=COHORT)
        wire = first.attestations[0]
        issuer = decode(SignedAttestation, wire).body.issuer
        grant = lab.trust.grants[(issuer, "lab-v1")]
        withdrawal_scope = {
            "source": ("bundle", "research", source.sha256),
            "target": ("bundle", "research", target.sha256),
            "attestation": ("attestation", issuer, digest(wire)),
            "verifier-key": ("verifier-key", issuer, digest(grant.public_key.public_bytes_raw())),
        }
        assert service.assess_compatible(source, target, cohort=COHORT) is not None
        service.accept_withdrawal(withdrawal(lab, *withdrawal_scope[target_kind]), cohort=COHORT)
        assert service.assess_compatible(source, target, cohort=COHORT) is None
    now += 5
    with open_evidence(lab, path, clock=lambda: now) as reopened:
        assert reopened.assess_compatible(source, target, cohort=COHORT) is None
        if target_kind in {"attestation", "verifier-key"}:
            assert reopened.assess(source, cohort=COHORT).outcome == "inconclusive"


@pytest.mark.parametrize("side", ["source", "target"])
def test_contradiction_and_direct_history_precede_compatibility(lab, pair, tmp_path, side):
    now = NOW
    source, target = pair
    database = tmp_path / "evidence.sqlite"
    disputed = source if side == "source" else target
    with open_evidence(lab, database, clock=lambda: now, attestation_ttl=5) as service:
        service.verify(source, cohort=COHORT)
        assert service.assess_compatible(source, target, cohort=COHORT) is not None
        initial = service.verify(disputed, cohort=COHORT)
        opposite = contradict(lab, initial.attestations[0])
        conflict = service.accept_attestation(disputed, opposite, cohort=COHORT)
        assert conflict.reason == "contested" and conflict.contradiction[1] == digest(opposite)
        assert service.assess_compatible(source, target, cohort=COHORT) is None
    now += 5
    with open_evidence(lab, database, clock=lambda: now, attestation_ttl=5) as service:
        refreshed = resign(lab, disputed)
        assert service.verify(refreshed, cohort=COHORT).reason == "contested"
        assert service.verify(source, cohort=COHORT).outcome == (
            "inconclusive" if side == "source" else "reproduced"
        )
        assert service.assess_compatible(source, resign(lab, target), cohort=COHORT) is None


def test_simultaneous_jobs_share_only_the_same_cohort_and_bundle(lab, pair, attempts):
    source, target = pair
    different = portability_bundle(lab, "marker", harness="harness-v2")
    private = portability_bundle(lab, "marker", cohort="lab-green")
    scopes = [(source, COHORT), (target, COHORT), (different, COHORT), (private, "lab-green")]
    barrier = Barrier(12)

    def verify(scope):
        barrier.wait(timeout=10)
        bundle, cohort = scope
        return service.verify(bundle, cohort=cohort)

    with open_evidence(lab, max_workers=2) as service, ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(verify, scopes * 3, timeout=15))
        assert all(result.outcome == "reproduced" for result in results)
        assert results[:4] == results[4:8] == results[8:]
        with pytest.raises(ValueError, match="exact bundle scope"):
            service.accept_attestation(private, results[0].attestations[0], cohort="lab-green")
    assert len(attempts) == 4
    assert set(attempts.values()) == {2}


def test_withdrawal_during_collection_cannot_seed_compatibility(lab, pair, monkeypatch):
    source, target = pair
    started, release = Event(), Event()
    original_run = runner.run

    def paused(*args):
        started.set()
        assert release.wait(5)
        return original_run(*args)

    monkeypatch.setattr(runner, "run", paused)
    with open_evidence(lab) as service, ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(service.verify, source, cohort=COHORT)
        duplicate = pool.submit(service.verify, source, cohort=COHORT)
        try:
            assert started.wait(5)
            assert service.assess_compatible(source, target, cohort=COHORT) is None
            service.accept_withdrawal(withdrawal(lab, "bundle", "research", source.sha256), cohort=COHORT)
        finally:
            release.set()
        for future in (first, duplicate):
            result = future.result(5)
            assert result.reason == "bundle-withdrawn" and result.attestations == ()
        assert service.assess_compatible(source, target, cohort=COHORT) is None


def test_portability_worker_source_drift_fails_closed(lab, pair, tmp_path, monkeypatch):
    source, target = pair
    staging = tmp_path / "portability_worker.py"
    staging.write_bytes(b"# incomplete synthetic worker")
    monkeypatch.setattr(runner, "PORTABILITY_WORKER", staging)
    with open_evidence(lab) as service:
        assert service.verify(source, cohort=COHORT).reason == "worker-unavailable"
        assert service.assess_compatible(source, target, cohort=COHORT) is None


def test_direct_history_blocks_even_after_one_observation_expires(lab, pair):
    now = NOW
    source, target = pair
    with open_evidence(lab, clock=lambda: now) as service:
        service.verify(source, cohort=COHORT)
        assert service.assess_compatible(source, target, cohort=COHORT)
        with Evidence(":memory:", lab.trust, lab.verifiers[:1], clock=lambda: NOW,
                      profiles=PROFILES, attestation_ttl=1) as direct:
            single_observation = direct.verify(target, cohort=COHORT).attestations[0]
        service.accept_attestation(target, single_observation, cohort=COHORT)
        now += 1
        assert service.assess(target, cohort=COHORT).attestations == ()
        assert service.assess_compatible(source, resign(lab, target), cohort=COHORT) is None


def test_private_ledgers_and_signers_are_separate():
    blue, green = "lab-blue", "lab-green"
    blue_lab, green_lab = (create_lab(NOW, cohorts=frozenset({cohort})) for cohort in (blue, green))
    blue_bundle = portability_bundle(blue_lab, "confidential-marker", cohort=blue)
    green_bundle = portability_bundle(green_lab, "confidential-marker", cohort=green)
    with open_evidence(blue_lab) as blue_service, open_evidence(green_lab) as green_service:
        blue_result = blue_service.verify(blue_bundle, cohort=blue)
        assert green_service.assess(green_bundle, cohort=green).attestations == ()
        with pytest.raises(ValueError, match="issuer, role or cohort"):
            green_service.verify(blue_bundle, cohort=blue)
        with pytest.raises(ValueError, match="exact bundle scope"):
            green_service.accept_attestation(green_bundle, blue_result.attestations[0], cohort=green)
        assert green_service.assess_compatible(blue_bundle, green_bundle, cohort=green) is None
        assert green_service.verify(green_bundle, cohort=green).outcome == "reproduced"
