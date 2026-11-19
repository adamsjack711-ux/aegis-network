"""Reproduce isolated-lab latencies for existing and independently witnessed Evidence."""

import argparse
import json
import math
import platform
import statistics
import sys
import time
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.evidence.records import SignedManifest, Withdrawal, decode, digest, sign_record
from aegis.evidence.runner import LOCAL_PROFILE
from aegis.evidence.service import Evidence
from aegis.evidence.status import RelyingStatus, StatusProof, StatusWitness
from aegis.evidence.status_protocol import ATTESTATION_TTL, MAX_HISTORY, STATUS_TTL, StatusPolicy, WitnessGrant, observe
from aegis.evidence.synthetic import create_lab


def summary(samples):
    ordered = sorted(samples)
    return {
        "p50_ms": statistics.median(ordered),
        "p95_ms": ordered[math.ceil(.95 * len(ordered)) - 1],
        "max_ms": ordered[-1],
        "samples_ms": samples,
    }


def elapsed(start):
    return (time.perf_counter_ns() - start) / 1_000_000


def components(directory, lab, clock):
    keys = tuple(Ed25519PrivateKey.generate() for _ in range(2))
    policy = StatusPolicy("bench", "lab-blue", "research-org", "local-bench", lab.trust, tuple(
        WitnessGrant(f"witness-{i}", f"status-org-{i}", key.public_key()) for i, key in enumerate(keys)
    ))
    witnesses = tuple(
        StatusWitness(directory / f"witness-{i}.db", policy, f"witness-{i}", key, clock=clock, provision=True)
        for i, key in enumerate(keys)
    )
    reader = RelyingStatus(directory / "local.db", policy, "bench-deployment", clock=clock, provision=True)
    return policy, witnesses, reader


def evaluate(reader, bundle, fetch):
    manifest = decode(SignedManifest, bundle.manifest).body
    return reader.evaluate(
        bundle, expected_bundle_sha256=bundle.sha256, expected_claim_sha256=manifest.claim_sha256,
        expected_environment_sha256=manifest.environment_sha256, fetch=fetch,
    )


def admit(witnesses, *records):
    for record in records:
        for witness in witnesses:
            if witness.admit(record) != digest(record):
                raise RuntimeError("witness refused fixture intake")


def warm(directory, lab, clock, bundle, samples, sizes):
    policy, witnesses, reader = components(directory, lab, clock)
    observations = tuple(observe(policy, worker, bundle, clock=clock) for worker in lab.verifiers)
    admit(witnesses, bundle.manifest, *observations)
    pins = {digest(wire) for wire in observations}
    with Evidence(directory / "legacy.db", lab.trust, clock=clock, attestation_ttl=ATTESTATION_TTL) as evidence:
        for observation in observations:
            evidence.accept_attestation(bundle, observation, cohort=policy.cohort)
        legacy_ms = []
        for _ in range(samples):
            start = time.perf_counter_ns()
            result = evidence.assess(bundle, cohort=policy.cohort)
            legacy_ms.append(elapsed(start))
            if result.outcome != "reproduced" or set(map(digest, result.attestations)) != pins:
                raise RuntimeError("legacy assessment did not match the outcome and provenance oracle")

    rows = []
    last_size = 3
    for size in sizes:
        for i in range(last_size, size):
            admit(witnesses, lab.bundle(f"archive padding {i}").manifest)
        last_size = size
        total_ms, witness_ms, appraisal_ms = [], [], []
        proof_bytes = nonce_bytes = 0

        def fetch(request):
            nonlocal proof_bytes, nonce_bytes
            start = time.perf_counter_ns()
            left, right = (witness.endorse(request) for witness in witnesses)
            witness_ms.append(elapsed(start))
            proof = StatusProof(left.endorsements + right.endorsements, left.records)
            proof_bytes = sum(map(len, (*proof.endorsements, *proof.records)))
            nonce_bytes = len(request)
            return proof

        head = None
        for _ in range(samples):
            start = time.perf_counter_ns()
            result = evaluate(reader, bundle, fetch)
            total_ms.append(elapsed(start))
            appraisal_ms.append(total_ms[-1] - witness_ms[-1])
            if (result.outcome != "reproduced" or result.head is None or result.head.revision != size
                    or set(result.attestation_sha256) != pins or result.binding_sha256 is None):
                raise RuntimeError("status appraisal did not match the outcome, scope and provenance oracle")
            head = result.head
        rows.append({
            "archive_records": size,
            "checkpoint_root_sha256": head.root_sha256,
            "proof_payload_bytes": proof_bytes,
            "challenge_payload_bytes": nonce_bytes,
            "total": summary(total_ms),
            "two_sequential_endorsements": summary(witness_ms),
            "local_appraisal": summary(appraisal_ms),
        })
    return {"legacy_local_appraisal": summary(legacy_ms), "independently_witnessed": rows}


def cold(directory, lab, clock, bundle, samples):
    legacy_ms, independent_ms = [], []
    for i in range(samples):
        iteration = directory / str(i)
        iteration.mkdir()
        policy, witnesses, reader = components(iteration, lab, clock)

        def fetch(request):
            left, right = (witness.endorse(request) for witness in witnesses)
            return StatusProof(left.endorsements + right.endorsements, left.records)

        def independent():
            observations = tuple(observe(policy, worker, bundle, clock=clock) for worker in lab.verifiers)
            admit(witnesses, bundle.manifest, *observations)
            result = evaluate(reader, bundle, fetch)
            if result.attestation_sha256 and set(result.attestation_sha256) != {digest(wire) for wire in observations}:
                raise RuntimeError("cold appraisal used a different set of observations")
            return result.outcome

        with Evidence(iteration / "legacy.db", lab.trust, lab.verifiers, clock=clock,
                      attestation_ttl=ATTESTATION_TTL) as evidence:
            def legacy():
                return evidence.verify(bundle, cohort=policy.cohort).outcome

            arms = [(legacy, legacy_ms), (independent, independent_ms)]
            for measure, timings in arms if i % 2 == 0 else reversed(arms):
                start = time.perf_counter_ns()
                outcome = measure()
                timings.append(elapsed(start))
                if outcome != "reproduced":
                    raise RuntimeError(f"cold run returned {outcome}")
    return {"legacy_two_workers": summary(legacy_ms), "two_workers_and_independent_status": summary(independent_ms)}


def revocation(directory, lab, clock, bundle, samples):
    first_ms, second_ms = [], []
    for i in range(samples):
        iteration = directory / f"revocation-{i}"
        iteration.mkdir()
        policy, witnesses, reader = components(iteration, lab, clock)
        observations = tuple(observe(policy, worker, bundle, clock=clock) for worker in lab.verifiers)
        admit(witnesses, bundle.manifest, *observations)

        def fetch(request):
            left, right = (witness.endorse(request) for witness in witnesses)
            return StatusProof(left.endorsements + right.endorsements, left.records)

        if evaluate(reader, bundle, fetch).outcome != "reproduced":
            raise RuntimeError("revocation setup did not establish a reproduced observation")
        withdrawal = sign_record(Withdrawal(
            kind="aegis.evidence.withdrawal.v1", record_id=uuid4().hex, issuer="review", key_id="lab-v1",
            cohort=policy.cohort, issued_at=clock(), expires_at=clock() + 5,
            target_kind="bundle", target_issuer="research", target_sha256=bundle.sha256, reason="withdrawn",
        ), lab.revoker)
        for witness, reason, timings in zip(witnesses, ("divergent-status", "revoked"), (first_ms, second_ms)):
            start = time.perf_counter_ns()
            admit((witness,), withdrawal)
            result = evaluate(reader, bundle, fetch)
            timings.append(elapsed(start))
            if result.reason != reason or result.binding is not None:
                raise RuntimeError("witnessed withdrawal did not stop positive eligibility")
    return {"first_admission_to_divergent": summary(first_ms), "second_admission_to_revoked": summary(second_ms)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warm-samples", type=int, default=100)
    parser.add_argument("--cold-samples", type=int, default=20)
    parser.add_argument("--sizes", type=int, nargs="+", default=[3, 32, 128, 256])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.warm_samples, args.cold_samples) < 1 or not 3 <= min(args.sizes) <= max(args.sizes) <= MAX_HISTORY:
        parser.error("positive sample counts and archive sizes between 3 and MAX_HISTORY are required")

    lab = create_lab(1_800_000_000)
    bundle = lab.bundle("fixed local synthetic marker")

    def clock():
        # Hold evidence age fixed across workloads so they measure appraisal rather than refresh.
        return lab.now

    with TemporaryDirectory(prefix="aegis-t5-bench-") as temp:
        directory = Path(temp)
        report = {
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cryptography": version("cryptography"),
            "pydantic": version("pydantic"),
            "fixture_environment": vars(LOCAL_PROFILE),
            "status_ttl_seconds": STATUS_TTL,
            "attestation_ttl_seconds": ATTESTATION_TTL,
            "synthetic_clock": lab.now,
            "bundle_sha256": bundle.sha256,
            "fixture_material_sha256": {role: digest(data) for role, data in bundle.objects.items()},
            "source_sha256": {
                str(path): digest(path.read_bytes()) for path in (
                    Path(__file__).relative_to(Path.cwd()), Path("src/aegis/evidence/status.py"),
                    Path("src/aegis/evidence/status_protocol.py"),
                )
            },
            "warm": warm(directory, lab, clock, bundle, args.warm_samples, sorted(set(args.sizes))),
            "cold": cold(directory, lab, clock, bundle, args.cold_samples),
            "revocation": revocation(directory, lab, clock, bundle, args.cold_samples),
        }
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
