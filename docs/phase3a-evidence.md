# Phase 3A — Aegis Evidence

Aegis Evidence runs offline verification of enrolled synthetic marker fixtures and appraises the signed observations. The component lives under `aegis.evidence` and has a local Python API. Its only output is an assessment of evidence for a specific claim and bundle.

## Intake and signatures

- The intake caller supplies the authorized cohort, the expected SHA-256 of the signed manifest, the manifest bytes, and exactly four pinned byte objects. Each pin includes its digest and byte length. The objects represent the synthetic subject, configuration, dependency lock, and build recipe.
- The manifest binds the claim digest, fixture family, submitter, cohort, timing, material pins, environment, check, and oracle. The claim digest is an opaque reference. In the reusable lab fixture it comes from a synthetic claim label. Another authorized intake could supply the digest of an exact signed finding reference.
- Only registry entries for feature-gate, route-toggle, and service-access marker models are admitted. Admission checks every object before consulting the cache or starting a worker. The worker repeats the registry check. Objects are short fixed byte strings. The installed registry defines all test behavior.
- Wire records are strict canonical ASCII JSON envelopes with an Ed25519 signature over the bytes `AEGIS-EVIDENCE\x00` followed by the canonical body. Canonical JSON uses sorted keys, compact separators, and escaped Unicode. The body includes the versioned kind, issuer, key ID, cohort, record ID, and validity interval. Noncanonical encoding, duplicate fields, unknown fields, and conflicting content under an existing kind, cohort, issuer, and record ID are rejected. Pins use lowercase SHA-256. Signed records are limited to 8 KiB and each of the four objects to 4 KiB.
- Trust comes from locally pinned submitter, verifier, and revoker grants. A public key belongs to one issuer and role. An issuer belongs to one organization. The operator sets cohort membership, approved worker profiles, and revoker scope. The caller supplies the cohort after its own authorization check.

## Worker and appraisal

Each attempt starts a fresh isolated Python process with a disposable working directory, an empty environment, closed inherited descriptors, and bounded stdio input. The parent verifies the worker source digest and launches a private copy of the verified bytes. A parent deadline terminates a timed-out process. The worker sets CPU, regular-file output and core-dump limits, plus a 256 MiB address-space limit on Linux. Its Python audit hook blocks file opens, imports, process creation, and socket operations after startup. The boundary is designed for the fixed stdlib worker and inert fixtures. It depends on the trusted interpreter, host, and installed source.

The check and oracle pins are domain-separated digests of the worker source. The environment pin binds the isolation profile, worker source, interpreter implementation/version, and OS release and architecture. A collector can run only its installed profile. A relying party can appraise an explicitly enrolled profile from another machine. Attestations include the signed manifest digest, run start and end, both control results, and a typed observation. The verifier key stays with its signer in the parent process.

| Assessment | Rule |
| --- | --- |
| `reproduced` | Two current verifier organizations observed the marker with both controls passing. |
| `not-reproduced` | Two current verifier organizations observed its absence with both controls passing. The conclusion applies to the exact synthetic scope. |
| `inconclusive` | Insufficient independent agreement, an unavailable oracle or worker, an expired or withdrawn bundle, or a recorded contradiction. The assessment reason and any signed observations distinguish those cases. |

One organization contributes at most one vote to each outcome. The submitter's organization is ineligible to vote. Each verifier can run in a separate signer service with one private key. A relying deployment imports and checks both attestations using its own pinned public trust. The single-host lab and benchmark simulate distinct organizations with separate keys and subprocess attempts. Administrative independence is an enrollment assumption.

## Reuse and invalidation

- The reusable key is the authorized cohort and exact signed bundle digest. Within one coordinator, concurrent callers share one in-flight attempt per key and verifier identity. Each appraisal revalidates signed bytes, time and trust. Completed inconclusive observations can be reused until expiry. Crashes, timeout and malformed worker output leave no signed result and a later request can retry.
- Times are UTC Unix seconds and validity intervals are half-open. Local attestations expire after at most five minutes by default and are bounded by bundle and verifier-grant expiry. A relying party also enforces its configured maximum attestation lifetime. The SQLite ledger records a time high-water mark and rejects observed rollback. Host clock accuracy and backup integrity are local operator dependencies.
- A trusted revoker can withdraw a bundle, attestation, or verifier key by target issuer and digest in an authorized cohort. A verifier-key target digest hashes the raw Ed25519 public key. Withdrawal can arrive before its target. Once accepted, a tombstone survives withdrawal-envelope expiry and process restart. The coordinator rechecks bundle and verifier eligibility before publishing a worker result.
- Fresh credible positive and negative observations for the same material scope create a durable `contested` hold, even if a quorum previously passed. The hold stores the two signed attestation digests. Material scope includes the cohort, submitter, claim digest, family, all object pins, environment, check, and oracle. Reissuing a manifest for the same material scope carries the hold forward. Votes still bind the exact signed envelope. Time and later withdrawals do not clear a recorded hold. A corrected claim or materially changed scope requires its own signed bundle and corroboration.
- One component instance owns each local SQLite ledger. The ledger is trusted local state with persistent manifests, signed observations, withdrawal tombstones, and contradiction history. Portable attestations require independent intake of applicable withdrawals. Withdrawal freshness and single flight depend on this local ledger. The caller supplies the applicable withdrawal feeds.

## Reproduce locally

Use the repository's Python environment with its test dependencies installed.

```sh
PYTHONPATH=src python -m pytest -q tests/test_phase3a_evidence.py
PYTHONPATH=src python scripts/benchmark_phase3a_evidence.py \
  --deployments 10 100 --scenarios cold warm distinct cohorts one-per-ten \
  --repetitions 5 --output benchmarks/phase3a-evidence.json
```

```python
from aegis.evidence import Evidence
from aegis.evidence.synthetic import create_lab

lab = create_lab()
bundle = lab.bundle("synthetic marker example")
with Evidence(":memory:", lab.trust, lab.verifiers) as coordinator:
    result = coordinator.verify(bundle, cohort="lab-blue")
assert result.outcome == "reproduced"
```

The tests exercise live workers, quorum and control behavior, portable signatures, key and record forgery, material and cache corruption, exact-scope isolation and deduplication, time rollback, durable withdrawal and contradiction, worker timeout/crash, retry, and withdrawal during a run.

All 22 Evidence tests passed. The full suite passed 29 tests and reproduced one baseline failure in `test_invalid_signature_does_not_poison_sequence`. The existing assertion expects `invalid or expired signature` while the baseline agent returns `invalid signature`.

## Shared versus repeated verification

The benchmark pairs each workload and seed across two arms. Repeated verification runs two isolated verifier attempts per logical deployment and stage. Shared verification uses one coordinator with two attempts per distinct cohort and bundle key. Both arms include manifest intake and separate local signature appraisal per deployment. The warm workload charges both the cold warm-up and replay. The benchmark verifies each result against the frozen synthetic outcome and checks attempt counts.

The [raw benchmark](../benchmarks/phase3a-evidence.json) records wall time, aggregate user and system CPU time for the coordinator and child processes, worker attempts, exact key counts, all outcome counts, and source digests. It covers the 10- and 100-deployment scales with five pairs each. The 1,000-deployment scale and mixed stale/contradictory performance workload were unrun. Adversarial cases are covered by functional tests. These runs model a local CPU-only marker workload with in-memory ledgers and sequential requests. Worker startup is a substantial part of the cost. The measured costs are local process execution, in-memory ledger activity, and signature appraisal.

### 100 logical deployments

CPU times are medians in aggregate core-seconds. Ratios are medians of paired repeated/shared CPU times with the observed ranges. Both arms matched the expected result for every deployment and stage.

| Scenario | Exact keys | Worker attempts, repeated / shared | CPU, repeated / shared | Paired CPU ratio |
| --- | ---: | ---: | ---: | ---: |
| cold | 3 | 200 / 6 | 6.428 / 0.576 | 11.28× (10.96–11.42×) |
| warm | 3 | 400 / 6 | 12.371 / 0.963 | 12.82× (12.19–13.17×) |
| distinct | 100 | 200 / 200 | 6.171 / 6.158 | 1.02× (0.94–1.05×) |
| cohorts | 6 | 200 / 12 | 6.356 / 0.751 | 8.46× (8.42–8.51×) |
| one-per-ten | 12 | 200 / 24 | 6.324 / 1.104 | 5.73× (5.66–5.83×) |
