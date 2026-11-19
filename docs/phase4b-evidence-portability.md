# Phase 4B — Evidence portability

Phase 4B starts at the reviewed Phase 3C commit `7744ebd7f80e6f2aabb253d5cc3ec9972c86cffd` on `feat/phase4b-evidence`. It measures reuse for a closed set of synthetic marker fixtures. The Phase 3A exact verifier and the Phase 3C finding, Mesh transport, Rapid appraisal, approval, and containment path still use their existing interfaces and trust requirements. [Phase 3A Evidence](phase3a-evidence.md) · [Phase 3C integration](phase3c-integration.md)

## What can be reused

**Exact scope.** Use the signed manifest SHA-256 and authorized cohort as the cache key. Each verifier observation signs that exact digest. Manifests bind the claim, issuer, material pins, worker environment, harness and oracle. On reuse, a relying deployment rechecks the digest, material bytes, signatures, eligible verifier organizations, validity, applicable withdrawals, and any contradiction hold in its local ledger. Two current independent organizations and passing controls are required for a conclusive result. A negative observation describes only the tested scope. Repeated signed inconclusive observations can avoid identical work while current and still yield an inconclusive assessment.

**Independently checked compatibility.** The only enabled relation is `synthetic-package-label-v1`. A signed target manifest pins a subject with the literal `repackaged` label and the SHA-256 of a specific signed source manifest whose subject has the literal `original` label. The appraiser verifies both manifests and their materials under local trust, then checks the source pin and compares all other subject bytes, the claim, cohort, issuer, key, configuration, target runtime, policy, dependencies, recipe, and worker profile. The fixture has a finite registry and its marker ignores the packaging label. Both manifests must be current and the source must still have a positive quorum. An independently signed direct observation anywhere in the target material scope takes precedence, including after that observation expires or is withdrawn.

A compatibility match carries the source assessment, target manifest digest, and local rule identifier. The source attestations stay bound to the source. The target manifest binds the claimed relation to the exact source envelope. Relying deployments recompute the relation with their own stored status and trust. A missing match means **unknown**. The caller can then verify the target independently if it is eligible. The Phase 3C gate still requires direct exact evidence for its finding. There is no transitive reuse, transfer of negative observations, or substitution of a newly signed source envelope for a withdrawn source.

The collective-intelligence research in the workspace informed the two-layer design. An index can suggest an immutable source by digest, and the relying party appraises the original signed statements. Bazel separates action lookup from content storage, and in-toto statements bind an attestation to immutable subjects. Phase 4B uses the repository's Ed25519 Evidence format. [Bazel remote caching](https://bazel.build/remote/caching) · [in-toto Statement specification](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)

## Reproducible scope matrix

All rows use the same claim unless stated otherwise. For changed rows the target points to the same signed original even when the change makes it ineligible for compatibility. The expected outcomes are fixed in the [machine-readable matrix](../tests/fixtures/phase4b_portability.json), shared by the tests and the benchmark.

| Target relative to reproduced original | Exact evidence from original reusable | Compatibility | Independent target result |
| --- | --- | --- | --- |
| Identical signed original | Yes | Exact path | Reproduced |
| Package label and source pin only | No | Supported | Reproduced |
| Version v2 or v3 | No | Unknown | Not reproduced |
| Alternate build | No | Unknown | Not reproduced |
| Feature disabled | No | Unknown | Not reproduced |
| Runtime B | No | Unknown | Not reproduced |
| Runtime offline | No | Unknown | Inconclusive |
| Security policy v2 | No | Unknown | Not reproduced |
| Dependency lock v2 | No | Unknown | Not reproduced |
| Build recipe v2 | No | Unknown | Reproduced |
| Harness v2 | No | Unknown | Reproduced |
| Harness unavailable | No | Unknown | Inconclusive |

Recipe and harness changes are blocked even when the same marker still appears. Separate tests reject unknown profiles and dependencies, changes to the claim or claimed source digest, altered bytes, reissued source envelopes, negative or inconclusive sources, and cross-cohort use.

## Verification and invalidation tests

- Collect two signed observations in separate single-signer Evidence instances and verify that a relying ledger needs both. Two keys in one organization, the submitter's organization, a key outside the cohort, and an unknown key cannot fill an independent role.
- Reappraise at the expiry boundary and after worker refresh. Verify that withdrawal of either bundle, an attestation, or a verifier key invalidates compatibility and that withdrawal tombstones survive restart and envelope expiry.
- Inject contrary signed observations for the source and target. A contradiction places the material scope on a durable hold. A reissued envelope and expired observations leave that hold in force.
- Launch 12 simultaneous requests across four exact scopes. Each scope performs two worker attempts. The requests span different harnesses, a related target, and separate cohorts. A withdrawal while a worker is running prevents its result from seeding reuse.
- Exercise missing controls and worker source drift. Both leave the claim inconclusive. Out-of-cohort manifests and attestations are rejected even when both cohorts use the same fixture.

See [Phase 4B automated tests](../tests/test_phase4b_evidence.py). The original worker bytes and profile pins are preserved. The new profile is explicitly enrolled and binds the fixed marker worker, the existing audit restriction helper, the interpreter and platform identity, and the selected harness.

## Benchmark protocol

| Arm | Verification schedule |
| --- | --- |
| Independent | A separate collector runs two isolated attempts for every logical deployment. |
| Exact shared | One collector runs two attempts per distinct signed scope. Every deployment appraises the signed observations locally. |
| Compatible shared | If an exact target has already been collected, use it. Otherwise, the cache may offer an already collected source. The relying deployment checks the narrow rule and falls back to exact collection when the relation is unknown. |
| Private cohorts | Two seeded cohorts have separate keys, roster grants, and in-memory ledgers. Each cohort reuses exact evidence only within its own namespace. |

Each arm starts cold and processes the same shuffled fixture sequence. The clustered workload repeats four scopes with one claim. The heterogeneous workload cycles all 13 fixtures, creating a separate claim per group of 52 requests. Cohort assignment uses the same seed as the request shuffle. The report covers 10, 100, and 1,000 deployments with three seeds, one in-memory relying ledger per request, and a fresh process per arm. Worker attempts run sequentially in the timing experiment. Concurrency and status faults are tested separately.

The report records aggregate parent and child CPU seconds, worker attempts, wall time, and parent and child RSS high-water marks. With one worker active at a time, the sum of the two peaks is an upper bound on simultaneous aggregate memory, since the peaks may occur at different times. A cache hit is a deployment served without a new worker attempt with signed observations to appraise. The report includes conclusive and operational inconclusive hits separately. An incorrect hit includes a wrong outcome, an unauthorized source scope, or mismatched attested bundle digest or cohort. The three-way accuracy metric includes correctly inconclusive cases. Conclusive accuracy and cost per correct conclusive case are recorded separately. Verified-finding latency is measured from request start to correct reproduced appraisal. The report also gives the time from episode start to the first such result and the latency of all assessments.

Cost is measured in CPU milliseconds per correctly assessed deployment, including local appraisal and cache operations. Process RSS includes runtime and fixture setup. Key generation and workload construction are outside the CPU and latency timing window. Worker startup is included. The raw report records profile and corpus digests, run order, outcomes, and per-arm metrics. [Raw measurements](../benchmarks/phase4b-evidence-portability.json)

## Benchmark results

The 72 arm-runs processed 26,640 requests and accepted 16,505 cache hits. **No incorrect cache reuses or false conclusive results were observed.** The strict oracle and provenance check passed on 26,636 requests. In one heterogeneous 1,000-deployment compatibility sample (seed `20261120`), three cases expected to be conclusive returned inconclusive, and one expected inconclusive lacked the required signed provenance. The original sample remains in the data and the medians. The benchmark CLI writes the report and exits nonzero for a strict oracle discrepancy.

The four values in each cell are ordered **independent / exact shared / compatible shared / private cohorts**. Values are medians across three seeds. CPU speedups are medians of the paired ratios to the independent arm for exact, compatible, and cohort sharing.

| Deployments | Workload | Public exact scopes | Worker attempts | CPU ms per correctly assessed deployment | Paired CPU speedups |
| ---: | --- | ---: | --- | --- | --- |
| 10 | Clustered | 4 | 20 / 8 / 6 / 14 | 74.37 / 31.81 / 26.48 / 55.11 | 2.34× / 2.85× / 1.37× |
| 10 | Heterogeneous | 10 | 20 / 20 / 18 / 20 | 74.38 / 73.51 / 70.18 / 72.43 | 1.00× / 1.06× / 0.99× |
| 100 | Clustered | 4 | 200 / 8 / 8 / 16 | 74.66 / 6.71 / 6.85 / 9.63 | 11.20× / 11.07× / 7.93× |
| 100 | Heterogeneous | 26 | 200 / 52 / 50 / 96 | 70.37 / 21.40 / 20.50 / 36.37 | 3.29× / 3.43× / 1.96× |
| 1,000 | Clustered | 4 | 2,000 / 8 / 8 / 16 | 73.33 / 4.22 / 4.19 / 4.50 | 17.19× / 17.11× / 16.08× |
| 1,000 | Heterogeneous | 259 | 2,000 / 518 / 494 / 950 | 89.92 / 26.02 / 27.61 / 44.89 | 3.49× / 3.26× / 2.00× |

### 1,000-deployment latency, cache and memory

| Workload | Arm | Aggregate CPU seconds | Aggregate peak RSS upper bound (MiB) | Cache hits | Verified finding p95 (ms) |
| --- | --- | ---: | ---: | ---: | ---: |
| Clustered | Independent | 73.33 | 70.2 | 0.0% | 82.0 |
| Clustered | Exact shared | 4.22 | 70.2 | 99.6% | 4.0 |
| Clustered | Compatible shared | 4.19 | 70.0 | 99.6% | 4.2 |
| Clustered | Private cohorts | 4.50 | 70.4 | 99.2% | 4.0 |
| Heterogeneous | Independent | 89.92 | 70.8 | 0.0% | 114.4 |
| Heterogeneous | Exact shared | 26.02 | 71.9 | 74.1% | 94.4 |
| Heterogeneous | Compatible shared | 27.61 | 71.9 | 75.3% | 132.3 |
| Heterogeneous | Private cohorts | 44.89 | 72.7 | 52.5% | 98.7 |

At 1,000 deployments, median reproduction and inconclusive rates were 50.0% and 25.0% in the clustered workload and 30.8% and 15.3% in the heterogeneous workload. All observed conclusive outcomes matched their expected outcomes and provenance. The RSS upper bound stayed within 70–73 MiB at this scale. The report contains CPU cost per correct conclusive assessment, per-arm rates, and per-seed latency.

Exact sharing delivered the largest consistent savings as repeated scopes became common. In the heterogeneous 1,000-deployment trial, checking compatibility saved 8–28 worker attempts per seed relative to exact sharing. It used more aggregate CPU in each of those three pairs. Whether a source arrived before a target affected whether compatibility saved a run. The separate private cohorts required more attempts, while still cutting median heterogeneous CPU in half relative to independent verification. Keep exact sharing as the baseline. The compatibility result supports further testing of this narrow rule when verification itself costs more than it does in the marker lab.

A diagnostic replay of seed `20261120` with worker exception logging matched all 1,000 expected results. It recorded 502 attempts, 749 hits, zero incorrect reuses, and zero worker exceptions. The original sample had 510 attempts and took 75.16 seconds wall time, compared with 27.26 seconds in the replay. The evidence establishes an intermittent loss of assessment availability in the original sample. The original run did not record worker exception subtypes, so the immediate cause remains open. The replay is excluded from the three-seed comparison.

## Reproduce

Run from the Phase 4B worktree with the repository's Python environment and test dependencies. The full suite uses local Unix sockets for its disposable HTTP fixtures.

```sh
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python scripts/benchmark_phase4b_evidence.py \
  --deployments 10 100 1000 --repetitions 3 \
  --output benchmarks/phase4b-evidence-portability.json
```

## Limits and handoff

- The target versions, builds, dependencies, runtime and policy are inert fixture bytes. The relying caller must supply an authenticated, current target inventory and ledger status for a real deployment. Real build or runtime equivalence remains unknown.
- Source and target status are rechecked in one local ledger snapshot. The result depends on complete withdrawal and contradictory evidence delivery. The experiment leaves multi-host reconciliation, withholding detection, offline recovery, key enrollment governance, and proof of organizational independence open.
- Single flight is an in-process property of the Evidence coordinator. The study covers simultaneous identical jobs and withdrawal while in flight. Distributed leases, recovery after coordinator loss, and durable queueing remain open.
- Cohort isolation is evaluated through keys, grants, exact scope, and separate local ledgers. The benchmark driver sees both synthetic workloads and does not measure service-level access controls, encryption or metadata leakage. Deployment agents, workers, storage and trust domains are simulated on one host. CPU is a compute proxy. Infrastructure, network transfer, operator labor, and real verification cost are unmeasured.
- Zero observed errors in a finite, correlated synthetic corpus establishes the behavior of these tested cases. It gives no estimate of real cross-deployment error probability or real mitigation effectiveness. Phase 4B is a local research result on the feature branch.
