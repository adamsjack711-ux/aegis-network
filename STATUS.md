# Aegis Network status

## Phase 4 architecture handoff

All three Phase 4 development worktrees were verified clean at Phase 3C `7744ebd` during intake. The full baseline suite passed 129 tests. The isolated control rerun confirmed all 60 eligible lab rollouts and reproduced the reuse-heavy 100-deployment CPU result at 11.1647×. Phase 4 candidates are pending. The contract freeze and 4A → 4B → 4C sequence are recorded in the planning worktree.

An independent baseline check reproduced a critical protection release blocker. The current journal can omit a valid withdrawal and still pass the freshness prerequisite. No mitigation writes were attempted in the check. Phase 4 release readiness remains pending. [Integration plan](docs/phase4-integration-plan.md) · [Contract freeze](docs/phase4-contract-review.md) · [Risk register](docs/phase4-risk-register.md)

## Phase 4A distributed reliability

Phase 4A on `feat/phase4a-distributed` verified distribution to **300 independent agent processes on one physical host**. Both completed 300-agent runs confirmed **8,100/8,100** expected decisions and found zero duplicate logical decisions or missed withdrawals. Decision p95 was **465–500 ms** for steady traffic and **4.23–5.57 s** for a 20-finding burst.

The 100-agent stress run drained 1,600 pending deliveries after paused agents resumed. Controlled faults covered duplicate identity claims, SIGKILL recovery, broker restart, JetStream capacity backpressure, and signed journal repair after purge. One deliberately crashed identity crossed the five-second withdrawal reporting threshold in each fault profile and recovered. The separate approved fixture confirmed five restricted rollouts with **381.70 ms p95** from verification to protection.

The 500- and 1,000-agent profiles stopped before sending traffic when their memory projections exceeded the configured host budget. Real multi-host scale and replicated broker or database failover remain open. See the [Phase 4A handoff](docs/phase4a-distributed.md) for the raw traces, reproduction commands, and limits.

## Phase 4B evidence portability

Verified 2026-11-19 on `feat/phase4b-evidence` in `.worktrees/phase4b-evidence` from the reviewed Phase 3C baseline `7744ebd`. This is a single-host synthetic experiment. Exact reuse remains bound to the signed bundle and authorized cohort. The sole compatibility rule checks an inert package-label change, a signed link to the exact source, and equal behavior-bearing inputs. All other compatibility is unknown. Mesh transports the signed finding and Rapid requires exact evidence for Phase 3C findings.

All 162 tests passed, including 33 Phase 4B cases. The full suite used local Unix sockets for the existing disposable fixtures. It covered expiry, bundle and key withdrawals, contradiction holds, independent verifier identities, and simultaneous exact-scope collection.

The four benchmark strategies ran at 10, 100, and 1,000 deployments over three seeds. Exact-scope sharing reduced median paired CPU by 17.19× at 1,000 clustered deployments and 3.49× at 1,000 heterogeneous deployments. No incorrect cache reuse was observed across 16,505 hits. One heterogeneous compatibility sample had four inconclusive assessments without the expected signed result. Every conclusive assessment matched its expected outcome and provenance. A diagnostic replay passed all 1,000 requests.

The cohort experiment used separate trust keys and ledgers. Multi-host status completeness, administrative independence, real software compatibility, production privacy, and live broker validation remain outside this result.

See [the Phase 4B handoff](docs/phase4b-evidence-portability.md) for the scope matrix, reproduction commands, raw measurements, and limitations.

## Phase 4C independent validation

The 2026-11-19 review is on `test/phase4c-adversarial` in `.worktrees/phase4c-adversarial`, based on `7744ebd`. All 137 tests passed, including eight new defensive checks of the integrated path. Independent HTTP and SQLite readback verified that a signed withdrawal after the canary prevented peer writes and that fixture lease expiry closed all nine routes before durable recovery. Mesh replay was in-process, and fixture HTTP was live on loopback.

Retain isolated-lab use. Integration review should prioritize independently witnessed journal completeness, authenticated cross-broker identity with durable fencing, and independently administered Evidence status. [Phase 4C report](docs/phase4c-adversarial.md) · [Threat-model proposals](threat-model.md#proposed-phase-4c-trust-boundaries)

## Aegis Trust isolated prototype

**2026-11-19.** Use `.worktrees/aegis-trust` on `feat/aegis-trust`, based on Phase 3C `7744ebd7f80e6f2aabb253d5cc3ec9972c86cffd`. The separate `aegis.trust_lab` package demonstrates receipted withdrawal coverage, independently signed Evidence status, exact local approval, cross-broker generation fencing, and held or authenticated recovery on synthetic fixtures.

All 35 prototype tests and all 172 tests in the combined Phase 3C, Phase 4C, and Trust run passed. The local full-prefix benchmark measured 25, 155 and 582 ms p95 at 3, 32 and 128 records. State and isolation tests used one process topology and local files. Live authenticated transport, operational independence, a multi-target ownership barrier, and rollback-safe witness handover remain integration gates. [Architecture](docs/trust/architecture.md) · [Acceptance and reproduction](docs/trust/acceptance-tests.md) · [Integration plan](docs/trust/integration-plan.md)

## Phase 3C local-lab integration

Verified implementation **`1cb5cd60467ad6885f8aa1350197f576c06ae0ed`** on `integration/phase3c` in `.worktrees/phase3c`. The branch uses Phase 2 RC `ffe5c32` and the pinned Phase 3A, 3B and 3D commits. Master and the source feature branches were preserved. The Phase 2 runtime remains dry-run. Phase 3C applies only an exactly approved route restriction in a disposable synthetic fixture.

The integrated runner verifies digest-pinned Evidence with signed attestations, transports the signed finding over the existing Mesh outbox and JetStream, independently appraises the finding and evidence at each eligible Rapid deployment, then requires local exact-plan approval. A fenced canary gates expansion. Independent HTTP probes confirm the marker is suppressed and the benign routes are healthy. A durable audit binds the finding and attestations to the action and observation. Withdrawal, status or health loss, and expiry force a restrictive recovery.

**Verified 2026-11-19.** All 129 tests passed, including the Phase 3D suite and the stable invalid-signature reason and watermark test. Live scoped Mesh withdrawal and broker loss reached verified quarantine in 117.530 and 1,304.709 ms. The original Phase 2 live regression passed, including actual network partition, purge/replay, and crash recovery. Lab containers were stopped.

| Logical agents | Confirmed eligible deployments | Verified finding to protection p95 |
| ---: | ---: | ---: |
| 3 | 20/20 | 512.200 ms |
| 10 | 20/20 | 532.374 ms |
| 100 | 20/20 | 602.859 ms |

The benchmark used scripted local approval and two three-replica fixture deployments per episode. It observed zero marker escapes across 360 post-confirmation marker probes. The 100-deployment cold, three-key workload saved 11.15× verification CPU. The all-distinct workload saved 1.01×. The latency and compute thresholds were observed under the stated lab workloads. Human approval p95, multi-host availability, independent status completeness, authenticated broker identity, and distributed operator trust remain open.

See [the Phase 3C handoff](docs/phase3c-integration.md) for the compatibility register, acceptance checklist, reproduction commands, exact timings, raw results, and unresolved risks.
