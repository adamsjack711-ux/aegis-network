# Aegis Network status

## Phase 4E integration

The common clean baseline is Phase 4D `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f`. The integration checkout is `.worktrees/phase4e` on `integration/phase4e`. The clean baseline reproduced **272 passing tests** with all three local live modes enabled. Both detached T6 commits reconstructed at their retained hashes. The later guarded fixture contains both source and test changes, and its distributed verdict remains failed.

Four specialist workstreams share the approved baseline in separate worktrees. Independent baseline probes reproduced withdrawal starvation and a 29.644-second restart-to-ACK interval after SIGKILL. Three new Phase 4B diagnostic trials each matched 1,000/1,000 outcomes, with the original four availability/provenance misses retained. The original cause remains unknown.

Authorized testing stays on disposable localhost or container fixtures with throwaway test signing material. Physical multi-host acceptance, independent administration and distributed enforcement remain blocked. [Architecture](docs/phase4e-architecture.md) · [Contract review](docs/phase4e-contract-review.md) · [Integration plan](docs/phase4e-integration-plan.md) · [Risk register](docs/phase4e-risk-register.md) · [Benchmarks and topology](docs/phase4e-benchmarks.md)

## Phase 4E-A withdrawal priority

The opt-in lab profile on `feat/phase4e-withdrawal` starts from approved Phase 4D `ae59a97`. Five paired broker-restart trials put one withdrawal behind 1,000 ordinary findings. The priority worker acknowledged the withdrawal first in each trial. Intake-to-report p95 was 2.675 seconds. SIGKILL after an audit commit left a denial reportable in 55 ms, with an ACK at 30.476 seconds. SIGKILL before intake left the all-agent five-second gate open. The existing lease and independently verified actuator authority still apply. [Implementation and risks](docs/phase4e-withdrawal.md) · [Raw measurements](benchmarks/phase4e/)

## Phase 4E-C isolated trust services

`feat/phase4e-trust` in `.worktrees/phase4e-trust` starts at approved Phase 4E baseline `ae59a97`. The local-service prototype exercises direct scoped withdrawal intake, independent checkpoint and status signing, authenticated archive replay, and protected floors across isolated processes. The default suite passed 278 tests on 2026-11-19, including all nine Phase 4E-C tests. Three opt-in Docker cases were skipped. The shared Phase 3C/T6 writer remains outside this change. Independent real-world custody, anchor recovery, withdrawal dispatch priority and target fencing remain integration and release gates. [Trust model, contract and terminal handoff](docs/phase4e-trust.md) · [Raw local measurements](benchmarks/phase4e-trust.json)

## Phase 4D isolated integration candidate

The native Trust profile is integrated in `.worktrees/phase4d` on `integration/phase4d`. It layers native witnessed Mesh coverage, independent Evidence status and durable ownership fencing onto explicit approvals for the disposable three-replica fixture. At tested pin `f26f69d`, the complete suite passed **272 tests** with all local live modes enabled. All three Phase 4C High findings have tested fixture dispositions. Distributed enforcement remains blocked on independently administered endpoints, authenticated broker identity and session fencing, rollback-resistant trust anchors and barriers across separate writers. [Architecture](docs/phase4d-architecture.md) · [Security dispositions](docs/phase4d-security-review.md) · [Release readiness](docs/phase4d-release-readiness.md)

The 10-process legacy transport comparison delivered **810/810** logical decisions per arm. The candidate's fault run recovered **310/310** logical decisions, with one withdrawal crossing the five-second reporting budget after SIGKILL. In 12 paired preprovisioned fixture trials per arm, p95 plan-request-to-confirmation was **185.949 ms** with Trust and **137.772 ms** for legacy. The exact three-key 100-deployment workload saved **10.9334×** verification CPU. The all-distinct workload saved **1.0033×**. [Methods and raw results](docs/phase4d-benchmarks.md) · [Commit intake and conflicts](docs/phase4d-trust-integration.md)

## Phase 4 architecture handoff

All three Phase 4 development worktrees were verified clean at Phase 3C `7744ebd` during intake. The full baseline suite passed 129 tests. The isolated control rerun confirmed all 60 eligible lab rollouts and reproduced the reuse-heavy 100-deployment CPU result at 11.1647×. The contract freeze and 4A → 4B → 4C sequence were recorded in the planning worktree.

An independent baseline check reproduced a critical protection release blocker. The coordinator-only journal could omit a valid withdrawal and still pass the freshness prerequisite. The check used no mitigation writes. [Integration plan](docs/phase4-integration-plan.md) · [Contract freeze](docs/phase4-contract-review.md) · [Risk register](docs/phase4-risk-register.md)

## Phase 4D Journal Integrity

The reference witnessed Mesh profile addresses 4C-01 in `.worktrees/phase4d-journal-integrity` on `feat/phase4d-journal-integrity`. The tested implementation is `2de4d1b`, on the Phase 4A baseline with Phase 4C's review and defensive tests. The combined suite passed 154 tests with both live fault modes enabled on 2026-11-19. The witnessed gate blocked peer writes after a separately admitted withdrawal and recovered that withdrawal after replacing NATS and damaging the original archive. Phase 4A's broker restart and journal repair also passed.

Deployment acceptance requires independently administered witnesses, rollback-resistant pins, and a witnessed-only cutover for protected writers. See the [trust model, integrity evidence, and integration requirements](docs/phase4d-journal-integrity.md) and [raw benchmark results](benchmarks/phase4d-journal.json).

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

## Phase 4D T5 independent Evidence status

The 2026-11-19 T5 handoff is on `feat/phase4d-t5-evidence` in `.worktrees/phase4d-t5-evidence`, based on the Phase 4C review at `52a4dc4`. The prototype uses two independent verifier organizations and two separately enrolled status operators. The relying party verifies complete status, retains continuity and denial history, and supplies a stable Evidence binding for explicit local policy review. The isolated lab benchmark measured p95 appraisal of 3.21 ms at three records and 70.84 ms at 256 records. [Protocol and T6 instructions](docs/phase4d-t5-evidence-status.md) · [Raw measurements](benchmarks/phase4d-t5-evidence.json)

The full Phase 4C-based suite passed 157 tests and skipped the Phase 4B-only case, with the inherited Starlette/httpx deprecation warning. The combined Phase 4B and T5 focused suites passed all 54 tests. The 4C-04 fix is demonstrated at the T5 API boundary. T6 owns wiring the gate into the disposable writer and validating independently administered services, authenticated intake and recovery before promoting a release candidate.

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
