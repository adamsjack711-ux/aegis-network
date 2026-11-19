# Aegis Network status

## Phase 4 architecture handoff

All three Phase 4 development worktrees were verified clean at Phase 3C `7744ebd` during intake. The full baseline suite passed 129 tests. The isolated control rerun confirmed all 60 eligible lab rollouts and reproduced the reuse-heavy 100-deployment CPU result at 11.1647×. Phase 4 candidates are pending. The contract freeze and 4A → 4B → 4C sequence are recorded in the planning worktree.

An independent baseline check reproduced a critical protection release blocker. The current journal can omit a valid withdrawal and still pass the freshness prerequisite. No mitigation writes were attempted in the check. Phase 4 release readiness remains pending. [Integration plan](docs/phase4-integration-plan.md) · [Contract freeze](docs/phase4-contract-review.md) · [Risk register](docs/phase4-risk-register.md)

## Phase 4A distributed reliability

Phase 4A on `feat/phase4a-distributed` verified distribution to **300 independent agent processes on one physical host**. Both completed 300-agent runs confirmed **8,100/8,100** expected decisions and found zero duplicate logical decisions or missed withdrawals. Decision p95 was **465–500 ms** for steady traffic and **4.23–5.57 s** for a 20-finding burst.

The 100-agent stress run drained 1,600 pending deliveries after paused agents resumed. Controlled faults covered duplicate identity claims, SIGKILL recovery, broker restart, JetStream capacity backpressure, and signed journal repair after purge. One deliberately crashed identity crossed the five-second withdrawal reporting threshold in each fault profile and recovered. The separate approved fixture confirmed five restricted rollouts with **381.70 ms p95** from verification to protection.

The 500- and 1,000-agent profiles stopped before sending traffic when their memory projections exceeded the configured host budget. Real multi-host scale and replicated broker or database failover remain open. See the [Phase 4A handoff](docs/phase4a-distributed.md) for the raw traces, reproduction commands, and limits.

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
