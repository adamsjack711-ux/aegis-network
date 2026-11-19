# Aegis Network status

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
