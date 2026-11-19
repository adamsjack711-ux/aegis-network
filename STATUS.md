# Aegis Network status

## Phase 4D T5 independent Evidence status

The 2026-11-19 T5 handoff is on `feat/phase4d-t5-evidence` in `.worktrees/phase4d-t5-evidence`, based on the Phase 4C review at `52a4dc4`. The prototype uses two independent verifier organizations and two separately enrolled status operators. The relying party verifies complete status, retains continuity and denial history, and supplies a stable Evidence binding for explicit local policy review. The isolated lab benchmark measured p95 appraisal of 3.21 ms at three records and 70.84 ms at 256 records. [Protocol and T6 instructions](docs/phase4d-t5-evidence-status.md) · [Raw measurements](benchmarks/phase4d-t5-evidence.json)

The full Phase 4C-based suite passed 157 tests and skipped the Phase 4B-only case, with the inherited Starlette/httpx deprecation warning. The combined Phase 4B and T5 focused suites passed all 54 tests. The 4C-04 fix is demonstrated at the T5 API boundary. T6 owns wiring the gate into the disposable writer and validating independently administered services, authenticated intake and recovery before promoting a release candidate.

## Phase 4C independent validation

The 2026-11-19 review is on `test/phase4c-adversarial` in `.worktrees/phase4c-adversarial`, based on `7744ebd`. All 137 tests passed, including eight new defensive checks of the integrated path. Independent HTTP and SQLite readback verified that a signed withdrawal after the canary prevented peer writes and that fixture lease expiry closed all nine routes before durable recovery. Mesh replay was in-process, and fixture HTTP was live on loopback.

Retain isolated-lab use. Integration review should prioritize independently witnessed journal completeness, authenticated cross-broker identity with durable fencing, and independently administered Evidence status. [Phase 4C report](docs/phase4c-adversarial.md) · [Threat-model proposals](threat-model.md#proposed-phase-4c-trust-boundaries)

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
