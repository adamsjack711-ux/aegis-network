# Roadmap and milestone checklist

| Phase | Milestone | State |
| --- | --- | --- |
| 0 | Investigate OSS-CRS, Buttercup, GUAC, OSV, CycloneDX/VEX, in-toto, TUF; decide reuse boundaries | Documented |
| 1 | Architecture, threat model, ADRs, contracts, acceptance plan | Documented |
| 2a | Signed finding → validation → durable event → local match → audited dry run | Implemented |
| 2A mesh reliability | Independent durable fan-out, outbox recovery, role-pinned trust, signed revocation, fault injection | Implemented locally on `feat/mesh-reliability`; integration review pending |
| 2b | Multi-publisher trust rotation, artifact schema evolution, audit replication | Planned |
| 3 | Three intentionally vulnerable, isolated lab apps and reversible templates | Planned |
| 4 | Independent verifier workers, container integration, failure injection, health checks, rollback | Planned |
| 5 | 10/100/1,000 deployment benchmark with p50/p95/p99, coverage, false positives, safety failures, cost | Planned |
| 6 | Optional provider-agnostic LLM investigator in isolated labs, no execution authority | Two-stage investigator tested with one provider on two synthetic boundary cases. [Phase 6 evidence](#phase-6-lab-evidence) |

The next concrete milestone is independent verification design and three isolated lab apps. Execution stays disabled until all safety gates in `docs/acceptance.md` pass.

## Phase 6 lab evidence

In two preselected synthetic advisories the investigator identified the exact package among decoys. In separate version requests it classified the introduced version as affected and the fixed version as unaffected. Each citation resolved to the correct source bytes. The independent version request used the frozen matching row in each case. Replaying the actual identity answer produced the same request bytes. [Introduced-boundary result](../benchmarks/phase6-two-stage-independent/live-h28.md) · [Fixed-boundary result](../benchmarks/phase6-two-stage-independent/live-h53.md)

The offline replay reads the four retained provider replies and checks them against their local receipts. In a disposable database each case produced one research row and a second save preserved its original contents. A fresh reader recovered the outcome and citation. The database records the local scripted appraisal. Provider attribution stays in the private receipts. [Replay from a clean checkout](studio-phase6-retained-native-history-replay.md)

The scratch writer rechecked revision and freshness under a SQLite write lock. The expiry test supplied a simulated commit time. The next timing check is to sample the clock after a real lock wait and verify both a fresh and an expired finding. [History controls and timing assumptions](../benchmarks/phase6-scratch-admission-review/README.md)
