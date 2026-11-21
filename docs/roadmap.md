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
| 6 | Optional provider-agnostic LLM investigator in isolated labs, no execution authority | One provider tested on two version boundaries and one missing-version case in the synthetic lab. [Phase 6 evidence](#phase-6-lab-evidence) |

The next concrete milestone is independent verification design and three isolated lab apps. Execution stays disabled until all safety gates in `docs/acceptance.md` pass.

## Phase 6 lab evidence

In two preselected synthetic advisories the investigator identified the exact package among decoys. In separate version requests it classified the introduced version as affected and the fixed version as unaffected. Each citation resolved to the correct source bytes. The independent version request used the frozen matching row in each case. Replaying the actual identity answer produced the same request bytes. [Introduced-boundary result](../benchmarks/phase6-two-stage-independent/live-h28.md) · [Fixed-boundary result](../benchmarks/phase6-two-stage-independent/live-h53.md)

The offline replay reads the four retained provider replies and checks them against their local receipts. In a disposable database each case produced one research row and a second save preserved its original contents. A fresh reader recovered the outcome and citation. The database records the local scripted appraisal. Provider attribution stays in the private receipts. [Replay from a clean checkout](studio-phase6-retained-native-history-replay.md)

A second SQLite writer held the lock while the finding was pending. The scratch writer sampled a controlled clock after it acquired the lock. At exactly seven days it saved one finding. One microsecond later it held the finding and saved zero. A separate reader confirmed both outcomes. This tests the timing of the freshness check with a real lock wait and a supplied clock. [Independent timing review](../benchmarks/phase6-scratch-admission-review/post-lock.md)

A third synthetic case isolated the version question. The model saw version `3.1` and one PyPI package row with no version information. It returned `unknown` with an empty row selection. Aegis accepted the abstention and released zero references. The backend reviewer reconciled the single HTTP 200 reply against the frozen case. A scratch replay used a scripted identity decision and the exact provider version reply and saved zero findings. [Live missing-version review](../benchmarks/phase6-two-stage-independent/live-h75.md) · [Scripted controls for unsupported claims](../benchmarks/phase6-two-stage-independent/offline-h75.md)

The offline `h84` handoff passed independent review on a synthetic advisory with two matching rows. The version request used the locally verified identity draft and carried both original rows in source order. The scripted unaffected decision required both exact source references. Incomplete, incorrect, and abstaining identity drafts produced no version request. [Independent h84 review and replay](../benchmarks/phase6-two-stage-independent/offline-h84.md)

The scripted `h84` replay saved one unaffected finding in disposable research history. Fresh readers recovered both exact source references, and an identical retry left the stored investigation byte-identical. A partial version exclusion and an incomplete identity draft each left a separate database empty. [Independent scratch history review](../benchmarks/phase6-two-stage-independent/offline-h84-scratch.md)
