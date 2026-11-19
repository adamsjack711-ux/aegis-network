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
| 6 | Optional provider-agnostic LLM investigator in isolated labs, no execution authority | Planned |

The next concrete milestone is independent verification design and three isolated lab apps. Execution stays disabled until all safety gates in `docs/acceptance.md` pass.
