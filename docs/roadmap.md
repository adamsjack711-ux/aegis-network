# Roadmap and milestone checklist

| Phase | Milestone | State |
| --- | --- | --- |
| 0 | Investigate OSS-CRS, Buttercup, GUAC, OSV, CycloneDX/VEX, in-toto, TUF; decide reuse boundaries | Documented |
| 1 | Architecture, threat model, ADRs, contracts, acceptance plan | Documented |
| 2a | Signed finding → validation → durable event → local match → audited dry run | Implemented; eight local tests and one live Compose smoke path passed |
| 2b | Multi-publisher trust rotation, revocation, artifact schema evolution, audit replication | Planned |
| 3 | Three intentionally vulnerable, isolated lab apps and reversible templates | Planned |
| 4 | Independent verifier workers, container integration, failure injection, health checks, rollback | Planned |
| 5 | 10/100/1,000 deployment benchmark with p50/p95/p99, coverage, false positives, safety failures, cost | Planned |
| 6 | Optional provider-agnostic LLM investigator in isolated labs, no execution authority | Planned |

The next concrete milestone is revocation and independent verification design, followed by failure injection and three isolated lab apps. Execution stays disabled until all safety gates in `docs/acceptance.md` pass.
