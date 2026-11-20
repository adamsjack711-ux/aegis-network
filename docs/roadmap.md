# Aegis roadmap and Studio handoff

## Resume here · 20 November 2026

Start development from `integration/cli-offline-handoff-reviewed` at `9ba94a84fd54ea9052d09e0c73bb6c365cbd5d5d`. This roadmap branch adds documentation to that commit. The private branch `backup/private-tester-9ba94a8` holds the tester archives, walkthroughs and final review evidence under `private-tester-bundles/` and `private-validation/`. Both branches are in the private GitHub repository and in the iCloud Git bundle.

**Completed.** The observation-only CLI passed the four frozen arm64 Linux venv configurations under read-only grant custody. Source regression recorded 463 passes, five passing subtests, 37 skips and one historical grant-file race xfail. The offline Scout → Investigator handoff passed both withdrawal orderings, replay and restart for fresh readers of one trusted SQLite file. The combined wheel passed its own installation matrix after adding the handoff module.

| Artifact | SHA-256 |
| --- | --- |
| Combined tester archive `aegis-tester-9ba94a8.tar.gz` | `6dc743be96c18a3fbb3e2deeec02765418e2c2709dbef85ee97d86d2fc9e9694` |
| Installed wheel in that archive | `4afa7a6669b5f4b719be75bc53367cd4a52877ee59b831b056fb4a61072665b8` |

## Proposed next phases

| Order | Work | Evidence for the next decision |
| --- | --- | --- |
| 1. Studio tester handoff | Verify the archive digest on arrival. Follow its guide in one supported arm64 Linux guest on the Studio, using the reviewed offline dependencies and read-only grants. | Save the environment, install and uninstall results, expected status exit 2 for unknown evidence, and installed handoff import. Record any tester friction. |
| 2. CLI grant custody | Review the [custody proposal](alpha-grant-custody-policy-v2-proposal.md) and the historical xfail. Define the trusted administrator, who may change the grant list, and how the client detects replacement or rollback before considering broader layouts. | Review the threat model independently. Demonstrate the chosen custody guarantees under the proposed layout and repeat affected installed checks before broadening the alpha. |
| 3. Offline research quality | Evaluate the combined Scout and Investigator on held-out, independently adjudicated advisories. Include ambiguous, unaffected, withdrawn and superseded cases. | Freeze expected outcomes and scoring before evaluation. Report unsupported affected claims, missed matches, abstentions and evidence attribution. Real-model evaluation is a separate decision. |
| 4. Recovery research | Review the obligation, audit anchor, target, owner generation and cursor contracts in the [recovery decision](phase4f-recovery-decision.md). Retained denial was about 30.6 seconds against five seconds. | Obtain written contract review before implementation. Assess agent-owned denial against the frozen 72 fault pairs and 18 healthy controls. Record target-side holds separately. Distributed enforcement remains NO-GO. |
| 5. Diagnostic Runner research | Resolve operator consent and containment questions against the [runner contracts](phase5c-integration-contracts.md). | Independent review of consent, containment and trace coverage precedes consideration of the frozen 72 safety and two sets of 30 performance trials. Runner preview remains NO-GO. |

**First assignment for the Studio agent.** Complete phase 1 and return the full candidate commit, archive and wheel digests, guest OS and Python version, walkthrough evidence and a PASS or BLOCKED decision. Use a separate worktree for follow-up changes. Publication and merging to master remain owner decisions.

## Original milestone checklist (historical)

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
