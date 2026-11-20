# Phase 4F, 5A and 5B integration plan

## Baseline and worktrees

The common clean parent is Phase 4E `ee739cacfaa3f81a0994b4d7802fd2943c067d86`. No later Phase 4E integration commit was present at review. The separate D validation tip is `39a17e4bb162485f3a3bb747d52b597bf431b788`, with its reviewed evidence already imported into Phase 4E. The original master checkout is dirty at `14440ee226c58aa6e8e06517ab1601b2d672798c` and remains untouched. Four specialist branches and this preparation branch started exactly at the parent. The specialist design commits are Agent 1 `ae83b16ad9159d96e80553b335eef3bfa218fd47`, Agent 2 `086a1df2764bd496a811cff584861bd02570df24`, Agent 3 `553587615de8319e742a70f28926b4150f8c5094`, and Agent 4 independent validation `e41770868f8c614a73764a8d9a73917b76ef2d91`. Their source-code contracts have not been integrated.

| Assignment | Branch and worktree | Owned files and limits |
| --- | --- | --- |
| Agent 1, native enforcement | `feat/phase4f-stabilization`, `.worktrees/phase4f` | Native target, ownership, critical delivery and related Phase 4F tests and raw fixtures. Changes to `src/aegis/mitigation`, `phase3c.py`, `agent_runtime.py`, broker/identity code require an interface proposal first. No C shadow promotion. |
| Agent 2, AI intelligence | `feat/phase5a-intelligence`, `.worktrees/phase5a` | New `src/aegis/intelligence/`, `tests/intelligence/`, local advisory corpus and Phase 5A raw results. Existing Evidence, signed finding and native authorization code are read-only review inputs. |
| Agent 3, Linux CLI | `feat/phase5b-linux-cli`, `.worktrees/phase5b` | New observation CLI and its package inventory adapters, tests, fixtures and packaging proposal. Existing writer, Mesh, Evidence and trust roots remain outside its implementation ownership. |
| Agent 4, independent validation | `test/phase4f-phase5a-validation`, `.worktrees/phase4f-phase5a-validation` | Frozen adversarial and baseline oracles, exact-pin test drivers, raw results and independent review. No implementation fixes on specialist branches. Challenges all three streams, with priority on 4F safety and 5A model independence. |
| Integration lead | `docs/phase4f-phase5a-preparation`, `.worktrees/phase4f-phase5a-preparation` | Contract freeze, ADRs, cross-component review, risk ledger and eventual isolated integration candidate. Does not rewrite specialist-owned components. |

## Interface freeze and review order

The phase-specific proposed records are in [4F](phase4f-architecture.md), [5A](phase5a-architecture.md), and [5B](phase5b-cli-contract.md). The exact existing and proposed schema authority map is [Phase 5 schema authority](phase5-schema-authority.md). Existing signed Finding 1.0 and Revocation 1.0/1.1, T4/T5, Rapid plan, approval, event ID, journal, audit and target contracts retain their Phase 4E bytes and default behavior. New records live in separate namespaces until field-level review. Any proposal changing a shared wire, database, trust grant, denial order, key domain, CLI output or package identity must include exact old/new examples, versioning, old/new reader behavior, migrations and rollback, threat analysis, golden vectors and D's negative tests. The integration lead records approval before any merge or native wiring.

Order the dependencies as follows. First, freeze oracles and reproduce all predecessor failures. Second, review 4F native target and ACK/cursor protocol separately, with a cross-component regression after each approved intake. In parallel, 5A can build a deterministic read-only baseline and 5B can design offline inventory and output behind separate namespaces. Third, validate 5A candidate provenance and 5B exposure matching against shared fixtures. Fourth, D challenges exact pins for all streams. Finally, create a new isolated integration worktree only after branch handoffs have exact commits, raw evidence and contract decisions. Preserve feature branches and master. No automatic merge.

## Acceptance and release decisions

Phase 4F must meet every criterion in its architecture, pass the complete exact-pin suite with zero failures and an independent fault matrix, and retain earlier failures. The five-second all-agent gate stays open until measured with a declared denominator and healthy/fault repetitions. Physical multi-host tests and independent custody need authorized host enrollment and credential references before any external activity. A passing local test cannot release distributed enforcement.

Phase 5A must pass its fixed deterministic baseline, source and schema validation and independent prompt-injection or malformed-output challenges. A model provider remains optional. Its output may enter human review and existing independent verification but has no native write authority.

Phase 5B must pass offline, unprivileged container packaging and deterministic observation controls. Its release label is observation-only. Phase 5A research candidates can be displayed with their uncertainty but cannot be treated as signed Evidence or protected approval. The CLI is not a production integration under this preparatory contract.

Independent D reviews shared contracts and source diff before running a branch. D archives results for every case with exact source and harness commit, environment and retained original failure. Record GO only for the tested capability. Any missing authority proof, missed denial deadline or unobserved protected route is NO-GO for distributed write authority.

## Unresolved research

- Can a target persist a restrictive hold before independent observation when its owner home and broker fail simultaneously, without opening a vulnerable route during a partial rollback?
- Which durable generation-bound broker ACK and replay floor protocol survives old in-flight results, duplicated sessions and restored snapshots without changing Phase 2 logical decision identity?
- What trusted cut and bounded freshness window can be enforced at the native transaction when withdrawal intake occurs after the last remote witness sample?
- Did the 4E broad-suite failure come from Trust fixture process readiness, temporary resource pressure, or the ten-second retirement fixture starting before the test's first admission? The retained traces do not establish a cause.
- Which advisory authorities, licenses, correction feeds and package ecosystem comparators can support a reproducible 5A corpus without external access in this phase?
- Which Linux distributions and package databases can a non-root CLI read consistently, and how should partial inventory affect an exposure observation?

[Phase 4E acceptance and failures](phase4e-integration-plan.md) · [Current risks](phase4e-risk-register.md)

## Preparatory interface review

Agent 1's native proposal matches the frozen 4F authority ordering. Its requested generation token would change persistent consumer state and therefore needs a versioned, migration-aware review before implementation. Agent 2's proposed `ResearchCandidate.v1` is private research data. It must stay separate from signed Finding and Evidence messages, and from the Phase 5B observed exposure record. Agent 3's `ExposureObservation/v1` has its own package and result fields. A conversion from an AI candidate into a CLI observation needs exact source revision, package identity, comparator and uncertainty mapping reviewed by both owners and Agent 4. The CLI cannot interpret a research confidence value as verifier confidence.

During review, untracked `src/aegis/intelligence/{__init__,feeds,models,baseline}.py` appeared in Agent 2's worktree after the clean branch had been created. Agent 2 did not create or commit them. They are preserved in place and are excluded from the design commit. The unreviewed `FeedClient` has network-fetch capability for public advisory endpoints, while this preparation allows local fixture inputs only. Ownership, source provenance and network policy must be resolved before adopting or running that code. No external host or credential was used by this preparation.

Agent 4 froze independent F01–F05, A01–A04 and L01–L04 challenge criteria before implementation. Independent validation plan at `.worktrees/phase4f-phase5a-validation/docs/phase-next-independent-validation.md`

Agent 3's signed-Mesh adapter correction is `443a2c4779948b5be24342c9c3bdad9eea6b5d54`. Uncommitted CLI and packaging files appeared concurrently in the Phase 5B worktree. They are preserved and excluded from integration until ownership and interface review. [Schema authority](phase5-schema-authority.md)
