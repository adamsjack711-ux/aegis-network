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

## Active ownership resolution and integration hold

Four external Codex tasks are active for native Phase 4F, AI Phase 5A, Linux CLI Phase 5B and independent validation. The integration lead delivered the schema authority map and role instructions individually to each active task. Delivery is recorded as message-tool success; direct acknowledgements and ownership reports are tracked in `AEGIS-MASTER-STATUS.md`.

The active native implementation branch is `feat/phase4f-native-enforcement` in `.worktrees/phase4f-native-enforcement`. Its owner confirmed all current native code and test files. A separate internal design agent began an overlapping watcher in `feat/phase4f-stabilization`. That agent stopped edits and preserved its uncommitted experiment and 12/24 default-on failures. The active native branch is the only 4F implementation source. Any watcher idea from the design branch requires a reviewed interface proposal and independent oracle before intake.

The active AI implementation owner confirmed authorship of every untracked file in `.worktrees/phase5a`. Its optional feed and provider code has reachable HTTPS paths and cannot be accepted under the current offline boundary. The owner is disabling those paths before committing. The research record names and fields remain provisional and require reconciliation against the frozen proposal. The active CLI implementation files in `.worktrees/phase5b` belong to the external CLI task under explicit ownership confirmation. Read-only review found unsigned `observation-v1` input being treated as finding data and omission of unknown, stale and withdrawn results. Resolve both before accepting a code commit. Preserve all drafts and report each result on its exact pin.

Integration sequence remains native 4F only after a committed implementation and D's retained pre-observation, transaction and crash oracle; then offline 5A with deterministic baseline and zero reachable network path; then 5B with signed Finding compatibility, explicit uncertainty and a non-root Linux packaging run. Run focused and full regression after each approved intake. No shared signed schema or master branch change is approved. The independent validator uses its own `test/phase-next-validation` branch and cannot fix implementation in a specialist worktree.

## Contract review queue after owner attribution

- **4F native** The active owner branch has source and test changes pending full-suite diagnosis. A separate overlapping design watcher remains preserved but will not be cherry-picked. Before intake, independently test idle T4/T5 outage before observation, same-generation return and read-only route behavior during owner transfer. Review any default-on fence timing against inherited assertions. Generation-bound ACK/cursor remains a versioned proposal, with no implementation approval.
- **5A offline** Agent 2 owns the uncommitted modules and reported a scripted 12-case baseline/model tie. The executable now rejects HTTPS source mode and provider selection. The guarded feed/provider code still contains outbound implementations. Agent 4 must confirm that the shipped path cannot invoke them, review the provisional record fields against the frozen schema, and test malicious advisory text, stale or conflicting corpus revisions and zero authority promotion. The scripted model is not a measured external model result.
- **5B observation** Agent 3's earlier draft admitted unsigned observation rows and omitted unknown/stale cases. Its active owner is revising these paths. A reviewed exact commit must prove signed Finding 1.0 compatibility, local trust, explicit unknown output, non-root Linux install and zero protected or network side effects. Six local tests on the uncommitted draft do not close those gates.

No uncommitted implementation code is eligible for sequential intake. The integration lead will review complete branch commits with Agent 4's exact-pin evidence, then create a separate integration candidate. The Phase 4E full-suite failure and five-second all-agent gate remain open throughout this queue.

## Updated cross-stream review decisions

The schema authority publication `faba7f99c546db46e7761e2d6794140c91bc3eda` remains in force. The current implementation drafts have not proposed an approved change to signed Finding 1.0, exact local inventory matching or native T4/T5. No adapter is permitted to promote a research result into a signed finding or a local protected-writer approval.

For 4F, review the target-owned idle Trust/Evidence watcher and original full-suite failures before accepting native writer changes. Test a withdrawal or trust loss before any request, competing owner generations, lost ACKs and delayed cursors on an exact committed pin. A new persisted ACK/cursor generation field requires a versioned, migration-aware contract proposal and independent denial-preservation test.

For 5A, keep the prepared pipeline local-fixture-only. The executable rejects selected live modes, but retained outbound code and direct APIs still require a source review and negative transport tests before a commit is accepted. Reconcile the current `SourceSnapshot`/`Claim`/`Asset`/`Assessment` implementation with the proposed `AdvisoryInput.v1`/`ResearchCandidate.v1`/`ResearchCheck.v1`/`ResearchReview.v1` semantics. The broad-suite exit 2 needs a trace and classification. The 12-case scripted tie does not establish model benefit.

For 5B, the signed-only Mesh adapter and incomplete-inventory unknown handling are promising uncommitted changes. Verify the signature, publisher grant, expiry, revocation and unsupported identity paths with old/new reader fixtures. Decide whether `status` without a local signed feed should return an unknown exit status. The owner must document local UUID storage, exact owned file list, non-root installation and zero network/protected-writer effects. Agent 4 must challenge the exact committed CLI pin before intake.
