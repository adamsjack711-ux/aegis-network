# Phase 5A claim-integrity proposal

Design-only handoff on `feat/phase5a-claim-integrity` at `192feacf0c015c1fa37b075228b258d70e565d42`. The private Phase 5A source reviewed is `e3da3876df413f080095dc7568a664f75ffba5b6`. The independent failure and closure oracle is frozen at `2eb2ca27be986f3b55e3f85c2067ae6672d213a5` in `docs/phase-next-remediation-validation-freeze.md`. No implementation or shared contract is changed here.

## Observed failure and authority boundary

The retained `unsupported_positive_point` reproduction supplies a fixture Claim whose version scheme is `none` and whose summary says that affected versions, ecosystem and fix are unconfirmed. `assess()` returns `unknown`. A scripted provider returns `candidate_outcome=affected` and repeats “Confirmed affected 5.0-2 with remote execution.” with fact ID `F1`. `research()` accepts it because `F1` exists in the citation map. Fact-ID membership proves neither that the text is present in the source nor that its claims are supported. The independent raw run records this case as failed. Its research record has `independently_verified=false`, and the same run confirms that it cannot parse as `SignedFinding`.

`SourceRef.sha256` and `Claim.summary` are not cryptographically bound to one another in the `research()` input. A manually constructed Claim can name a digest without supplying snapshot bytes. A future positive source-support finding therefore requires a digest-checked snapshot plus deterministic normalization or separately reviewed evidence. A citation ID or model confidence cannot fill that gap.

## Private `ResearchCheck.v1` contract

This is a research-workflow record. It does not amend `Finding 1.0`, its signed canonical bytes, Evidence attestations, T4/T5 status, inventory matching or local approval.

| Field | Proposed meaning |
| --- | --- |
| `schema_version` | Literal `research-check-v1`; strict, immutable record. |
| `research_result_digest`, `source_snapshot_digests`, `checker_revision` | Bind the check to exact private inputs and checking code. A missing or mismatched snapshot digest yields `needs-evidence`. |
| `model_candidate_outcome` | Preserve raw `affected`, `unaffected`, `unknown` or `conflicting` as an untrusted hypothesis. Never substitute it for a checked outcome. |
| `deterministic_outcome` | Existing `assess()` result, with its reason codes and source references. It is an advisory computation, not independent Evidence verification. |
| `disposition` | `needs-evidence`, `rejected` or `research-consistent`. `research-consistent` only means the model's structured outcome does not contradict an independently reproduced deterministic assessment over digest-checked input. It grants no publication or writer authority. |
| `reportable_outcome` | `unknown` or `conflicting` when the baseline is such, source binding is absent, or model and checker disagree. If the baseline is supported by digest-checked structured input and model outcome agrees, it may repeat that deterministic outcome with an explicit advisory-only label. Never use model text to promote it. |
| `reason_codes` | Stable codes such as `source-binding-unavailable`, `model-exceeds-deterministic-evidence`, `model-contradicts-deterministic-evidence`, `unsupported-free-text-claim`, `source-withdrawn`, `source-stale` and `source-conflict`. |
| `point_support[]` | One entry for each `points`, `ambiguities`, `prerequisites` and `local_explanation` item, indexed by field and position. Values `unchecked`, `structured-source-supported` or `contradicted`, with exact source digest and pointer when support is established. |

Initial implementation should mark **all model-generated prose `unchecked`**, including prose accompanying a deterministic `affected` outcome. Display it only as quoted, unverified research hypothesis. A present fact ID is a locator, not a support decision. In particular, an affected-version match cannot certify a sentence's impact, exploitability, fix or mitigation claim. A separately generated, exact structured source fact may be labeled `structured-source-supported` when its immutable snapshot bytes, digest, pointer, product, version and factual wording are checked. This permits the frozen oracle's healthy signed-source informational control without crediting the model's prose. A later model-text support state needs a defined atomic claim grammar and a checker that compares each claim with digest-checked source text; free-form semantic similarity is insufficient. `ResearchCheck.v1` must have no signature, approval, mitigation, action, publish or writer field. No automatic adapter may turn it into a signed finding or verifier attestation.

For the original case, the expected check is `deterministic_outcome=unknown`, `model_candidate_outcome=affected`, `disposition=needs-evidence`, `reportable_outcome=unknown`, reason `model-exceeds-deterministic-evidence`, and all repeated prose `unchecked`. The raw candidate can remain retained for audit and reviewer analysis. A presentation or export path must never emit the fabricated sentence as a confirmed fact.

## Frozen negative-test request

The independent validator owns the oracle and raw results, frozen at `2eb2ca2`. Each case should assert both the private disposition and absence of `SignedFinding`, attestation, Mesh publication, local approval and protected-write side effects. The seven original scripted security cases and their retained JSON SHA-256 `87fbe112ed212e6dfeb0c5421cc5ee7e7f7fc3f17ad86bb1467007957a734133` remain unchanged.

1. Retain the exact `unsupported_positive_point` fixture and wording. Require the disposition above. Preserve its original failing raw result unchanged.
2. Provide a digest-checked structured source that deterministically matches an affected version, then script a matching `affected` candidate with an invented “remote execution” impact. The outcome may repeat the deterministic version result as advisory, while the impact sentence stays `unchecked` and is never rendered as source fact.
3. Script a matching `unaffected` candidate with invented fixed-version or safety prose. Mark that prose `unchecked`; do not infer immunity from the model.
4. Script `affected` on a withdrawn, stale, future-dated or contradictory source, and on an unsupported version comparator. Require `needs-evidence`, no positive reportable outcome and stable reason codes.
5. Give a valid fact ID but a source pointer or digest that cannot be verified against supplied immutable bytes. Require `source-binding-unavailable`; citation membership alone cannot satisfy support.
6. Retain existing unknown-fact-ID, executable-instruction, invalid schema, over-budget and offline-network rejections. Add duplicate fact IDs or rewritten source bytes, provider timeout and extra output fields as negative controls.
7. Include exact structured positive and negative controls so the guard does not erase reproducible deterministic assessments. Record case denominators and all inconclusive results.

Scripted provider fixtures test guardrails, not model accuracy. The current `e3da387` research API receives `Claim` objects without the snapshot bytes needed for positive source binding; tests should therefore avoid claiming independently verified semantic support from that API. The original fixture's source digest is not checked against its manually constructed summary. The frozen closure oracle also requires a fresh separately labeled holdout, zero unsupported positive claims among **all emitted positive points**, and explicit denominators for attempted points, emitted points, adjudicated support and abstentions. Reuse the pinned 12-case holdout; preserve the Debian epoch case as inconclusive until an independently reviewed comparator exists. Record per-case decisions, latency, CPU and model cost; absent real model and billing data remain skipped.

## Reconciliation and file ownership

1. Review the independent validator's frozen `2eb2ca2` oracle, source pin, labels and negative controls. Preserve the original failure script and raw JSON.
2. Review the Phase 5A private source against that oracle. Port only the needed private intelligence files from `e3da387` into this isolated branch after the freeze. Do not cherry-pick unrelated tests or shared-contract changes.
3. Add the private check boundary and presentation labels in `src/aegis/intelligence/` and focused Phase 5A tests. Keep `SignedFinding 1.0`, `src/aegis/artifact.py`, native trust, Mesh and writer code untouched.
4. Run focused and independent negative tests, plus the offline corpus evaluation on the exact candidate commit. Record raw counts, false positive and inconclusive denominators, latency and resource cost. Ask integration lead to review before any reconciliation with other branches.

Agent 2 owns this branch's proposal, future private `src/aegis/intelligence/{research,models}.py` changes and focused Phase 5A tests. Agent 4 owns the independent oracle and its separate worktree. The integration lead owns shared schema decisions and cross-stream adapters. The previous `feat/phase5a-intelligence` commit remains intact. No network or model provider is enrolled.

## Private result version and reader behavior

The original `phase5a-research-v1` record at `e3da387` exposed raw model `candidate_outcome`, `points`, `ambiguities`, `prerequisites` and `local_explanation` at the top level. The remediation emits `phase5a-research-v2`: top-level `candidate_outcome` is the checked research appraisal, while raw provider outcome and prose are segregated as `model_candidate_outcome` and `raw_hypothesis`; `check` carries the private `research-check-v1` disposition. Its generated points have `support=unchecked` and are absent from top-level reportable fields. This is a breaking **private** research-record change, with no change to SignedFinding 1.0 or any shared signed bytes.

Readers must require the explicit literal `phase5a-research-v2` and parse the strict v2 schema before using `candidate_outcome` or `check`. A v1 record, a versionless record or a v1-style record with top-level points must fail v2 parsing. There is no automatic v1-to-v2 conversion: preserve v1 as raw historical research and, where immutable snapshot bytes still exist, rerun deterministic normalization and checking into a new v2 record. If source bytes are unavailable, the new check stays `needs-evidence` with reportable `unknown`. The focused test exercises valid v2 and all three rejection shapes.

The v2 reader also requires a non-null `check`, equality among its reportable outcome and the top-level `candidate_outcome`, equality among its raw outcome, `model_candidate_outcome` and `raw_hypothesis.candidate_outcome`, and equality among its deterministic outcome and `baseline_outcome`. It rebuilds point-support positions and fact IDs from the raw hypothesis and verifies a canonical SHA-256 over all serialized v2 fields except `check.research_result_digest` itself. Changed raw prose, check metadata, source-digest references or reportable outcome therefore fail parsing unless the entire private record is rewritten. This is an **unkeyed integrity check**, not a signature, source authentication, independent verification or defense authority. A reader without the snapshot bytes cannot establish the truth of the serialized `source_binding` assertion and must not use this record to authorize a finding or protected write.
