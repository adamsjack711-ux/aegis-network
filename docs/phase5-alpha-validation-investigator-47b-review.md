# Independent exact-pin Investigator offline revision review

**Owner pin:** `feat/phase5a-investigator-offline-astra` at `47b2f5f1c57a98706bd505f7bad1daee0fb6a0d4`, clean direct child of held live-capable `97265de36a67de4a7ae6f374fb8cd64362fcb6fe`. **Review baseline:** `8292e531194216a578c32c912d066f98cdbce9ea`; frozen validator plan `f5da1814162c821e0491b7591837b6623113294a`. This verdict examines the **cumulative final tree** from `8292`, not only the revision diff. No owner files were edited and no network/model call was made.

## Decision

**Conditional GO for a single squashed offline-only research-source intake of the exact final files; NO-GO for the historical `97265de` intermediate source, Scout bridge, real inference and release.** The cumulative tree adds only `src/aegis/intelligence/investigator.py` and `investigator_eval.py`, private tests, offline evaluation script/raw, and docs. The revised source imports no `httpx`, `requests`, `urllib`, `socket`, `os` environment or other transport; `OpenAIProvider.complete()` unconditionally raises `PermissionError` before payload or environment access. `investigate()` admits only exact `type(provider) is ScriptedProvider`, and rejects any `authorization`, `ledger` or `corpus_sha256` parameter before reading the advisory. A custom provider claiming `live=False` cannot enter. A direct reproduction with caller-created Authorization and a throwaway environment key raised `PermissionError` with **zero socket connect attempts**. The original callable live adapter must never appear as an intermediate integrated commit.

The immutable authority sources (`SignedFinding 1.0`, exact local observer/InventoryItem, Trust/T4/T5, mitigation store and existing adapter) have no cumulative diff. `git diff --check` passed. `ResearchCandidate.independently_verified` stays false, exact-byte quotes are citation checks only, and no signed Finding, Evidence or protected-writer adapter is present. The 12 author-visible offline cases report 12/12 deterministic and 12/12 scripted outcomes, zero false affected, 12 exact-byte citations; `unsupported_semantic_claims` is null. They do **not** establish independent semantic support or model advantage.

**Documentation condition:** `docs/phase5a-investigator-handoff.md` remains the original `97265de` document and states that a dormant HTTP/OpenAI adapter exists. That is false for the revised final source. Intake should either omit that historical handoff or amend it to prominently say it is superseded by `docs/phase5a-investigator-offline-revision.md`; do not publish the old claim as current behavior. This is a documentation conflict, not evidence of live transport in the final source.

## Proposed Scout adapter

`docs/phase5a-scout-investigator-adapter-v1.md` is **GO as a private design proposal for review only; HOLD implementation and contract adoption**. It explicitly identifies `scout-advisory-input-v1` versus `advisory-input-v1`, pins original bytes and digest, holds withdrawn/conflicted/stale revisions, preserves unverified provenance and unknown applicability, requires a caller-supplied local Asset, omits Scout priority from applicability, and forbids Finding/Evidence/writer promotion. It specifies tamper, alias, stale-cursor, withdrawal-after-cache and no-authority negative cases. No adapter code or cross-lane test exists. A future versioned adapter needs independent golden old/new reader tests and a freshness/denial review before adoption.

## Independent tests and raw evidence

| Check | Planned/attempted | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: | ---: |
| Owner-named `tests/test_phase5a*.py` on exact pin | 41/41 | 41 | 0 | 0 |
| Broader Phase 5A plus `tests/intelligence_phase5a1` | 46/46 | 46 | 0 | 0 |
| Direct historical live-provider bypass reproduction | 1/1 | 1 denied, 0 socket connects | 0 | 0 |
| Frozen independent 24+12 semantic cases | 0 new adjudications | 0 | 0 | all |
| Frozen conditional real-model experiment | 0/72 model attempts | 0 | 0 | 72; no authorization/cost oracle |
| Full repository suite on final integrated candidate | not yet staged | 0 | 0 | pending integration |

Raw outputs: `benchmarks/phase5-alpha-validation/investigator-47b-focused.txt` SHA-256 `a4bce7c4db793ea29a6b29694be0195cafd5bd81fe306d4c0f706a26485baff3`; `investigator-47b-relevant.txt` `101d994eaa27ee393bb21dddd7cebf9f8a4db2fb16a74b67d733c435587875c5`; `investigator-47b-bypass.txt` `865dbb7634311216dcee8252a6629162fa5af867070d62ff01ec79b4823385c0`.

Retain the independent HOLD on original `97265de` and its reproduction. This source-intake decision does not authorize a model endpoint, advisory feed, signing, independent Evidence, local approval or distributed enforcement. CLI alpha, AI model claims, Diagnostic Runner preview and distributed enforcement remain **NO-GO**.
