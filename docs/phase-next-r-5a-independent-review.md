# Phase 5A-R independent exact-pin review

**Decision: NO-GO for integration or release at `3aa91c92f69828e4ee507b396d9230b00541dfb9`.** The source pin is `5ba957eadba340af928fa6208e528c535c9b764e`. The implementation changes only private research/evaluation files; signed Finding, Evidence, approval, Trust and writer contracts were not changed. It remains an isolated offline research candidate. This review used the pre-implementation freeze at `f419af45d0437e84702c400b1b2cc196376725a6` with the clarification at `6c7589e87bcb000f4df0cbe3959d56edea3ea3b3`.

## Reproduction and denominators

Run from this validation worktree with no external network or model:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.worktrees/phase-next-r-5a-astra/src .venv/bin/python -m pytest -q -p no:cacheprovider .worktrees/phase-next-r-5a-astra/tests/test_phase5a_source_claim.py .worktrees/phase-next-r-5a-astra/tests/test_phase5a_alpha_eval.py .worktrees/phase-next-r-5a-astra/tests/test_phase5a_intelligence.py .worktrees/phase-next-r-5a-astra/tests/test_phase5a_claim_integrity.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.worktrees/phase-next-r-5a-astra/src .venv/bin/python .worktrees/phase-next-r-5a-astra/scripts/phase5a_alpha_evaluate.py --root .worktrees/phase-next-r-5a-astra --output .worktrees/phase-next-r-val-astra/benchmarks/phase-next-r-validation/5a-r/independent-36.json --repeats 3
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python .worktrees/phase-next-r-val-astra/scripts/phase_next_r_5a_independent.py --candidate .worktrees/phase-next-r-5a-astra --pin 3aa91c92f69828e4ee507b396d9230b00541dfb9 --v-corpus .worktrees/phase-next-r-val-astra/benchmarks/phase-next-r-validation/5a-r/retained-v01-v12.json --output .worktrees/phase-next-r-val-astra/benchmarks/phase-next-r-validation/5a-r/independent-challenge.json
```

The commands above use repo-root-relative paths. The actual execution used equivalent absolute paths from the validation worktree. Candidate cleanliness and exact pin are checked in the independent harness.

| Check | Independently observed |
| --- | --- |
| Focused owner tests | 29/29 passed; no failures or skips. |
| Sealed visible corpus | Three repeats, each 36 planned, 34 evaluable, 2 Debian epoch inconclusive, 33/34 deterministic exact, 0 false affected. |
| Private atomic claims | 23 attempted, 15 emitted; 10 positive attempted, 6 positive emitted (five version, one effect). Zero independently adjudicated or real authenticated advisories. |
| Scripted points | 36 unsupported positive attempts/trial, zero emitted. This is an inert fixed response, not a model. Raw scripted decisions have 29 false affected/trial; checked decisions have zero by abstention. |
| Frozen V01–V12 on candidate parser/claim builder | 9/12 exact, zero false affected, zero claim-builder errors. V03 ecosystem collision and V10 withdrawal abstain conservatively; V11 Debian epoch is inconclusive. This is a **different parser** from the retained prior 11/12 deterministic baseline. No labels were tuned. |
| Artifact type boundary | Private claim rejected by `Evidence.model_validate` and `SignedFinding.model_validate`. No protected-writer invocation found in changed files. |
| Network/model | Focused socket-blocking test passes; no real model/provider arm run; billed tokens and USD cost unmeasured. |

## Reproduced defects at the exact source pin

1. **Version quote integrity is incomplete.** With the sealed B01 source unchanged, change only `byte_start`, `byte_end`, `source_locator` and `quote` from the version comparator to its `no code execution` phrase. `verify_atomic_claim` accepts this as a `version-applicability` claim. It checks that the quote is a byte substring but does not require the decisive span selected by `_span`. The source digest remains valid. The expected invariant is that a claim's displayed quote actually witnesses its typed predicate.
2. **Source-role and acquisition fields are not associated with the source.** Changing B01's `source_role` from `vendor` to `registry`, or `acquisition` from `sealed-local-fixture` to `pinned-inline-fixture`, is accepted by `verify_atomic_claim` with unchanged source bytes. Neither is live authentication, but private records must not misstate their fixture provenance.
3. **Impact attribution is overbroad.** An inline vendor-labeled source saying `PyPI maple-json 1.2.0 is affected. An unrelated database outage can cause availability degradation.` yields an `effect` claim for maple-json. The evaluator would report `supported_impact="availability degradation"` although the effect sentence is about the database. The expected invariant is no positive product-specific impact without product-specific source support. The current `supported_impact` field also conveys more authority than `support="fixture-parser-consistent"` and `independently_verified=false`; qualify or rename it before any downstream integration.

Exact sealed-source prefix/suffix mutation is rejected in 2/2 controls. Contradictory visible-case claims are retained as attempted only; withdrawn/stale and prompt-injection examples produce no positive emitted claim in the visible corpus. Those controls do not negate the three defects above. The hardcoded `2026-11-13` cutoff and `vendor`/`registry` role strings are synthetic fixture rules, not runtime freshness or authenticated advisory identity. An internally consistent private record is never Evidence.

## Raw provenance and limits

| Artifact | SHA-256 |
| --- | --- |
| `scripts/phase_next_r_5a_independent.py` | `02e0b82403c304fae6a49a6108a363029b2e7e14a6ad6f9a63925349a2b7d039` |
| `benchmarks/phase-next-r-validation/5a-r/retained-v01-v12.json` | `d7a728ba657920e6adffbf26004c39fccaefa16ab55053df5a399692113c2f5f` |
| `benchmarks/phase-next-r-validation/5a-r/focused-tests.txt` | `ffed804477442a0a4034f27fe1b4f647db8f48257c4a554cd292e83233257791` |
| `benchmarks/phase-next-r-validation/5a-r/independent-36.json` | `9ad62d645a9c0fb4dc9244179e5a0a2c1fb74ae77c56a537b9e7cdde6a3ed55f` |
| `benchmarks/phase-next-r-validation/5a-r/independent-challenge.json` | `75e3bb90ca62e555c0e59193d639607ba3bfce4d3a43b40704c856074736ab68` |

The V corpus is retained from independent `b81dac88c895aa074e534d7ea0feb6341b4347e6`; the original 11/12 result and all prior failures remain in the frozen manifest. The 36 cases were visible during candidate development, and the V corpus is synthetic. No independent real-advisory source authentication, semantic adjudication of all emitted facts, real-model result, measured billable cost, or full integrated regression is claimed. The private-only code may be revised and retested without changing shared signed contracts.
