# Phase 5A-R repaired exact-pin independent review

**Scope decision: GO for isolated private offline research inclusion at clean `feat/phase5a-research-r-astra` `ebcc30c9cfcee54c3e103b6fb8cfafb8b5d4e762` (source commit `d100adf3ceeac61edff366fb9eed9f27d720d9b7`); NO-GO for released AI intelligence or any authority-bearing use.** The original failing pin `3aa91c9` and [raw negative report](phase-next-r-5a-independent-review.md) remain untouched. This independent replay used the same committed harness `scripts/phase_next_r_5a_independent.py`, frozen V01–V12 corpus and sealed 36-case inputs; no labels or assertions were changed.

## Exact results

| Oracle | Repaired pin observation |
| --- | --- |
| Four owner focused files | **30/30** pass, zero fail/skip. |
| Original arbitrary version quote | Rejected: B01 claim span changed to same-source `no code execution` fails `verify_atomic_claim`. |
| Original provenance spoof | `source_role` vendor→registry and `acquisition` sealed→inline both rejected. |
| Original unrelated impact | `An unrelated database outage can cause availability degradation` fails effect claim construction. |
| Source byte mutation controls | Prefix and suffix tamper both rejected (2/2). |
| Artifact boundary | Private claim rejected by `Evidence.model_validate` and `SignedFinding.model_validate`; changed source has no writer, approval or network path. |
| Sealed visible corpus | Three trials, each 36 planned, 34 evaluable, 2 epoch inconclusive, 33/34 deterministic exact, 0 false affected. 23 atomic claims attempted, 15 emitted; 10 positive attempted, 6 positive emitted. Authenticated real advisory and independent semantic adjudication both **0**. |
| Scripted control | 36 unsupported positive points attempted/trial, 0 reportable emissions. Fixed inert response only; no real model or billable cost. |
| Frozen V01–V12 on this candidate parser | 9/12 exact, 0 false affected, V03 and V10 conservative unknown, V11 Debian epoch inconclusive. This is distinct from the retained 11/12 **different-parser** baseline. |

The private evaluator row key changed from `supported_impact` to `fixture_impact_observation`, and its top-level schema changed from `phase5a-alpha-eval-v2` to `phase5a-alpha-eval-v3`. This correctly narrows the field's asserted authority. The strict `AtomicSourceClaim.v1` verifier now recomputes its decisive quote span and checks fixture role/acquisition association. `ResearchResult.v2`, signed Finding/Evidence and approval/writer contracts are unchanged. No production reader of this private evaluator was found; old v2 evaluation records must be rerun from sealed bytes rather than silently upgraded. The older `docs/phase5a-r-source-claims.md` still describes v2 as historical context; the repair document names v3. Integration documentation should link the v3 repair as current.

The effect grammar remains a deliberately narrow fixture parser. It accepts an explicitly named matching product or the fixed `a crafted document/request/input/packet` phrase in the same context; semantic truth and real source authentication remain unproved. Source role strings and the hardcoded fixture freshness cutoff are **not** live identity or current advisory status. A recomputed unkeyed digest is not independent source authentication. These limitations block release/authority claims even though the three retained defects are fixed.

## Raw and method

Commands are identical to the original review, substituting `--pin ebcc30c9cfcee54c3e103b6fb8cfafb8b5d4e762` and output paths under `repair-ebcc30c/`. Focused tests used `PYTHONDONTWRITEBYTECODE=1`, candidate `PYTHONPATH=src` and `.venv/bin/python -m pytest -q -p no:cacheprovider` over `test_phase5a_source_claim.py`, `test_phase5a_alpha_eval.py`, `test_phase5a_intelligence.py`, `test_phase5a_claim_integrity.py`. The evaluator ran three repeats, one process, monotonic wall and process CPU. The V adapter invokes the exact candidate `_source_decision` and `build_atomic_claim` without label tuning. No external network, provider, model or real credential was used.

| Raw under `benchmarks/phase-next-r-validation/5a-r/repair-ebcc30c/` | SHA-256 |
| --- | --- |
| `focused-tests.txt` | `28e402e5d8633193a2c7837f8d7263664ac142684d7d52873d5f01b31cfb674c` |
| `independent-36.json` | `6102e458b44339bd686b6527f88be546e5b68171ee5dc84e1cd433dc569e7606` |
| `independent-challenge.json` | `5337a21a373d6f9f32be1d7db55ed0c93ee7c217d8ccde70438861490d3f2542` |

No integrated full regression, real source enrollment, point-by-point independent semantic assessment, real-model runs, billed tokens, GPU/CPU comparison or model cost oracle was completed here. Release and model-advantage claims remain **NO-GO**.
