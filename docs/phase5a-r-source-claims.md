# Phase 5A-R private source-claim check

Exact implementation pin `5ba957eadba340af928fa6208e528c535c9b764e` on isolated `feat/phase5a-research-r-astra`, parent design `51607f910f35323d71e7c8abc9577442d61520e2`. VAL-R acceptance was frozen first at `f419af45d0437e84702c400b1b2cc196376725a6`. No signed Finding, Evidence, attestation, local approval, Trust, Mesh or protected-writer contract changed. No external host, model, provider, credential or network call was used.

## Private contract

`AtomicSourceClaim` is a strict `phase5a-source-claim-v1` research record. It names the source ID, exact UTF-8 byte SHA-256 and byte-span locator, original quote, fixture acquisition/role/status, asset and source product identities, asset version, version-predicate reason, affected/unaffected polarity, optional availability effect, and `independently_verified=false`. Its support label is **`fixture-parser-consistent`**. It does not claim real advisory authentication or independent semantic truth. A cross-process reader must reopen the exact sealed source bytes and call `verify_atomic_claim`; Pydantic parsing and a source ID alone are insufficient.

The check reopens validator-sealed source files or pinned inline prior-corpus text, verifies bytes and locator, checks role and freshness, reparses product/version/polarity with the conservative deterministic parser, and verifies an affirmative availability-effect phrase against the same product context. It rejects altered bytes, locator, product, source product, version predicate, polarity, stale role/status and unrelated or negated effect examples. It does not parse arbitrary prose semantics. A quote can be only the decisive version or comparator token; the surrounding digest-bound source and parser result carry the product/polarity association. This remains a **fixture parser observation**, not proof that the vulnerability claim is true.

The evaluator's private record changes from `phase5a-alpha-eval-v1` to `phase5a-alpha-eval-v2` because each row now includes separate `source_claims_attempted` and `source_claims_emitted` arrays. Contradictory source claims remain in attempted research history but yield no emitted conclusive claim. Withdrawn, stale, unverified, unconfirmed and unsupported comparator cases emit no positive claim. The inert scripted provider's raw prose remains `unchecked`; no model sentence enters either source-claim array. Existing `ResearchResult.v2` and its reader remain unchanged. No automatic old-evaluation conversion is defined; rerun the pinned corpus with this evaluator for v2 counts.

## Exact-pin offline results

Run from the assigned worktree at `5ba957e`:

```sh
PYTHONPATH=src ../../.venv/bin/pytest -q tests/test_phase5a_source_claim.py tests/test_phase5a_alpha_eval.py tests/test_phase5a_intelligence.py tests/test_phase5a_claim_integrity.py
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_alpha_evaluate.py --root . --output /tmp/phase5a-r-5ba957e.json --repeats 3
```

Three-trial raw file: [phase5a-r-5ba957e.json](../benchmarks/phase5a-r-5ba957e.json), SHA-256 `280d51f9f64b45506b1d6221525a9ddc69d037f57b6ef48af4802951e527167f`. Each trial retains all 36 planned cases and per-case verdicts, reasons, exact source locators and raw point states.

| Measure | Each of three trials |
| --- | ---: |
| Planned / evaluated / inconclusive | 36 / 34 / 2. Debian epoch `H11` and `P02` remain inconclusive; no comparator was added. |
| Deterministic exact / false affected | 33/34 / 0. `H10-withdrawn` stays conservative unknown versus unaffected label. |
| Atomic fixture claims attempted / emitted | 23 / 15. Positive attempted / emitted: 10 / 6, comprising five affected-version observations and one availability-effect observation. Contradictory observations remain attempted only. |
| Independently semantically adjudicated / real authenticated advisory claims | 0 / 0. |
| Scripted positive model points attempted / emitted | 36 / 0. All attempted remote-execution prose lacks affirmative cited-source support; raw points remain unchecked. |
| Scripted raw / checked exact | 5/34 / 24/34. Raw has 29 false affected; checked has zero false affected by abstention. |
| Real model / billed tokens / USD cost | Skipped / unmeasured / unmeasured. Synthetic byte/4 estimate is 5,369 per trial, not billable tokens. |

In-process deterministic case wall p50/p95/p99 across trials was `0.127/0.848/4.219`, `0.023/0.297/0.423` and `0.018/0.225/0.437` ms. Inert provider p50/p95/p99 was `0.009/0.019/0.040`, `0.008/0.022/0.027` and `0.008/0.016/0.031` ms. Process wall was `61.994/6.497/6.060` ms and CPU was `16.772/6.438/6.025` ms; first-trial seal reads and scheduler delay dominate the cold wall value. Peak process RSS was `36,667,392/36,798,464/36,896,768` bytes. Timing uses one-process monotonic wall and process CPU; case times include claim-byte reopens but exclude initial corpus seal verification, interpreter startup and output serialization. These observations are not a controlled performance improvement comparison.

Focused exact-pin tests: **29 passed, zero failed/skipped**. They cover digest and locator tamper, wrong asset/source product, polarity and predicate mismatch, stale/unverified source, affirmative versus negated/unrelated effect, contradiction non-emission, withdrawn/stale/no-version abstention, no network socket, bounded inert provider and no SignedFinding parsing from private research. The full repository regression was not rerun on this specialist branch; VAL-R owns the integrated gate.

The independent `V01–V12` result at `b81dac8` remains **11/12** with one conservative Debian epoch unknown, zero false affected and no model run. It is a separate hidden scorer and was not tuned or rescored here. The 36-case corpus was visible during prior parser development, so 33/34 is descriptive rather than blind generalization. No V or 36 case was removed post hoc. The exact-source checks narrow the representation of source support; a new hidden corpus and independent point-by-point semantic adjudication are still required. The model experiment remains dormant under [the design](phase5a-r-research-design.md) until separate artifact/endpoint, export-scope, budget and cost-oracle authorization.
