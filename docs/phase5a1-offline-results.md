# Phase 5A-1 offline evaluator owner result

**Scope:** isolated private research on source pin `a937f1622d8035b64a6b5af527bd878f93612052`; original integrated baseline `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`. The independent VAL-1 freeze is `0960e6f43af83b221da47e873cc64a9fe899fca7`; proposal review is `0cf8724`. This is an owner run awaiting independent exact-pin validation. SignedFinding 1.0, Evidence, Trust, inventory matching, local approval and protected writers were not changed. No external model, API, feed, credential or network operation occurred.

## Frozen inputs and measured results

The retained V01–V12 corpus SHA-256 is `d7a728ba657920e6adffbf26004c39fccaefa16ab55053df5a399692113c2f5f`. The evaluator rejects changed corpus bytes and runs the candidate parser/claim builder for three fixed-order and three seeded-shuffled repeats (seed 501). It does not import the separate older text scorer. In **each** repeat: 12 planned/attempted, 11 eligible, one Debian epoch inconclusive, 9/12 exact on planned cases (9/11 on eligible), zero false affected, two conservative unknown mismatches. The earlier 11/12 text-parser result remains a separate historical observation.

Across the six V repeats: **72 planned/attempted, 66 eligible, six inconclusive, 54/72 exact on planned, 54/66 exact on eligible, zero false affected, 54 abstentions**. Thirty atomic source claims were attempted and emitted, all with reopened exact source bytes and private `fixture-parser-consistent` support; zero errors, zero independently semantic-adjudicated claims and zero authenticated real advisories. The inert scripted control attempted 72 positive points, emitted **zero** reportable points, and had 66 raw false-affected versus zero checked false-affected. Its checked decision was exact for 42/66 eligible cases. This is guardrail behavior, not model accuracy or superiority.

The sealed visible corpus was run separately for three trials. **Each trial:** 36 planned, 34 evaluable, two Debian epoch inconclusive, 33/34 deterministic exact and zero false affected; 23 atomic claims attempted/15 emitted, 10 positive attempted/six emitted, one fixture impact observation, zero independently semantic-adjudicated. Each scripted control attempted 36 unsupported positive points and emitted zero. These labels were visible during parser development and cannot establish blind generalization. The old F1 unsupported-positive regression and repaired quote/provenance/effect negatives are included in the focused test suite.

## Timing and resource method

This was one local macOS 27.0.1 arm64 process using Python 3.15.2. `perf_counter_ns` and `process_time_ns` measure process-local spans; no clock subtraction across hosts. V candidate baseline per-case wall p50/p95/p99 was **0.005/0.358/0.634 ms** across 72 observations; V scripted control was **0.009/0.018/0.107 ms**. V baseline CPU total was **3.664 ms** and scripted CPU **1.023 ms**. Visible 36 baseline p50/p95/p99 for the three trials was **0.123/0.787/0.881**, **0.022/0.286/0.372**, and **0.018/0.221/0.256 ms**. Whole evaluator wall/CPU was **30.0918/30.004 ms**, peak process RSS **38,567,936 bytes**. Timing includes source-byte checks in the candidate baseline; the scripted control never performs inference. Three short local trials do not characterize tail capacity.

The real-model arm is **72/72 skipped, zero attempted**: no separately approved endpoint/model, data-export boundary, credential or billing oracle. Real-model latency, token use, billed USD, source-supported accuracy and advantage are **unmeasured**, not zero. The 72 deterministic V observations and 72 inert scripted controls are not 144 real-model comparisons. There is no independent semantic adjudication or live source authentication.

## Reproduction and retained raw

From a clean checkout of source pin `a937f1622d8035b64a6b5af527bd878f93612052`:

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python -m pytest -q -p no:cacheprovider tests/intelligence_phase5a1/test_offline_eval.py tests/test_phase5a_source_claim.py tests/test_phase5a_alpha_eval.py tests/test_phase5a_claim_integrity.py tests/test_phase5a_intelligence.py
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase5a1_evaluate.py --root . --output /tmp/phase5a1-offline.json
```

Focused tests: **35 passed, zero failed, zero skipped** in 0.38 seconds. The raw run is `benchmarks/phase5a1/offline-a937f16.json` (433,329 bytes; SHA-256 `3fd9ddc617b81eaae41f3b59a73dd1ff80b5a62a119a53c2abb5d513adffdfcf`). It records individual V rows and visible 36 rows, per-case spans, source digests, exact claim fields, outcomes and all arm denominators. The benchmark refuses a dirty source worktree. A full-repository regression and independent exact-pin replay have not been run in this owner lane.

## Remaining gates

This private fixture evaluator is **GO for independent offline challenge only**. VAL-1 must replay the original unsupported-positive, altered-byte, arbitrary-quote, role/acquisition spoof and unrelated-impact negatives at the exact source pin and verify there is no authority conversion. A new sealed, independently labeled blind corpus and claim-level semantic adjudication are required before any model-benefit claim. Synthetic role labels and unkeyed digests do not authenticate a source. Debian epoch/backport handling remains inconclusive. OpenAI or any other external model remains disabled pending separate approval of exact endpoint/model, export scope, prompt/schema, rate and hard cost caps, credential custody and billing oracle.
