# Phase 5A-C offline advisory evaluation

Implementation source pin `c6bceb624be1f071b5b728afa8de53ad43611dfa` on isolated `feat/phase5a-eval-astra`, based on integrated parent `3bfd2abea430bc8036105ce85adfdc78706d367d`. This branch has not been integrated into master. The new 24-case corpus is copied byte-for-byte from independent validator seal `8a08e47294ff667fca5c3919519d1f3ccfb10c92`; its manifest SHA-256 is `20a3a37da8f941f17e6db514d1437d8d6575140e2e3bde61fc2cad9c6d4a234b`. The prior 12-case holdout remains at SHA-256 `d21b931c2e5822d40145b709e72ed83fb7dc14a25217b8600deebbcf0ca1c8ac`. Raw three-trial results are [phase5a-alpha-c6bceb6.json](../benchmarks/phase5a-alpha-c6bceb6.json), SHA-256 `e5d73df90b08b3f22e8b956a9e7b82872dd1bdcfe194f37818c2dc65f535e6ef`.

## Boundary and method

The sealed 24-case set contains synthetic text advisories and 27 raw UTF-8 source files. The existing Phase 5A normalizer only accepts structured JSON OSV, NVD, KEV and GHSA. This evaluator reads the text bytes and verifies the seal rather than inventing normalized JSON or asserting a `ResearchResult.v2` source binding. No text record becomes `SignedFinding`, Evidence, attestation, local approval or a protected action. Phase 5A's strict v2 reader and claim-integrity code are unchanged.

The conservative deterministic parser recognizes explicit product identity, numeric version predicates and limited exact version sentences. It returns `unknown` on missing identity, unconfirmed or withdrawn notices, stale snapshots, contradictions and unsupported version syntax. Debian epochs are marked inconclusive. The same case asset and source records go to an inert local scripted provider that always proposes `affected` with an invented remote-execution point. Its point carries cited source IDs and `support=unchecked`; a phrase-absence check records it as unsupported. The checked scripted outcome only agrees with a completed deterministic affected assessment; other raw positives abstain. This stress response tests the safety boundary and is **not model inference or evidence of model quality**.

`OfflineBudget` limits input and output bytes, approximate output tokens, an observed deadline and one concurrent call. The only executable adapter is `ScriptedStressProvider`, which imports no transport. A blocking arbitrary provider cannot be safely preempted by the post-return deadline check; that interface is not enrolled. No external fetch, model runtime, token or credential was used. A future provider requires separate authorization, an out-of-process hard deadline and source/claim review before evaluation.

Run from this exact source pin with the repository's local virtual environment:

```sh
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_alpha_evaluate.py --root . --output /tmp/phase5a-alpha-c6bceb6.json --repeats 3
PYTHONPATH=src ../../.venv/bin/pytest -q tests/test_phase5a_alpha_eval.py tests/test_phase5a_intelligence.py tests/test_phase5a_claim_integrity.py
```

All clocks used for case timing are monotonic within one process: `perf_counter_ns` for wall and `process_time_ns` for CPU. Case latency excludes sealed-corpus file validation and interpreter startup; run wall time includes seal validation. Peak RSS is a process high-water mark, not per-case memory. Quantiles interpolate over 36 case timings in each trial and are descriptive at this sample size. The three trials ran sequentially in one process, so the first was colder than later trials.

## Results and denominators

| Measure | Observed in each of three trials |
| --- | --- |
| Planned / completed / inconclusive | 36 / 34 / 2. `H11-epoch-boundary` and `P02-debian-epoch-fixed` require an independently reviewed Debian comparator. |
| Deterministic exact labels | 33/34 completed. One conservative disagreement: withdrawn `H10-withdrawn` returned `unknown` against the validator's `unaffected` label. |
| Deterministic affected classification | 5 true positive / 5 affected completed, 0 false positive. Precision and recall are 1.0 on these small fixture denominators only. |
| Raw scripted hypothesis | 5/34 exact, 29 false affected outcomes. This is the deliberately incorrect fixed stress response. |
| Checked scripted decision | 24/34 exact, 0 false affected outcomes. Nine deterministic unaffected results became unknown because the raw scripted answer contradicted them. |
| Scripted point attempts | 36 positive points attempted; all 36 lack an affirmative cited-source remote-execution phrase; 0 points emitted as supported. Human semantic entailment was not adjudicated. |
| Real model / billable cost | Skipped. Synthetic byte/4 token estimate was 5,369 per trial; actual provider tokens and USD cost are unmeasured. |
| Per-case deterministic wall p50 / p95 / p99 | Trials: `0.008 / 0.232 / 0.461`, `0.008 / 0.028 / 0.035`, `0.005 / 0.019 / 0.027` ms. |
| Per-case inert provider wall p50 / p95 / p99 | Trials: `0.008 / 0.014 / 0.021`, `0.007 / 0.013 / 0.020`, `0.007 / 0.009 / 0.010` ms. |
| Process wall / CPU / peak RSS | Wall: `8.065 / 3.680 / 3.228` ms; CPU: `8.041 / 3.660 / 3.225` ms; RSS: `36,569,088 / 36,618,240 / 36,683,776` bytes. These exclude interpreter startup and output-file writing. |

These labels were sealed independently before implementation but became visible during parser development. The parser was adjusted after inspecting them. Its 33/34 score is therefore **development-informed descriptive evidence**, not a blind generalization estimate. A fresh hidden holdout is needed for that claim. The fixture roles labeled vendor or registry are not real-world authentication. Phrase absence can reject this fabricated impact, while phrase presence would still require human or independent semantic entailment review. The supported availability phrase in `B01-inclusive-lower` is a narrow text observation and does not certify a vulnerability or mitigation. The private v2 record's unkeyed digest remains informational and cannot authenticate source truth across processes.

## Tests, incomplete gates and external branch review

Focused command above: **24 passed, 0 failed, 0 skipped**. Tests cover sealed source mutation, 36-case denominator, conflict and stale/withdrawn behavior, prompt-injection text as data, unsupported impact, no network socket creation, provider byte limits, deterministic-only mode and no SignedFinding parsing from a research row.

A broad repository invocation first stopped at collection with five import-path errors. A temporary in-process import-path shim then collected and ran the suite: **277 passed, 56 failed, 25 errors, 37 skipped**. The failures and errors are outside the owned 5A files; representative Phase 4E local service startup failed to bind a Unix socket with `PermissionError: [Errno 1] Operation not permitted` in this sandbox. This run does not establish a passing full regression suite. The integration lead must repeat the full gate in an authorized local lab environment.

Informational external branch `feat/phase5a-model-evaluation` at `5b4787432ed3c5ccbb215d85a87d55ae0c9e5ea1` was reviewed read-only. It adds an HTTPS provider, 20 author-labeled cases and separate model-evaluation code. None was copied or merged. Its real-model and source-support claims require independent review and explicit authorization before any future use.

Independent validation of this exact 5A-C pin remains pending. There is no measured model benefit, real model latency, provider cost, authenticated advisory intake or authority promotion. The read-only research lane remains separate from native T4/T5 and all protected writers.
