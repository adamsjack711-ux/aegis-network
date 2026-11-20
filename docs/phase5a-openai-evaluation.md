# Phase 5A-1 OpenAI research evaluation handoff

Starting reference: `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`. Branch: `feat/phase5a-openai-evaluation`. This branch is an isolated, read-only research experiment. It does not change SignedFinding, Evidence, approval, or protected-writer code.

## Compatibility and sealed denominator

The independent holdout consists of the unchanged prior 12-case JSON and 24 separately authored text cases with 27 sealed raw UTF-8 source files. The text cases cannot be passed to the original Phase 5A structured OSV/NVD/KEV/GHSA normalizer without inventing normalized claims. The older `research.JSONProvider` and the external `feat/phase5a-model-evaluation` generic HTTPS transport also do not implement the OpenAI Responses API wire response. That external evaluator calls `research(..., now=...)`, which the starting reference does not accept. Its author-labeled 20 cases and scripted hypotheses are not part of this denominator or evidence of model benefit.

This harness reuses the exact sealed text evaluator for the deterministic arm and projects those same synthetic asset and advisory fields into model requests. It verifies the 24-case source bytes and manifest before either arm. No label, expected impact, local source path, real endpoint, asset identifier, production inventory, or credential is sent. Model decisions are private raw hypotheses; parser-consistent atomic claims remain fixture observations, never independently verified advisory truth.

| Artifact | SHA-256 |
| --- | --- |
| Prior 12-case corpus | `d21b931c2e5822d40145b709e72ed83fb7dc14a25217b8600deebbcf0ca1c8ac` |
| New 24-case corpus | `7f88e132b92d528fb01573f37e00c8af4698919bf3747c583f3ec74fb7dbc82d` |
| New source seal manifest | `20a3a37da8f941f17e6db514d1437d8d6575140e2e3bde61fc2cad9c6d4a234b` |
| Exact instruction prompt | `ddd5b6419c545eb18475cb9543a8e770d9440aa4b7abca69f77ee418bbc589be` |

The result JSON records all 36 per-case projected input hashes and the evaluator code hashes. Labels stay in their independent files. Two Debian epoch cases, `H11-epoch-boundary` and `P02-debian-epoch-fixed`, remain planned but baseline-inconclusive. They are not silently removed or treated as model errors. The 36 cases were visible during parser development, so deterministic accuracy is descriptive rather than a blind generalization estimate.

## Reproducible offline result

Run from this worktree with the repository virtual environment:

```sh
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_openai_evaluate.py --output benchmarks/phase5a-openai-offline.json
PYTHONPATH=src ../../.venv/bin/pytest -q tests/test_phase5a_openai_eval.py tests/test_phase5a_alpha_eval.py tests/test_phase5a_source_claim.py tests/test_phase5a_claim_integrity.py tests/test_phase5a_intelligence.py
```

The retained [offline result](../benchmarks/phase5a-openai-offline.json) has SHA-256 `61c152738f7317446c16e32fce11905133de0fc51e91186ca679cbe4380858ab`. Re-running changes local timing values and therefore the result file hash, while the corpus, prompt, code hashes and decision counts remain stable. Focused tests: **37 passed**. Mocked transport tests exercise Responses wire shape, exact citations, token caps, approval mismatch, all 108 planned rows, unsupported affected-version claims, fabricated remote-execution impact and the process wall alarm. Mock replies are harness controls, not model inference.

| Offline baseline measure | Result |
| --- | ---: |
| Planned / completed / inconclusive | 36 / 34 / 2 |
| Correct on completed | 33 / 34 |
| Gold affected / unaffected / unknown, all planned | 5 / 12 / 19 |
| Correct affected / unaffected / unknown, all planned | 5 / 9 / 19 |
| False affected | 0 |
| Fixture atomic claims attempted / emitted | 23 / 15 |
| Positive fixture claims attempted / emitted | 10 / 6 |
| Independently semantically adjudicated claims | 0 |

The three unaffected misses on the all-planned count include the two epoch cases and the withdrawn-notice disagreement. The first two are inconclusive, yielding 33/34 on completed cases. The one-run in-process deterministic case latency was p50/p95/p99 **0.140/0.624/0.780 ms** on this host. It excludes seal validation, process startup, network and model inference. It is not comparable to a model latency until the same case order is run with approved inference.

Three additional sequential offline deterministic replays each returned **36 planned, 34 completed, two inconclusive, 33 correct and zero false affected**. This checks decision reproducibility; the single retained JSON contains the per-case hashes and timings from its own run.

## Prepared Responses API arm

The prepared exact endpoint is `https://api.openai.com/v1/responses`; model identifier is `gpt-6-luna`. The request uses strict JSON schema for `decision`, citations, affected-version assertion and impact assertion; `service_tier=default`, `reasoning.effort=none`, `store=false`, `truncation=disabled`, and `tools=[]`. Calls are serial with no retry, a 15-second HTTP timeout and POSIX process wall alarm, 4,096-byte case payload cap, 8,192-byte request cap, 512 output tokens, 8,192-byte response cap, and 108 calls maximum across three identical passes. The alarm interrupts the current Python call; it is not an out-of-process kill. The provider stops after a failed or unparseable response because its billability may be uncertain. A valid response must return the requested model and Standard tier plus reported usage within bounds. No model result is promoted to an Aegis authority.

The configured Standard prices are **$0.10 per million input tokens** and **$0.50 per million output tokens**, from the [OpenAI model page](https://developers.openai.com/api/docs/models/gpt-6-luna). The conservative 108-call estimate is **$0.1161216** using 8,192 input and 512 output tokens per call; the fixed approval cap is **$0.20**. The model run will record returned usage and an estimated cost from those rates. Actual provider billing requires an external billing oracle and is not inferred from usage. This offline run made **zero inference calls**, consumed **zero billed model tokens**, incurred **$0 estimated API cost**, and has **no measured model latency or model benefit**.

To review a disabled approval record, run:

```sh
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_openai_evaluate.py --output /tmp/phase5a-offline.json --approval-template /tmp/phase5a-openai-approval.json
```

The generated record has `approved=false`. An actual run requires separate, explicit user approval for this exact synthetic corpus, prompt, endpoint, model, token prices, 108-call plan and $0.20 budget. The user-supplied approval file must match every fixed field and identify the approver and time; only then may `--mode model --approval-file /path/to/approval.json` use `OPENAI_API_KEY` from the environment. Keep that file and credential out of Git. Changing scope requires a new approval. An approval file is an experiment gate and audit record, not cryptographic authorization; operators must verify the approval was genuinely granted.

Model source checks compare structured version and impact assertions with exact sealed, parser-consistent atomic claims from the cited source IDs. They flag unsupported positive versions and fabricated impacts. Presence of a matching phrase is only a fixture parser observation, so the report keeps semantic source support as `not-independently-adjudicated` and `model_benefit=unverified` pending separate point-by-point review. Model and baseline accuracy must be compared on the same 36 cases and on the paired 34 baseline-completed cases, with the two epoch cases separately identified. No real inference or such comparison was authorized or performed in this handoff.
