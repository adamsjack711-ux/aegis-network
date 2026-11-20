# Phase 5A-C: model inference evaluation handoff

## Scope and authority

This branch starts at `3bfd2abea430bc8036105ce85adfdc78706d367d`, which already contains claim-integrity commit `71a6f864456457769cfb3f844f0cd47aac3a9d95`. Research v2 reparses digest-checked snapshots before repeating a deterministic outcome. Raw model prose and candidate outcomes remain in `raw_hypothesis`; every point is `unchecked`. Unknown, conflicting, stale, withdrawn, unsupported-version, and model-disagreement cases cannot become positive checked outcomes. Research results cannot be parsed as SignedFinding or grant Evidence, local approval, writer, or enforcement authority.

No provider or live feed was authorized for this run. No external model inference or live feed retrieval occurred. **Real-model accuracy, latency, semantic support, and cost are unverified.** The HTTPS adapter is dormant unless `--mode model --authorize-external-model-calls` and exact endpoint, model, token environment variable, prices, and run cap are supplied. Feed retrieval is outside this runner and needs its own explicit authorization. The adapter accepts only one bounded JSON completion contract over HTTPS, refuses redirects, caps input and output bytes, token usage, and timeout, and stores no credential in reports. A provider or proxy must implement the documented request/response fields in `provider.py`; that contract is independent of model vendor.

## Corpus and labels

`tests/fixtures/phase5a_model_cases.json` contains the 12 prior author-labeled synthetic cases plus 8 variants: inclusive and exclusive range boundaries, a nonnumeric version, and KEV/stale/withdrawn unsupported-positive traps. Each source body has a digest in `phase5a_model_manifest.json`. All 20 labels are author labels and **are not independently validated**. These variants deliberately test control behavior; repeated source shapes make this a poor generalization sample. The fixed appraisal time is 2026-11-19 12:00 UTC. Corpus SHA-256: `9a2427c19ca90d47ef235859776f8e126fa0a59ab88c61f9b0e756420c08f6ff`. Manifest SHA-256: `8341d8f3bdc604702a72335c5fdd1ebe4af7b84d50545fbed934ab4935928baa`.

The separately frozen independent H01-H12 labels remain in `fixtures/phase-next-ai-holdout-v1.json`, pinned by validator commit `5665c4a156711d1da8c43667a017c8af7729ac0d`; their SHA-256 is `d21b931c2e5822d40145b709e72ed83fb7dc14a25217b8600deebbcf0ca1c8ac`. We reran the existing exact-pin deterministic adapter on those labels. **Independent validator coordination handoff:** preserve H01-H12 unchanged and ask the validator to adjudicate the eight new labels and each atomic model claim against source bytes, blinded to model output, before treating this as a held-out model comparison. The H11 Debian epoch case remains inconclusive until a separately reviewed comparator exists. No independent review of the new labels has been received.

## Method

The same normalized source snapshots and asset/version input feed the deterministic `assess()` arm and optional `research()` arm. The model receives fact IDs, bounded source fields, a redacted asset alias, and a numeric version when safe. It receives neither the gold label nor the deterministic outcome. Model raw outcome measures interpretation; the checked research outcome measures what can be safely repeated under claim-integrity rules. A source citation ID only identifies a location; it does not entail model prose. Unsupported-positive outcome count is observable from labels. Semantic assertion support requires human source-text adjudication, so the report records `unsupported_assertions_adjudicated=null` instead of a fabricated zero.

Exact accuracy uses all cases. Positive precision counts every affected outcome on nonaffected gold as a false positive. Recall counts an affected gold answered unknown, conflicting, or error as a false negative. Abstentions include unknown and conflicting outcomes. Latency percentiles use completed calls in process; the frozen holdout adapter also measures subprocess overhead. Scripted token counts simulate provider usage and are not billed inference. Model prices must be supplied explicitly; reported model cost will be an estimate from returned token counts, not a provider invoice. Model name, provider version, endpoint, prompt text/hash/revision, research code hash, limits, corpus and manifest hashes are included in run JSON. For a meaningful gain claim, obtain independently reviewed labels and claim-level support, run repeated fixed-configuration trials on the frozen holdout, improve exact accuracy or affected recall over the same baseline without unsupported positive assertions, and report variance plus real latency and cost. This run does not meet those conditions.

## Offline results

| Arm and corpus | Exact decisions | False affected | Abstentions | Latency p50/p95 | Cost |
| --- | ---: | ---: | ---: | --- | --- |
| Deterministic, 20 author cases | 20/20 | 0 | 13 | 0.009/0.062 ms | none |
| Scripted raw hypothesis, same 20 | 17/20 | 3 | 10 | 0.008/0.015 ms | no provider charge |
| Checked scripted result, same 20 | 20/20 | 0 | 13 | shares scripted call | no provider charge |
| Deterministic, frozen validator holdout | 9/11 mappable; 1 inconclusive | 0 | 7 of 11 completed | 147.42/150.44 ms, subprocess | none |
| Real model | unverified | unverified | unverified | unverified | unverified |

The three scripted false positives are the KEV, stale, and withdrawn traps. All 18 points attached to positive scripted hypotheses remain unchecked, including points on otherwise correct affected cases. The checked arm demonstrates containment, not AI improvement. On the independent holdout, H01 and H10 receive conservative `unknown` rather than validator `unaffected`; H11 is unmappable. The deterministic 20/20 result reflects an author-built corpus and must not be used as an independent accuracy estimate.

Artifacts: `benchmarks/phase5a-model-deterministic.json`, `benchmarks/phase5a-model-scripted.json`, and `benchmarks/phase5a-model-independent-holdout.json`. The last includes exact case decisions and the model arm explicitly marked skipped. No model benefit is demonstrated.

## Reproduction and authorization

From this worktree, using the repository virtual environment:

```sh
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_model_evaluate.py --mode deterministic --output benchmarks/phase5a-model-deterministic.json
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_model_evaluate.py --mode scripted --output benchmarks/phase5a-model-scripted.json
PYTHONPATH=src ../../.venv/bin/python -m pytest -q tests/test_phase5a_model_evaluation.py tests/test_phase5a_claim_integrity.py tests/test_phase5a_intelligence.py
```

After separate provider and outbound authorization, an operator may run `--mode model` with `--authorize-external-model-calls`, `--endpoint`, `--model-name`, `--token-env`, both `--*-usd-per-million` rates, and `--max-run-cost-usd`. The HTTPS request body is `{model,instructions,payload,max_output_tokens,response_format:"json"}`. The endpoint must return `{content:"<one JSON research object>",usage:{input_tokens,output_tokens},provider_version}`. Do not place credentials in arguments or files; set only the named environment variable locally. The command makes one inference request per case, so explicit authorization must cover the full case count and endpoint. The runner does not fetch live feeds.

## Limits

The corpus is synthetic, small, and partly derived from repeated source bodies. Existing normalization cannot adjudicate Debian epoch ranges or all ecosystem-specific versions. The checked arm cannot improve a deterministic unknown without a separately justified source checker; this is an intentional security boundary. Claim-level entailment, billing data, repeated model trials, and independent review of the expanded labels are absent. Consequently the real-model comparison remains unverified and there is no evidence that AI meaningfully improves threat-intelligence interpretation here.
