# Phase 5A-R research validation handoff

Source base: `d15a3a756b8066c5cb2d98665662220e52f4a7d6`. Worktree: `.worktrees/phase5a-research-validation`. Implementation and benchmark source pin: `d355e63fe55c4ad6dab7e4d91bbecff5d20e8501`. This is an isolated, read-only research result. Nothing was merged into master.

## Reviewed inputs and the 11/12 result

The base already includes claim-integrity commit `71a6f864456457769cfb3f844f0cd47aac3a9d95`, which passed the revised independent 12/12 private v2 reader challenge. That challenge also showed that a self-consistent forged private record can pass its unkeyed digest check; re-acquiring and checking exact source bytes is still required across processes. The base also includes sealed offline evaluator `99e866453a504aa070ee4e0b177da42b621ab67b`, separately reviewed at `c25373543bdf3e0440eae7687292f18b9287d354`, and its 12 old plus 24 new validator-owned synthetic advisory cases. The sealed manifest SHA-256 is `20a3a37da8f941f17e6db514d1437d8d6575140e2e3bde61fc2cad9c6d4a234b`.

The separate independent `test/phase-next-alpha-validation` holdout reported **11/12 exact**, six of six expected unknowns abstained, one additional conservative Debian epoch abstention, and zero false affected. It used a simple text parser and counted that epoch abstention as its single mismatch. An earlier **structured GHSA adapter** on the original H01–H12 cases instead reported **9/11 mappable**, two conservative unknown disagreements (H01 package-name collision and H10 withdrawn notice), and H11 Debian epoch unmappable. These are distinct adapters and denominator rules. They cannot be pooled or called a regression in authoritative inventory matching. The current sealed text evaluator reports **33/34 eligible** across 36 cases: H10 remains a conservative unknown disagreement, while H11 and P02 Debian epoch cases are explicitly inconclusive. H01 is resolved by the text fixture's explicit unrelated-product statement. The structured `InventoryItem` and `assess()` identity semantics were not changed.

The text evaluator had a separate sentence-boundary bug: `Debian maple-lib.` was tokenized with a trailing period in the package name. The narrow fixture-parser fix strips trailing sentence punctuation while preserving internal package dots and namespaces. It does not establish Debian version ordering. Epoch comparisons, Debian revision precedence, source-to-binary mapping, and unsupported version schemes remain unknown or inconclusive until a reviewed distribution comparator and mapping source exist. Conflicting, withdrawn, stale, configuration-dependent, missing-source, and unsupported-impact cases remain conservative. A withdrawn notice can justify withdrawing its own assertion without proving the installed package safe; this explains the H10 label disagreement.

## Corpus and independent scorer

The **36 sealed cases** include affected and unaffected packages, version boundaries, contradictions, ambiguous identities, stale/withdrawn and missing evidence, unsupported impact and prompt injection. The new `independent_validation.py` reads sealed labels and exact source bytes directly, without importing the baseline parser or accepting model-supplied labels. It checks case denominator, decision/status values, citation IDs, required citations, and that no raw model point was promoted. It does **not** authenticate synthetic vendor roles or prove semantic entailment merely because a citation ID exists.

The **four additional Debian backport controls** are in `phase5a-backport-supplement-v1.json`: exact fixed backport, missing binary mapping, upstream-only version claim, and conflicting distribution notices. They are **author-labeled development cases, pending independent review**, and are scored separately from the 36 sealed cases. They must not be used as held-out model accuracy evidence.

## Measured offline comparison

Three sequential trials at exact clean source pin `d355e63` produced identical decision counts. Each trial had 36 planned, 34 eligible, two epoch inconclusive, **33/34 exact deterministic**, five true affected, zero false affected, zero affected false negatives, 19 correct abstentions and one excess abstention. Citation-ID errors were zero. The inert scripted stress response proposed affected in every case: 5/34 exact and 29 false affected before checking. The guarded result was 24/34 exact, zero false affected and 29 abstentions; it did **not** improve the baseline. All 36 fabricated remote-execution point attempts per trial remained unchecked, and zero positive points were emitted. The four author-labeled backport controls scored 4/4 after the punctuation fix, with no real-model arm.

Baseline per-case wall p50/p95/p99 in the three trials (ms): `0.017/0.239/0.540`, `0.008/0.022/0.035`, `0.009/0.021/0.033`. These exclude fixture seal validation and interpreter startup. Scripted timings are not inference latency. **Real-model supported-claim accuracy, false-positive/negative rates, correct abstentions, citation/provenance accuracy, latency, token use, billed/estimated cost, and improvement are unverified.** Provider cost is unmeasured, not zero. The 36 labels were visible during evaluator development, so the result is descriptive rather than a fresh blind generalization estimate.

The raw benchmark is `benchmarks/phase5a-research-validation-raw.json` (SHA-256 `cfb62c1803e1d6c5b8ef51fc5ad645f8119fd3c78ecb38cf5bbea380e88b3ab9`), the independent rescore is `benchmarks/phase5a-research-validation-score.json` (SHA-256 `abb2a5c4848ce4ec161c511a8ed05f3209753da7a594cbdba59050be8892a582`), and the backport supplement is `benchmarks/phase5a-backport-supplement.json` (SHA-256 `020a461d0e383d741b9abb7a8724e2cf15ea909fc361727fb75602f2c1f7a769`). The original independent raw holdout and failures remain untouched.

## Dormant provider and security boundary

`OpenAIResponsesProvider` implements the existing provider-neutral `JSONProvider` protocol using the OpenAI Responses endpoint. It is never constructed by the offline benchmark. Its default authorization is false; a call without authorization fails before transport creation. The adapter fixes the endpoint, refuses redirects, uses `store=false`, disables tools and truncation, bounds input/output bytes, output tokens and wall timeout, validates completion status and token counts, and never writes the API key to a report. It has no retries or parallel calls. Research prompts no longer include the deterministic baseline outcome, so a later model arm can be compared without that answer in its input. The provider returns only an unchecked research draft; the existing digest-reparse check controls any reportable advisory outcome. There is no model-to-SignedFinding, Evidence, attestation, approval or writer path.

No endpoint, credential, external inference, live feed, production asset inspection, or network call was authorized or used here. A real-model evaluation requires explicit approved scope, an independently hidden source-labeled corpus, claim-by-claim source adjudication, repeated runs, actual provider usage and billing or documented price estimate, and the same deterministic input. The current evidence does **not** demonstrate AI superiority or qualify authenticated AI Evidence for release.

## Reproduce

From the implementation pin in this worktree:

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python -m pytest -q tests/test_phase5a_research_validation.py tests/test_phase5a_alpha_eval.py tests/test_phase5a_claim_integrity.py tests/test_phase5a_intelligence.py
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase5a_alpha_evaluate.py --root . --output /tmp/phase5a-research-validation-raw.json --repeats 3
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase5a_validate.py --root . --input /tmp/phase5a-research-validation-raw.json --output /tmp/phase5a-research-validation-score.json
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase5a_backport_evaluate.py --output /tmp/phase5a-backport-supplement.json
```

Focused result: **29 passed**. The benchmark script refuses a dirty checkout; rerun from the implementation pin, since this handoff commit adds only documentation and retained results. No full-repository regression or external provider call was run in this lane.
