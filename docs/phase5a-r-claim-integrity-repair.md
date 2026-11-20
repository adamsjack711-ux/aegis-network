# Phase 5A-R private claim-integrity repair

Source repair pin `d100adf3ceeac61edff366fb9eed9f27d720d9b7` on isolated `feat/phase5a-research-r-astra`. VAL-R's independent NO-GO reproduction in `docs/phase-next-r-5a-independent-review.md` at `7f8cc6d706b7fb11537120bd3364ad12f150e6ec` remains retained unchanged on its validation branch. This is an owner repair and owner replay, not an independent closure verdict. SignedFinding 1.0, Evidence, Trust, local approval and protected writers are untouched. No network or model call was made.

## Contract and repair

`verify_atomic_claim` now rederives the **decisive** `(byte_start, byte_end, quote)` from the reopened exact source bytes, claim kind, predicate and asset version. It rejects a quote moved to a different phrase within the same digest-valid source. It also requires `source_role` to match the actual fixture role and `acquisition` to match whether bytes came from the sealed file or pinned inline corpus. Raw source bytes, source ID/digest, asset and source product, version, polarity, predicate and current fixture status remain checked. A direct Pydantic parse is still insufficient; the caller must reopen bytes and call the verifier.

The availability-effect grammar now accepts an explicit asset product in the effect sentence or the constrained affected-input phrase “a crafted document/request/input/packet can cause availability degradation.” It rejects a sentence about an unrelated database outage. Other causal wording abstains. The row field `supported_impact` was removed in favor of `fixture_impact_observation`; private evaluator schema is `phase5a-alpha-eval-v3`. This value names a parser-consistent fixture observation, never independent vulnerability or impact proof. Old v2 evaluation rows must be rerun from the pinned source bytes; no automatic reader promotion exists. `AtomicSourceClaim.v1` still carries `support=fixture-parser-consistent` and `independently_verified=false`. The stricter verifier is a rejection bugfix to that private claim schema.

## Exact-pin replay and denominators

```sh
PYTHONPATH=src ../../.venv/bin/pytest -q tests/test_phase5a_source_claim.py tests/test_phase5a_alpha_eval.py tests/test_phase5a_intelligence.py tests/test_phase5a_claim_integrity.py
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_alpha_evaluate.py --root . --output /tmp/phase5a-r-d100adf.json --repeats 3
../../.venv/bin/python ../phase-next-r-val-astra/scripts/phase_next_r_5a_independent.py --candidate . --pin d100adf3ceeac61edff366fb9eed9f27d720d9b7 --v-corpus ../phase-next-r-val-astra/benchmarks/phase-next-r-validation/5a-r/retained-v01-v12.json --output /tmp/phase5a-r-val-replay-d100adf.json
```

Focused tests: **30 passed, 0 failed, 0 skipped**. The exact VAL-R negative cases are covered. The owner's replay of VAL-R's harness now reports `arbitrary_version_quote_accepted=false`, both role/acquisition spoofs rejected, unrelated-database effect rejected, two altered-byte controls rejected, and both private-to-Evidence/SignedFinding parsing attempts rejected. This replay's V adapter remains **9/12 exact**, zero false affected, one epoch inconclusive, zero claim-builder errors. V03 and V10 are conservative unknown; no hidden V labels were used to adjust the parser. The earlier independent **11/12** was a different scorer and remains a separate result.

The three-trial visible-corpus raw file is [phase5a-r-d100adf.json](../benchmarks/phase5a-r-d100adf.json), SHA-256 `5bf0db18afc126b6bd0e7c9a4984e9386c3bc55bbb5d7f85ced21be0ae9b419a`. The owner VAL-R harness replay is [phase5a-r-val-replay-d100adf.json](../benchmarks/phase5a-r-val-replay-d100adf.json), SHA-256 `ed17d75e4ce3d2f28d0e26ed7bfa81a760e3de15d2ba47c947215e3cd80507dc`. The original VAL-R raw failures remain only on its validation branch.

Each visible trial retains 36 planned cases, 34 evaluable, two Debian epoch inconclusive, deterministic 33/34 exact and zero false affected. Source claims remain 23 attempted/15 emitted, 10 positive attempted/6 emitted, including one fixture availability observation; independently semantically adjudicated and real authenticated advisory claims remain **0**. The scripted stress arm attempts 36 unsupported positive points and emits none; raw false affected is 29 and checked false affected is zero through abstention. Real-model calls, billed tokens and USD cost remain skipped/unmeasured. No denominator was reduced after the failure report.

Deterministic case wall p50/p95/p99 in the three trials was `0.138/0.848/0.884`, `0.020/0.248/0.264` and `0.020/0.287/0.315` ms. Process wall was `14.219/5.797/6.275` ms, CPU `14.041/5.789/6.240` ms, and peak RSS `36,683,776/36,814,848/36,913,152` bytes. The first trial was colder. These are one-process fixture observations and do not measure model inference or physical protection. No full repository regression was run on this specialist pin; VAL-R owns exact-pin independent review and the integration lead owns full regression on a future reviewed integration commit.

## Remaining limits

The effect grammar is intentionally narrow and cannot establish semantic causality in arbitrary prose. The decisive quote can be only a comparator or version token; its meaning still depends on the full digest-bound fixture and parser. A maliciously rewritten, self-consistent source record is not authenticated by SHA-256 alone. All fixture roles remain synthetic, V01–V12 is unchanged, Debian epoch comparison still abstains, no real model is enrolled, and no positive model prose is promoted. This candidate must stay read-only pending a new independent VAL-R verdict.
