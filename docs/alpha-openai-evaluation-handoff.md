# ALPHA-4 OpenAI research evaluation handoff

Source base: `29455087922a728a41936d8c5c79ff9942e1e3df`. Worktree: `.worktrees/alpha-openai-evaluation`; branch: `feat/alpha-openai-evaluation`. No master merge.

## Preserved evidence and adapter decision

The prior 12 labels remain in `fixtures/phase-next-ai-holdout-v1.json` (SHA-256 `d21b931c2e5822d40145b709e72ed83fb7dc14a25217b8600deebbcf0ca1c8ac`). The new 24 labels remain in `fixtures/phase-next-alpha-ai/holdout-v1.json` (SHA-256 `7f88e132b92d528fb01573f37e00c8af4698919bf3747c583f3ec74fb7dbc82d`). The 27 source files and both corpus digests are checked against `seal-manifest.json` (SHA-256 `20a3a37da8f941f17e6db514d1437d8d6575140e2e3bde61fc2cad9c6d4a234b`). The original denominator is 36: 12 prior plus 24 new. Label counts are 5 affected, 12 unaffected, 19 unknown.

The earlier structured GHSA adapter, `scripts/phase_next_5a_adapter.py`, expects a claim map covering the prior cases. It raised `KeyError` on all 24 new text cases. The original failure record remains at `benchmarks/phase-next-alpha-astra/5a-blind-holdout-incompatibility.json` (SHA-256 `fd0653f6042defcb8b7e1b3a4620d78d5476408d935bc2a9ef18faa76f0f686b`): deterministic completed 0/24, inconclusive 24/24; the model arm was skipped. This result is not replaced or silently scored as model behavior. The new harness uses the existing seal-verified text evaluator for its deterministic arm and supplies the same 36 assets and source texts to the prepared model arm. It does not synthesize structured claims or change fixture labels.

## Local baseline and prepared model input

`benchmarks/alpha-openai-baseline.json` is the one-trial local run. It records 36 planned, 34 completed, two inconclusive Debian epoch cases (`H11-epoch-boundary`, `P02-debian-epoch-fixed`), and 33/34 exact labels. The one completed disagreement is `H10-withdrawn`: the baseline abstains while the author label is unaffected. It has 5/5 affected true positives, zero false affected calls and 19/19 correct unknown abstentions. Those figures are development-informed synthetic fixture results, not generalization evidence. Local wall and CPU timings in that artifact are measured; the inert scripted stress arm is not a real model.

`benchmarks/alpha-openai-evaluation/prepared-inputs.json` is the outbound review bundle. Each of the 36 entries contains only the synthetic asset ecosystem, package name and version plus source ID, role, retrieval timestamp and source text. It excludes labels, expected impacts, local paths, source hashes, Aegis credentials and production data. The *canonical JSON* SHA-256 used by the authorization gate is `c9677d431a736abd10323a7c0bc2ab6cc298572d029548f51a848c6dedcc1598`; it differs from the indented file's byte hash. Inspect the complete bundle before approving it. `benchmarks/alpha-openai-evaluation/report.json` currently records model authorization pending and leaves model metrics unmeasured.

## Bounded model run, pending explicit authorization

The harness is `scripts/alpha_openai_evaluate.py`. Its `prepare` mode performs no network call. Its `run` mode needs an explicit user approved model name, the exact sanitized bundle hash above, an overall USD spending cap, and approved conservative input and output USD per million token rates. An exact-match authorization JSON file is required; no file has been created. The user must authorize these values before an operator creates that file or invokes `run`. A missing or mismatched authorization blocks all requests. The OpenAI key is read only from `OPENAI_API_KEY` at run time and is never written to the repo. Do not put the key in an authorization file or command argument.

The run uses the Responses API with `store: false`, a strict JSON output shape, at most 300 output tokens per case, 12,000 request bytes, 64,000 response bytes, a 20 second request timeout, one request at a time, no retries, and at most 36 calls. It conservatively rejects a run when the sum of ASCII request byte ceilings and output token ceilings at the approved rates exceeds the cap. A transport failure or malformed response stops the sequence. This cap is a preflight estimate based on the authorized rates; actual billed cost remains unknown until a provider billing record is inspected. If rates or API behavior change, stop and seek a new authorization. No request has been sent in this branch.

After authorization, the operator can create a JSON file outside the repository containing exactly these fields, with the authorized values substituted:

```json
{
  "authorization": "explicit-user-approval",
  "model": "USER_APPROVED_MODEL",
  "prepared_inputs_sha256": "c9677d431a736abd10323a7c0bc2ab6cc298572d029548f51a848c6dedcc1598",
  "max_usd": 0.0,
  "input_usd_per_million": 0.0,
  "output_usd_per_million": 0.0
}
```

The placeholders are intentionally invalid. Invoke from the worktree using the same model, cap and rates in the command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../../.venv/bin/python scripts/alpha_openai_evaluate.py run \
  --model USER_APPROVED_MODEL --authorization-file /tmp/alpha-openai-authorization.json \
  --max-usd USER_APPROVED_CAP --input-usd-per-million USER_APPROVED_INPUT_RATE \
  --output-usd-per-million USER_APPROVED_OUTPUT_RATE
```

The report records each completed model decision, source IDs, exact quotes, measured latency and API token usage, alongside failures. It compares exact decisions only on the same completed baseline cases and separately reports false affected claims and correct unknown abstentions over their stated denominators. Citation checks count allowed IDs, required IDs, and verbatim quote containment in the cited source. Quote containment is mechanical text support; semantic entailment and source authenticity require separate human review. The report never treats model prose as a SignedFinding, Evidence, local approval or protected-writer input.

## Reproduce and limits

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_alpha_evaluate.py \
  --root . --output /tmp/alpha-openai-baseline-replay.json --repeats 1
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../../.venv/bin/python scripts/alpha_openai_evaluate.py prepare
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. ../../.venv/bin/pytest -q \
  tests/test_alpha_openai_evaluate.py tests/test_phase5a_alpha_eval.py
```

The replay has different wall timings and may include a different source pin after this commit; compare case IDs, seal hashes, denominators and decisions. The current focused gate passed 8 tests. No real OpenAI model latency, token usage, cost, supported claims or model advantage has been measured. Even after a run, exact quote containment cannot establish that a model's decision follows from the cited text. No authenticated real advisories, source authentication or authority promotion are in scope.
