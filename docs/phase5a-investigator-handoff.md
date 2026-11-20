# Phase 5A Investigator handoff

This branch adds a research-only Investigator over immutable `SourceSnapshot` records. It uses the existing Phase 5A normalizer and deterministic `assess` checker. `AdvisoryInput`, `ResearchCandidate`, `ResearchCheck`, and `AuditRecord` are strict, versioned private records. They have no signed Finding, Evidence, Mesh, local approval, terminal, or protected-writer adapter.

The provider interface is replaceable. The offline `ScriptedProvider` is the default evaluation path. The dormant OpenAI Responses adapter is pinned to `gpt-4.1-mini-2025-04-14`, one small model, with prompt revision `investigator-1`. It has no model escalation. A live call requires an exact model and corpus hash, explicit spend cap and token rates, a shared process-local spend ledger, and a key. The outbound request uses `store=false`, no tools, no redirects, one call, a 10-second default deadline, 12 KB input limit, 512 output-token limit, and a 64 KB HTTP response limit. Failed calls retain their budget reservation. The ledger is process-local; an authorized future benchmark must use one process and also set a provider-side project budget for account-wide enforcement. No live call was made in this branch.

Model output is parsed into a strict draft. Emitted material text is only a contiguous exact byte excerpt of a supplied snapshot, with source digest and byte locator. A stored result can be rechecked with `verify_investigation` against the snapshots. Exact excerpts establish byte provenance, not semantic truth. An unsupported or conflicting model outcome yields `unknown` or `conflicting`; impact excerpts always require more evidence. Per-source deterministic dispositions retain disagreement. Model-generated uncertainty prose is discarded; baseline and check reason codes are retained. Audit records contain digests, model and prompt versions, status, token counts, cost and latency; they contain no asset identity, configuration or source prose. Private asset identity and configuration are also omitted from the prompt.

## Reproduction

From this worktree:

```sh
PYTHONPATH=.:src:scripts ../../.venv/bin/python -m pytest -q tests/test_phase5a_*.py tests/intelligence_phase5a1
PYTHONPATH=src ../../.venv/bin/python scripts/investigator_offline_evaluate.py --output benchmarks/phase5a-investigator/offline.json
```

The focused Phase 5A suite passed **45/45**. The offline evaluator verifies the existing 12-case manifest and source hashes, fixes evaluation time at 2026-11-20 UTC, then compares the same cases with the deterministic baseline and scripted Investigator. Both matched 12/12 visible labels with zero false affected outcomes. This is an implementation control result, not model accuracy or a benefit claim. The output is in [`benchmarks/phase5a-investigator/offline.json`](../benchmarks/phase5a-investigator/offline.json). Actual model accuracy, semantic unsupported-claim rate, billable tokens, latency and cost remain unmeasured.

The full repository suite could not complete in this sandbox: integration tests need Unix socket binding and failed with `PermissionError: [Errno 1] Operation not permitted`. The focused Phase 5A tests do not require those services.

For any future live benchmark, first authorize the exact model snapshot, sealed synthetic corpus hash, and total spending cap. Run the same corpus through both arms; have a reviewer adjudicate claim semantics and citation relevance. Do not treat source excerpts or model suggestions as independently verified Evidence.

The adapter follows OpenAI's [Responses API](https://platform.openai.com/docs/api-reference/responses) and the pinned model identifier appears in [OpenAI's model pricing reference](https://platform.openai.com/pricing/). Pricing is deliberately supplied by the authorizing caller rather than hardcoded.
