# Phase 5A Investigator offline source revision

**Review basis:** Investigator `97265de36a67de4a7ae6f374fb8cd64362fcb6fe`; independent HOLD `80da23095f5421e85ab692b0764104ee184cc029`; Scout `54c7ec4d90e612c667d9cd5f217a5e2f18e38d54`. This branch is an isolated source candidate, not integrated or independently accepted.

## Disposition of HOLD

The original `OpenAIProvider.complete()` had callable HTTP transport. A caller could construct `Authorization`, set an environment key, and call `complete()` without the `investigate()` ledger. This revision removes the HTTP and environment access from the module and makes `complete()` unconditionally raise `PermissionError`. `investigate()` accepts only the exact `ScriptedProvider` class and rejects live authorization parameters before it reads the advisory. A custom provider cannot declare `live=False` to bypass the gate. The old Authorization and SpendLedger records remain importable but inert for experiment-reader compatibility; they are not operator consent.

Offline exact source-byte quote checking, deterministic baseline, abstention and private research records remain. No Scout adapter is implemented. Its proposed v1 mapping and hold cases are in `docs/phase5a-scout-investigator-adapter-v1.md` and require independent contract review.

## Local verification

Command: `PYTHONPATH=src ../../.venv/bin/python -m pytest -q tests/test_phase5a*.py` from this worktree: **41 passed, 0 failed, 0 skipped**. Tests include direct provider call with a throwaway environment key and caller-created authorization, fake live and false-offline providers, socket connect trap, offline source excerpt integrity, conflicting/unknown abstention, and failed conversion of ResearchCandidate to SignedFinding or Evidence. These are local tests, not independent validation.

Command: `PYTHONPATH=src ../../.venv/bin/python scripts/investigator_offline_evaluate.py --output benchmarks/phase5a-investigator/offline-revision.json`: 12/12 author-visible baseline and scripted outcomes, zero false affected in those cases, 12 exact-byte citations. The raw output separately records `unsupported_semantic_claims: null`; exact bytes do not establish semantic support. Actual model: skipped; no real accuracy, latency, cost, or billing results. No external inference, feed, or network call occurred.

## Gate and follow-up

Independent VAL must re-review this exact commit for the original transport bypass and inspect the proposed Scout adapter. It must retain the original failure reproduction and separately adjudicate semantic support. Shared SignedFinding 1.0, exact InventoryItem matching, native T4/T5 and all enforcement boundaries remain unchanged. Real inference and Scout-to-Investigator intake remain **NO-GO**.
