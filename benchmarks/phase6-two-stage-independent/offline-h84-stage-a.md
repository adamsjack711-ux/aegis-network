# Independent h84 Stage A preflight

The original h84 Stage A body was independently rebuilt from the sealed input at integrated commit `056b7d4cc11fa665196aeca886a3ca488db34213`. An independent compact JSON encoder and identity projection reproduced the accepted CLI bytes, including the strict closed reply schema. The count body retains exactly `input`, `instructions`, `model`, `text`, `tool_choice` and `tools` with identical values, including the entire strict format.

| Bytes | Length | SHA-256 |
| --- | ---: | --- |
| Stage A create body | 1,450 | `92b5e3a2318e5221b11749e2e536efc183b034a4b7dbabd07d58fb6cfd622e20` |
| Stage A count projection | 1,387 | `2decf8568cdda2ac4d1933cb642c49d82d780701bd9f72123df568f862f8cd25` |
| Shared input string | 438 | `ee08d952541663db8b1ec7aebf6f10b10ae5df79ebb3f2f6c9e0de0ba20dd521` |
| Shared instructions | 451 | `9e8568e692d0051c42d9a73fd8a36a2f560383b7c359abcedb6ba62758f36d51` |

The Stage A input contains the synthetic target ecosystem and package and three uniform identity rows. Each row has an opaque ID, ecosystem, package, null PURL and PURL presence flag. Replacing all row versions and the target version preserved the entire create body. The wire uses the pinned model `gpt-5.4-mini-2026-03-17`, no tools, `store=false`, default tier and a 512 output-token cap. The strict object requires only `identity_outcome` and `selected_row_ids`, with additional properties disabled.

The prepared count body is an offline JSON projection. There are no h84 provider counts, receipts or billing measurements in this evidence. The previous m82 one-shot body check refused the h84 bytes. The scripted complete set admitted local Stage B preparation. Both singleton sets, wrong-ecosystem selections, abstention, oracle pointers, a full response envelope at the raw-draft boundary, and missing or oversized input produced zero Stage B bytes. Local Stage B preparation is independent of live approval and conveys no authorization.

## Owner handoff review

**PASS for offline owner review** of `c5ea4d455a7b5f9a9074974d0968774574f567c9`, against the reconstruction pinned at `73adefddb07fc382f372473fd961369b6ad16a51`. From a clean checkout with network access denied, the documented `create` and `count` entry points matched both independently built byte strings, and all five documented digests matched. The strict `text.format` object was 323 bytes at `8ac8411591eeabf0a8f06aa8b97f85e088f1008c9008a25a5f329207f3a18d00`.

Independent scripted attempt, HTTP, native response and transport records with a complete reversed identity set produced the exact 1,513-byte linked B body, SHA-256 `0202d8052cb303a4fdad942907631c08c4ef20adbee4ff5b3f56c280bb46bdb1`. All 15 incomplete, abstaining, invalid-receipt or out-of-bound controls returned exit 2 and produced zero B bytes. The helper checks consistency between local records. Custody and reconciliation of an actual observed reply belong to the operator, and those records carry no provider attestation of the original request hash. All 149 Phase 6 benchmark tests passed with networking denied.

An independently authorized h84 count and retained receipt, a reviewed spend basis, fresh owner approval, and an h84-specific signer and one-shot dispatch caller are still required for live Stage A. The m82 tooling binds m82 and the preflight has no dispatch entry point. The handoff gives Stage B a separate export, count, approval and exclusive attempt after an eligible observed A reply.

## Reproduce

Use the reviewed Python 3.12 test dependencies and a clean checkout of the reviewed revision.

```sh
cd benchmarks/phase6-two-stage-independent
sandbox-exec -p '(version 1) (allow default) (deny network*)' \
  python rebuild_h84_stage_a.py /path/to/c5ea4d4-checkout --check-handoff
```

Omit `--check-handoff` to rebuild the wire bytes at `056b7d4`.

[Handoff observations](offline-h84-stage-a-handoff.json) · [Wire observations](offline-h84-stage-a-wire.json) · [Linked gate observations](offline-h84-candidate.json) · [Frozen expectations](preselection-h84.json)
