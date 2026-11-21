# Independent offline h84 linked gate

The frozen h84 gate passed on the baseline `ede372ebf3defe81df03006ab8f1c299a67b02a4`. The 52 sealed files and the h84 label and input digests matched preselection `9d733da`. The run used scripted drafts and a macOS network-denial sandbox. There were zero provider calls.

- Stage A verified the exact complete set `/affected/0` and `/affected/2` with the scripted IDs in reverse order. Its wire input contained only package identity fields and opaque IDs.
- Stage B was prepared exclusively from those Stage A draft bytes through the linked verifier. Its asset context contained only version `4.5.0` and its two admitted rows matched the original source spans byte for byte. The scripted `unaffected` draft verified with 2/2 reference precision and 2/2 support coverage.
- Both singleton subsets, the decoy alone, a decoy substitution, an extra decoy, and an empty `unknown` abstention all blocked Stage B. No blocked case produced a Stage B request or decision opportunity. After successful admission, Stage B abstention, incomplete support, and an incorrect decision all yielded zero released references.
- The two existing focused test modules passed 29 tests on the baseline.

## Lead candidate review

**PASS for local integration** at `275edaf1e7c8eecd5ec99eade64332c51f636861`. The h84 entry point emitted the exact Stage A and linked Stage B wire bodies from the independent gate run. A scripted Responses-format envelope supplied the original Stage A draft with reversed IDs and JSON whitespace. The review parsed that envelope offline, confirmed the extracted draft digest, and passed the raw draft file to the candidate. The candidate reverified the complete identity set before emitting B. The CLI verifies the draft contents. Any provider request provenance is outside this offline review.

The six Stage A controls from the baseline, an oracle pointer admission, a full response envelope supplied as a draft, a missing file, and an oversized draft all returned exit 2 and zero stdout bytes. The accepted B payload and local `unaffected` verdict retained 2/2 reference precision and 2/2 support coverage. All 138 Phase 6 benchmark tests passed on the exact candidate with networking denied. The observed replies and decisions were scripted.

## Reproduce

Use Python 3.12 with the candidate project's test dependencies. Pass a separate checkout of the reviewed revision. The script prints the prepared and wire digests, raw control statuses and scoring.

```sh
cd benchmarks/phase6-two-stage-independent
(cd seal && shasum -a 256 -c SHA256SUMS)
sandbox-exec -p '(version 1) (allow default) (deny network*)' \
  python replay_h84_gate.py /path/to/275edaf-checkout --check-entrypoint
```

Omit `--check-entrypoint` to reproduce the baseline gate at `ede372e`.

[Candidate observations](offline-h84-candidate.json) · [Baseline observations](offline-h84-gate.json) · [Frozen expectations](preselection-h84.json)
