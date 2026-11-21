# Retained two-stage drafts in disposable history

Replayed the previously retained h28 and h53 native A/B drafts using the
offline bridge at `daf170c` and scratch admission at `e878744`. The fixture
seal is `46b5566`. For each of the four probes, the local attempt, HTTP and transport records
reconciled with the exact wire, saved response and embedded draft digests.
The replay did not make external requests. The local records supply the
request-to-response association for this replay.

For each case the retained A draft passed the complete identity check.
Rebuilding linked B produced byte-identical wire to the recorded oracle B
attempt, so the exact retained oracle B draft could be rechecked on the
linked input. The two arms had the same outcome and references. This was
an offline reuse of the retained response.

| Case | Fresh native history | Exact evidence | Repeat |
| --- | --- | --- | --- |
| h28 | One current affected row, `research-consistent` | `/affected/1`, original UTF-8 bytes `[90,230)` | `duplicate`, investigation JSON byte-identical |
| h53 | One current unaffected row, `research-consistent` | `/affected/2`, original UTF-8 bytes `[167,303)` | `duplicate`, investigation JSON byte-identical |

Both cases used one disposable SQLite database with the sealed clock
2026-11-20 00:00 UTC and fixture retrieval time. The existing
`read_history` and `read_asset_report` reopened the exact advisory and asset.
A fresh SQL read confirmed two saved research rows total. The benchmark
removed the database after the run.

**Stored in SQLite.** Each native private `research-candidate-v2` carries its
advisory, asset and source revision bindings, reportable outcome, native
check and audit, structured source pointer and exact excerpt. Its verifier
flag is false. The audit identifies the local scripted replay with zero
scripted input/output tokens and a null cost.

**Kept in private receipts.** The separate A/B drafts, wire and response
digests, provider identity and reported usage, attempt records, HTTP
metadata and raw provider responses stay outside the native investigation
JSON. No separate A/B attestation exists in the stored schema. The fixture
clock proves the scratch path only. Real acquisition freshness, production
admission and billing were outside this replay.

## Reproduce offline

Use the saved local replay harness and the exact worktrees. Set
`BRIDGE_CHECKOUT` to `daf170c`, `SCRATCH_CHECKOUT` to `e878744`,
`RECEIPTS_DIR` to the private retained receipts and `EVIDENCE_DIR` to
the local replay directory.

```sh
bridge="$BRIDGE_CHECKOUT/benchmarks/phase6-offline-fixture-freeze"
scratch="$SCRATCH_CHECKOUT/benchmarks/phase6-offline-fixture-freeze"
PYTHONPATH="$BRIDGE_CHECKOUT/src:$bridge:$scratch" python3.12 -B \
  "$EVIDENCE_DIR/replay_retained.py" "$RECEIPTS_DIR" "$bridge" "$scratch"
```

The retained harness SHA-256 is
`f071b2dfaf246685a0c3592af352cdfa6e79163f9e4253e1bcc3e8cd1c2ce822`.
The aggregate result SHA-256 is
`b79948b0645a600e8285d6a80488238e2ec29259d462338fc449b835c1e3cf90`.
No raw provider response or service identifier is included in either file.
