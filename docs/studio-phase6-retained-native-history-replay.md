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

From the clean integration checkout, use the reviewed Python 3.12 environment.
Set `RECEIPTS_DIR` to the operator's separate private receipt directory and
choose an output path outside the checkout. The directory must contain
`h28-two-stage-{A,B}.{attempt,http,response,transport}.json` and the equivalent
files for `h53`. The harness reads those inputs and creates its own temporary
database.

```sh
PYTHONPATH=src python3.12 -B benchmarks/phase6-offline-fixture-freeze/replay_retained.py \
  "$RECEIPTS_DIR" > "$OUTPUT_JSON"
shasum -a 256 "$OUTPUT_JSON"
```

Expected aggregate SHA-256
`b79948b0645a600e8285d6a80488238e2ec29259d462338fc449b835c1e3cf90`.
The repository contains the harness and synthetic fixtures. Keep the
original receipts, provider metadata and output in the operator's private
workspace.
