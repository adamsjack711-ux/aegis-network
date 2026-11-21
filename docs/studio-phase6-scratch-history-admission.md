# Scratch-only two-stage history admission

This benchmark creates and removes its own SQLite databases. The CLI does
not accept an existing database, an external provider or credentials.
It verifies the frozen fixture manifest and the exact four cases at
`46b5566`. It leaves the normal Scout, Investigator, handoff and reader
entry points intact. [Previous history replay](studio-phase6-history-boundary-replay.md)

From the candidate checkout with the reviewed Python 3.12 environment:

```sh
base=benchmarks/phase6-offline-fixture-freeze
PYTHONPATH=src python3.12 -B "$base/scratch_history_admission.py" > scratch-results.json
PYTHONPATH=src python3.12 -B -m pytest -q -p no:cacheprovider \
  "$base/test_scratch_history_admission.py" tests/test_offline_research_handoff.py
```

The benchmark replays the exact scripted identity and version choices using
the linked two-stage checker and the native Investigator. On its scratch
writer it acquires `BEGIN IMMEDIATE`, reopens the current Scout revision,
checks the trusted recorded retrieval time against the seven-day cutoff
and runs the conservative Aegis appraisal and verifier. It requires the
stored applicability references and excerpt spans to match the selected
source bytes. It inserts one native private research row only when all
checks agree. The prototype owns the small insertion under that transaction
because the product writer starts its own transaction. The product schema,
writer and readers are unchanged.

| Control | Required scratch observation |
| --- | --- |
| Fresh h28 | One append, current affected with the exact `/affected/1` bytes. Repeat yields duplicate and preserves the original payload. |
| Stale h28, and expiry between evaluation and commit | Held with zero rows in both. The second read uses a fixed commit clock just beyond the cutoff. |
| Frozen h53 and separately advanced withdrawal | Held as conflict or withdrawn respectively. No additional result and unchanged saved payload. |
| h31 superseded after evaluation | A different asset digest makes the pending result's key absent. Real local evaluation returns affected, then a separate Scout connection supersedes the head before the write lock. Fresh reads see zero pending rows both before and after. The prior subject's payload survives with superseded status. |
| h62 mixed applicability | Standalone union affected and conservative Aegis conflicting. Hold with zero inserted rows. |

Each outcome uses a fresh read-only `read_history` connection and the precise
`read_asset_report` subject. Focused tests also refuse stale bindings,
invalid drafts, and duplicated source text that cannot retain the exact
selected spans. This proves the controlled SQLite and appraisal behavior
for scripted fixtures. The schema does not persist a separate two-stage
attestation, and wall-clock sampling, production admission and history
authority remain separate decisions.

## Freshness across a contended write lock

Run the pair separately from the fixed lifecycle replay:

```sh
PYTHONPATH=src python3.12 -B benchmarks/phase6-offline-fixture-freeze/scratch_history_admission.py \
  --lock-contention > contention-results.json
```

Both controls start with a determinate, eligible h28 evaluation at exactly the
seven-day cutoff. A separate SQLite connection holds `BEGIN IMMEDIATE` for at
least 150 ms after the admission writer enters its lock attempt. While the
lock is held, another connection observes `SQLITE_BUSY` and a fresh reader
sees zero rows. The injectable commit clock is sampled after the admission
writer obtains its lock. The trace includes that sample before the locked
snapshot recheck.

- In the expiry control, the clock advances one microsecond beyond the cutoff
  while the other connection still holds the lock. Admission rolls back
  without an insert. A fresh reader sees zero rows.
- In the fresh control, the timestamp stays at the cutoff through the same
  hold schedule. Admission writes one row. A retry returns duplicate, and
  the stored history stays intact.

Measured waits vary by scheduler. The date and cutoff are controlled fixture
values. Existing calls with a fixed evaluation or commit time keep their
previous behavior. This demonstrates transaction ordering and expiry under
real contention in scratch SQLite. It leaves production wall-clock trust and
admission policy outside this benchmark.
