# Offline Scout to Investigator handoff

**Candidate** 9896de24ab4a78acd7897ca342247cf784dbfdcf on feat/offline-research-handoff. Baseline fc4a17bc6f9f0c289a645c4fb7006c999ba90e99. Freeze 41363d30999aeffec49da7f97639648dd5117a5b predates the implementation. The two original private schemas are unchanged.

## Using the handoff

Initialize a local file with ThreatScout(path) and ingest caller-supplied snapshot bytes. Its committed ScoutEvent.sequence is the queue item. Open OfflineHandoff(path) in the consumer and call consume(sequence, vulnerability_id, asset, scripted_provider). Supply the asset independently, and explicitly select a vulnerability ID. A receipt reports committed, duplicate or held. Read history(source_kind, advisory_id) to obtain research with its current revision status. Close each connection when finished. The caller drives pickup and retry. No background worker or external service is required.

The consumer pins the raw digest, re-normalizes the original snapshot, checks claim membership and exact references, runs the existing offline Investigator and verifies the resulting input binding and excerpt bytes. One key comprises the Scout sequence, selected ID and digest of the supplied asset. Duplicate deliveries may repeat computation but cannot add another row for that key. The output includes its original source URI, revision, acquisition and redistribution labels. Only the scripted fixture provider can enter this workflow. A current row can still contain an unknown assessment. Every stored candidate remains research-only and independently_verified is false.

## Transaction order

* Effective withdrawal is the COMMIT in which Scout advances its current revision to the withdrawn advisory. An incomparable material change produces a conflict event that also blocks publication. Older archive bytes retained without advancing Scout state do not constitute an effective withdrawal.
* Investigator works outside the write lock. Its final transaction starts with BEGIN IMMEDIATE. The INSERT ... SELECT tests the exact sequence, source digest, advisory ID, current pointer and latest source-key event under SQLite's single-writer lock. The public receipt is returned after transaction exit commits. A competing withdrawal either commits first and the insert selects zero rows, or waits/retries and invalidates the already committed result at its own commit.
* A history read obtains both payload and status in one SQL statement. Once withdrawal commits, fresh reads see withdrawn; earlier snapshots or previously copied responses retain their as-of-read meaning. The historical research payload stays intact. Current describes revision currency, not continuous re-evaluation of Investigator's age policy.
* Assumes trusted local processes using the normal Scout and handoff APIs, one connection per worker, a shared file with reliable SQLite locks and ordinary committed reads. Busy/IO/commit failures propagate; callers retry by exact key. Local storage tampering, database rollback, external replicas, long-held read snapshots and previously exported copies are outside the visibility guarantee.

## Results and reproduction

The five ordered traces, including committed event sequence, revision digest, read outcomes, and selected evidence bytes, are in [schedules.json](../benchmarks/offline-handoff/schedules.json). For OSV-2099-1 revision 1 the golden checks resolve CVE-2099-0001 to the supplied PyPI asset at 1.5 and verify the original fixed-version quote at byte offsets 109–122. The fixture's withdrawal is revision 2. The five outcomes were one current result, zero before pickup, zero after interrupted processing, one historical withdrawn result, and the same historical row after replay and restart.

Run from this evidence checkout with its preinstalled environment on the local macOS lab host:

```sh
export PYTHONPATH=src:scripts
PY=../phase-next-six-astra/.venv/bin/python
profile='(version 1)(allow default)(deny network*)'
/usr/bin/sandbox-exec -p "$profile" "$PY" -m pytest -qs tests/test_offline_research_handoff.py tests/test_threat_scout.py tests/test_phase5a*.py tests/intelligence_phase5a1
/usr/bin/sandbox-exec -p "$profile" "$PY" benchmarks/offline-handoff/independent-challenge.py
```

The relevant regression logs record 63 plus 5 passes, with zero failures or skips. The independent schedules use separate SQLite connections, actual writer lock boundaries and a separate synthetic source. Review evidence is retained under [benchmarks/offline-handoff](../benchmarks/offline-handoff/).

**PASS for the offline handoff.** The combined run passed 68/68. Independent validation passed 11 forced WAL schedules and three incomplete-input controls. The reviewer also reran 63 relevant regressions. The independent checks exercised both sides of the write lock, distinct consumers and a prior read snapshot. [Independent verdict and reproduction](../benchmarks/offline-handoff/independent-review.md).
