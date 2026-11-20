# Independent acceptance of the offline handoff

**PASS** for candidate `9896de24ab4a78acd7897ca342247cf784dbfdcf`. The pre-implementation freeze is `41363d30999aeffec49da7f97639648dd5117a5b`. The independent challenge specification is in `independent-freeze.json`. I reviewed both private schemas, the final implementation, the source diff, the five recorded schedules, and the independent executions below.

**Publication boundary.** The worker does its last ordinary input read before running Investigator. It acquires the SQLite writer lock with BEGIN IMMEDIATE after preparing its result. Its conditional INSERT selects the exact sequence, content digest and advisory ID only when the latest event for the same source kind and advisory ID is current and the Scout current digest also matches. An incomparable conflict event suppresses currency even if the Scout current pointer stays on the preceding revision. The uniqueness constraint covers sequence, explicitly selected vulnerability and asset digest. Returning the receipt exits the connection transaction and commits before the caller receives it. The fresh reader uses one joined SELECT over that same state. The earlier draft and its source disposition have no separate current-publication path.

**Independent order checks.** In a WAL database I injected a withdrawal from a separate connection at SQLite's dispatch of BEGIN IMMEDIATE, after the last ordinary read and before the worker held the writer lock. An independent reader saw zero rows after the withdrawal committed, right before the worker committed its empty transaction, and after it returned a held receipt. I also attempted a withdrawal at dispatch of the final INSERT with the worker's writer lock already held. Scout got SQLITE_BUSY with zero busy timeout. The result committed, the withdrawal succeeded on retry, and the historical result payload survived. A fresh reader saw withdrawn. An open WAL read transaction kept its earlier snapshot until the transaction ended. In another schedule a second consumer committed the same item after the first prepared it but before the first acquired the lock. The first received duplicate and exactly one current row existed.

**Attribution and evidence.** The independent synthetic OSV record names test-wheel and explicitly lists version 1.2. An independently supplied asset with that exact identity and version yielded affected, attached to OSV-2099-2500 and the explicitly selected CVE-2099-2500. I checked the raw digest, source URI and exact byte range for the versions field. An unmatched asset yielded unknown. Archive provenance remained unverified with unknown redistribution. The investigation remained independently_verified=false. This is semantic adjudication of one synthetic positive and one identity mismatch. Reachability, real-world exposure and third-party publication authority are outside those labels.

| Exact-pin verification | Result |
|---|---|
| Independent WAL schedules including all five frozen orders, conflict, unrelated advisory, unknown selection, uncertain asset, archive and competing consumers | 11/11 passed |
| Independent incomplete applicability fixtures (empty package identity, empty exact version, empty OSV range events) | 3/3 held with zero results |
| Scout, Investigator, handoff and relevant Phase 5A pytest regressions under OS network denial | 63 passed, 0 failed, 0 skipped |

Both the implementer's five traces and the independent schedules use explicit boundaries without sleeps. The five implementer traces at `regression.log` show the requested reader-visible statuses, revision digests and commit/hold decisions. The independent traces at `independent-challenge-9896.jsonl` record actual SQLite statement boundaries and the second connection's observed commit ordering.

**Assumptions.** Writers and readers share one intact local file with trustworthy SQLite locking, schema and Scout-managed records. A withdrawal here is an effective newer material revision, or a same-time conflict hold. An older archived source retained without a state change cannot redefine current history. Consumers retry lock contention using the same input identity. Fresh statements observe committed state, while already-returned copies and preexisting snapshots describe an earlier cut. Current denotes source revision currency at that cut. The result remains private unverified research.

Reproduction from the candidate root on the recorded macOS host, using the existing local Python environment and the evidence scripts:

```sh
export PYTHONPATH=src:scripts PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
profile='(version 1)(allow default)(deny network*)'
/usr/bin/sandbox-exec -p "$profile" ../../.venv/bin/python benchmarks/offline-handoff/independent-challenge.py
/usr/bin/sandbox-exec -p "$profile" ../../.venv/bin/python benchmarks/offline-handoff/independent-incomplete.py
/usr/bin/sandbox-exec -p "$profile" ../../.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_phase5a*.py tests/test_threat_scout.py tests/test_offline_research_handoff.py
```
