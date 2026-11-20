# Independent offline handoff validation

Verdict: **PASS**

- Tested commit: `9ba94a84fd54ea9052d09e0c73bb6c365cbd5d5d` (detached worktree).
- Frozen evidence commit: `597dfc8385e5f78be837ab0f4d8a0db7d8ecb1c9`.
- Runs used macOS `sandbox-exec` with `(deny network*)`, Python 3.15.2 and SQLite 3.54.1.
- The integration branch was resolved to the tested commit and was not moved.

| Frozen case | Fresh reader result | Outcome |
|---|---|---|
| Normal handoff | `current` after result commit; one row after duplicate delivery | PASS |
| Withdrawal before pickup | No row after withdrawal and held pickup | PASS |
| Withdrawal during processing | No row after withdrawal committed before the worker's `BEGIN IMMEDIATE`, immediately before the worker transaction commit, or afterward; worker held | PASS |
| Result committed before withdrawal | `current` after result commit, then one historical `withdrawn` row after withdrawal | PASS |
| Replay after restart | Historical row remains `withdrawn`; both replay attempts held and no new current row | PASS |

The separate-connection writer-lock challenge attempted withdrawal when the worker dispatched its final INSERT. Scout received `SQLITE_BUSY` while the worker held the lock; the result committed first, then withdrawal committed on retry. A fresh reader saw `withdrawn` and the original research payload was preserved. An existing WAL read snapshot retained its earlier `current` view until its transaction ended. The opposite order injected withdrawal at `BEGIN IMMEDIATE` dispatch, before the worker took the lock; a separate reader saw no row both before and after the worker's held result.

The frozen challenge harness passed all 11 schedules. The incomplete-applicability controls passed 3/3 with held receipts and no visible rows. Relevant regressions passed 63/63 and Investigator regressions passed 5/5, with zero failures or skips.

Raw evidence: `challenge.jsonl`, `challenge.stderr`, `incomplete.log`, `regressions.log`, and `intelligence-regression.log` in this directory. Exact frozen inputs and harness copies are alongside them.
