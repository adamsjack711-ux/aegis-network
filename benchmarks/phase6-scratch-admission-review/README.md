# Scratch admission verdict

**PASS** at `e87874463d8f771afeba3063b33bcba84bdad9d2` for the disposable SQLite prototype. The independent caller used the four original cases from `46b5566`, the actual linked A/B checks and the candidate's scratch writer. The CLI transcript matched the developer's capture in every field except measured latency. An independent rerun of scratch and handoff tests passed 24/24 under network denial.

| Case | Receipt | Total saved results, before → after |
|---|---|---|
| Fresh h28 | Committed current affected with exact /affected/1 span; retry duplicate | 0 → 1 |
| Stale h28 | Held as stale | 0 → 0 |
| h28 crossing seven-day cutoff | Held at simulated commit time, one microsecond beyond cutoff | 0 → 0 |
| Frozen equal-modified h53 | Held as conflict | 1 → 1 |
| Newer-modified h53 withdrawal | Held as withdrawn | 1 → 1 |
| h31 superseded before write | Held as superseded | 1 → 1 |
| Mixed h62 | Held for conservative-policy disagreement | 0 → 0 |

The observer saw a pre-lock source read, BEGIN IMMEDIATE, a second source read within the transaction and then the insert for fresh h28. A separate connection could still read zero results and received SQLITE_BUSY when it tried to acquire the writer lock before that insert. After commit a fresh mode=ro connection saw one row. Each hold tested here rolled back without issuing an insert. For the three head changes, the independent caller committed the revision through another Scout connection after examining the evaluated native result and before the lock. Each pending subject had an unused uniqueness key. Fresh reads confirmed zero pending rows, exact equality of all saved investigation bytes and only the expected status change on the prior row.

This demonstrates the tested revalidation and insert share one SQLite write transaction. Freshness uses the caller's recorded retrieval and supplied commit clock. The benchmark does not test a trusted wall clock across real lock waits or authenticate the source's acquisition time. The stored row uses the existing private investigation schema without a separately persisted stage attestation. The product tree remained identical. [Independent receipts and trace](observed.json) · [Replay caller](review.py)
