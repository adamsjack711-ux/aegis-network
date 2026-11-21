# Independent h84 scratch-history review

**PASS for local integration** of `c4ac23cbaeff63e83a8bfc4c4ff3c9c1f903caf9`. The candidate adds three benchmark cases exercising the existing scratch admission interface with the original h84 fixtures. The independent replay used the expectations frozen at `8d1d568d277d53815fd7dc39ddc718efbaec7531`, scripted drafts, three separate disposable SQLite databases, and fresh read-only connections.

| Replay | Linked result | Scratch result | Persisted research rows |
| --- | --- | --- | --- |
| Complete Stage A and both Stage B references | Verified unaffected | Committed, then duplicate | 1 after each attempt, byte-identical investigation JSON |
| Complete Stage A and one Stage B reference | Refused for incomplete support | Held | 0 |
| Singleton Stage A with a complete Stage B draft supplied | Blocked at Stage A | Held | 0 |

Fresh history reported one current `research-consistent` result with both exact references. The original source spans are `/affected/0` at `[13,149)` and `/affected/2` at `[228,312)`. Both the source digest and each stored UTF-8 excerpt matched the frozen record. Reference precision and support coverage were both 2/2. Both holds left the current asset report empty.

Retrieval and evaluation used 2026-11-20 00:00:00 UTC. The independent replay supplied 00:00:01 UTC through the commit clock. The commit and retry each read it inside the SQLite transaction. Neither hold reached that clock. All three disposable databases were removed when their contexts closed.

All 141 Phase 6 benchmark tests passed with networking denied, including the candidate's three new cases. The review used no provider calls or deployment.

## Reproduce

Use Python 3.12 with the candidate test dependencies and a checkout of the exact candidate.

```sh
cd benchmarks/phase6-two-stage-independent
(cd seal && shasum -a 256 -c SHA256SUMS)
sandbox-exec -p '(version 1) (allow default) (deny network*)' \
  python replay_h84_scratch.py /path/to/c4ac23c-checkout
```

Compare the receipt, reference, and row-count fields across runs. The stored investigation digest can vary between fresh runs because the persisted result contains measured latency. Each retry is compared byte for byte with the first write in its own database.

[Observed results](offline-h84-scratch-candidate.json) · [Frozen expectations](preselection-h84-scratch.json)
