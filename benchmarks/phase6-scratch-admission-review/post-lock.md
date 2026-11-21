# Freshness at SQLite write-lock acquisition

Independent offline replay passed on f07065ad786055fa5b9c4c3692e7d7c34beaf9a3. An independent harness used the same sealed h28 source, target, asset, retrieval time, preparation time and scripted drafts in two disposable databases. Both started with sequence 1 and the same current source digest. Only the value returned by the commit clock changed.

| Age returned by the commit clock | Observed wait from BEGIN attempt to clock sample | Receipt | Freshly read rows |
|---|---:|---|---:|
| Exactly seven days | 197 ms | committed | 1 current affected |
| Seven days plus one microsecond | 203 ms | held, stale-or-future-source | 0 |

A second SQLite connection acquired BEGIN IMMEDIATE before the admission. A trace on the admission connection signalled its own BEGIN IMMEDIATE attempt. The holder kept its lock for another 150 ms and checked the clock had not been called. At the sole clock callback, the admission connection was in a transaction and a third connection trying BEGIN IMMEDIATE with zero timeout received SQLITE_BUSY. This establishes sampling after acquisition in both runs. The clock values were injected. The measured waits are observations for these runs, not latency limits.

A separate mode=ro connection found the same sequence, digest and current status before and after both admissions. The public fresh history reader agreed with a fresh SQL research-row count in both cases. The accepted row referenced the same revision. This tests freshness at lock acquisition with fixture retrieval metadata. It does not measure acquisition age in a deployed system or freshness at WAL flush or physical commit completion.

The candidate's documented contention command also passed. The original fixed-time scratch suite reproduced aggregate SHA-256 b8d14e829758bccfaf48e0a51d62828a912793dfdc9324cdee0be19823bbaa7e. The retained h28/h53 replay reproduced b79948b0645a600e8285d6a80488238e2ec29259d462338fc449b835c1e3cf90. All reviewer runs denied network access.
