# Phase 6 history boundary replay

Replayed the four frozen expectations in
`46b5566:benchmarks/phase6-two-stage-independent/seal/oracle/lifecycle.json`
against the existing product writer and readers at `703d324`. All source and
target fixtures came from that freeze. The clock was 2026-11-20 00:00 UTC.
Each run used fresh disposable SQLite state under network denial. The original
writer received only the existing exact `ScriptedProvider`. No two-stage
result entered history.

| Frozen control | Observed existing path | Gap for two-stage history |
| --- | --- | --- |
| **h28 stale** · Hold, zero new rows | Scout accepted the snapshot with retrieval on Nov 10. Investigator detected staleness. `consume` committed one `current` row with reportable `unknown` and no structured citations. Both readers exposed it. | Freshness affects applicability, while the existing writer allows an unknown result. A new admission rule must hold stale snapshots before insertion. |
| **h53 withdrawn** · Hold, retain prior payload as withdrawn | Adding only the frozen withdrawal timestamp left `modified` unchanged. Scout emitted `conflict`; old and new consumes held, the prior row became `conflict`, and the asset report had no current result. In a separate control, advancing `modified` to the withdrawal timestamp yielded `held/withdrawn` and a prior `withdrawn` row. The saved payload was unchanged in both runs. | The exact freeze does not reproduce the expected withdrawal label. Keep the equal-time conflict as a held control. Use an explicitly advanced revision to test authoritative withdrawal under the existing policy. |
| **h31 superseded after evaluation** · Hold and retain prior payload | The existing `_commit` scheduling seam paused after real evaluation. A separate Scout connection committed the changed summary and newer modification time. The native transaction returned `held/superseded`. A fresh reader returned only the earlier payload, now `superseded`; the asset report had no current result. | The atomic revision guard is demonstrated for a native Investigation. The two-stage bundle still needs equivalent source and subject binding at its write boundary. |
| **h62 mixed policy** · Standalone affected, conservative history hold | Standalone B accepted the including row as `affected`. Under the same mutated source digest, native Aegis committed one `current` research row as `conflicting`, with no structured citations. The current report also showed `conflicting`. | Existing policy prevents a determinate affected report here. Existing persistence still inserts a conflict record. The candidate history path must hold disagreement with zero inserted results. |

`OfflineHandoff.consume` accepts the legacy scripted provider and validates an
`Investigation`. Its `BEGIN IMMEDIATE` insertion checks the current revision,
advisory and digest. Fresh `read_history` opens SQLite in read-only mode and
derives lifecycle status while preserving saved payloads. `read_asset_report`
filters by exact vulnerability and asset and returns the stored current check.
Neither reader re-evaluates freshness or interprets two-stage evidence.

The captured replay used the original APIs and a schedule-only barrier for
h31. Existing handoff and report regressions passed **18/18**. Retained local
evidence is in `/private/tmp/aegis-phase6-history-replay.BzOpKa`. From the
reviewed worktree, run:

```sh
evidence=/private/tmp/aegis-phase6-history-replay.BzOpKa
PYTHONPATH=src:benchmarks/phase6-offline-fixture-freeze python3.12 -B "$evidence/replay.py" "$evidence"
```

The captured `results.json` SHA-256 is
`3181736890bde8afa6384bdf01cf9d81749914de66f4d380520a66ea4615b31e`.

## Next scoped integration task

Prototype an explicitly invoked, scratch-only admission for one verified
scripted A/B bundle. Reopen the exact Scout snapshot and match the advisory,
asset digest, revision and selected byte spans. Under the same transaction
that would insert the private result, recheck current revision, trusted
retrieval freshness and conservative Aegis agreement. Require a supported
fresh determinate case to append one private row. Require zero new results
on h28 stale, h53 equal-time conflict and separately advanced withdrawal,
h31 supersession during processing, and h62 policy disagreement. Confirm
each outcome with a fresh read and compare prior payloads. Preserve the
legacy entry points and keep production admission behind separate review.
