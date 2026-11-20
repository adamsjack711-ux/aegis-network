# Phase 4F-1 diagnostic results and handoff

Branch `feat/phase4f-recovery-protocol` starts at `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`. The [architecture proposal](phase4f-recovery-protocol.md) has no Main Astra approval for shared ownership/fencing or native Trust changes. Runtime ownership, lease TTL, ACK/cursor, protected writers and T4/T5 are unchanged. The existing 30-second broker lease is retained. This handoff is **NO-GO** for the five-second all-agent gate and autonomous enforcement.

## Retained original diagnostics

The read-only [retained score](../benchmarks/phase4f-recovery-protocol/retained-diagnostic-score.json) hashes each original input and leaves it untouched. Five historical one-agent pre-intake SIGKILL/broker-restart trials contain **10/10 dry-run agent-withdrawal pairs over 5,000 ms**, ranging **30,576.431–30,616.800 ms** from submit to committed audit stage. Both withdrawal types fail in every crash trial. Two historical alive broker-restart controls contain **4/4 pairs within 5,000 ms**. Each crash trace records 30 busy KV claim attempts before claim. These are seven distinct one-host diagnostics, not a 72-pair release sample. The original reproduction files remain at `benchmarks/phase-next-remediation/`, `benchmarks/phase4f-withdrawal-recovery/` and `benchmarks/phase4f-kv-recovery/`, with per-file SHA-256 in the score.

The frozen release denominator is **72 fault agent-pairs plus 18 healthy control pairs**, with 1,000 ordinary pending findings in each fault run. At this pin, **0/72 fault and 0/18 healthy pairs are full-oracle evaluable; all 90 remain unrun**. The historical traces have no native T4/T5 acceptance or target transaction observation, and their ordinary queues were smaller. The retained ten timing failures are diagnostic failures; they are not converted into ten full-oracle failures or passes.

## Fresh 1,000-row fault diagnostic

Raw [fresh trace](../benchmarks/phase4f-recovery-protocol/fresh-sigkill-1000.json), SHA-256 `7fe88cb631b9fff47a415f869690e72cefcc5b23f109cef2ef51d940c0b4b398`, is one disposable host, broker, database and dry-run agent. It uses a pre-intake SIGKILL, broker restart, independent revoker, mixed publisher-sequence withdrawal and **1,000 ordinary findings**. The critical lane durably denied both targets while **1,002 ordinary outbox rows remained pending**; the normal stream head remained at 2. A later separate SQLite read verified the two effective denied finding IDs. The trace's commit times come from the worker's monotonic stage log, not an independent read-only observation upper bound.

| Withdrawal | Submit → durable dry-run audit | Submit → confirmed ACK | Result against 5,000 ms |
| --- | ---: | ---: | --- |
| Independent revoker | **12,613.289 ms** | 12,615.270 ms | **FAIL** |
| Mixed publisher sequence | **12,599.589 ms** | 12,601.085 ms | **FAIL** |

Broker start returned at 233.750 ms after restart request. The successor had **12 busy claims and 13 attempts**, acquired KV at 12,493.583 ms, then received critical wire at 12,536.865 ms. The 1,000 findings were queued while the broker was stopped, before the worker SIGKILL; that elapsed time aged the old 30-second lease. The shorter 12.6-second denial therefore does **not** show a faster recovery protocol or a shortened lease. This one trial remains outside the full oracle because it has no native T4/T5 or target-fence proof, three-agent coverage, witnessed admission upper bounds or independent denial timestamp upper bounds. CPU/RSS were not sampled.

## Focused regression and adversarial checks

- Restricted first run: 31 passed, 1 skipped, **15 socket-bind errors** in local fixture tests; this was an environment restriction, not a code assertion. The same focused suite rerun with localhost socket access: **46 passed, 1 optional live-broker skip, 0 failed**. New checks cover the retained denominator, competing successor claims after a target-home fence, resumed stale-owner command rejection, restored target-home resurrection counterexample and the present generation-free critical cursor. They are diagnostic boundary tests, not v2 protocol proofs.
- [Live JUnit](../benchmarks/phase4f-recovery-protocol/live-adversarial.xml), SHA-256 `7b578b7ea1f61f3544b0bd820145551f12a6deb21837781cf7d226c9a8cecccf`: **3 passed, 0 failed**, 21 deselected. Existing C05 live cases exercised death before intake, death after commit/before ACK, partition/rejoin and independent two-broker KV leases. The pre-intake killed agent's denial was first independently observed at **30,430.388 ms** from submission; its pair fails five seconds. The post-commit agent already had a durable denial at 50.189 ms while ACK floor was zero, and replay kept one logical row. During partition the agent had no denial and ACK floor zero; after rejoin, denial was observed within 1,956.888 ms of rejoin. That rejoin-relative interval does not reset the submission timer and is not a five-second pass. The two-broker test shows the un-restored local target home rejecting an old signed command despite independent live KV leases.

These checks do not cover all nine protected routes, complete native withdrawal views, stale cursor/anchor restore in an approved v2 implementation, a physical multi-host deployment or the complete 72+18 matrix. A current counterexample test deliberately shows that restoring the unanchored target home can resurrect an old generation; a second shows that today's critical cursor can move without a denial commit or generation. No successor authority is granted from either.

## Reproduction

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. ../../.venv/bin/python scripts/phase4f_recovery_evidence.py --output benchmarks/phase4f-recovery-protocol/retained-diagnostic-score.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python scripts/phase4e_withdrawal_recovery_check.py . --authorize-local-lab --kill-agent --priority --ordinary-count 1000 --output benchmarks/phase4f-recovery-protocol/fresh-sigkill-1000.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. ../../.venv/bin/python -m pytest -q tests/test_phase4f_recovery_boundary.py tests/phase4d/test_ownership.py tests/phase4d/test_native_enforcement.py tests/phase4e/test_withdrawal_status.py tests/test_phase2c_hardening.py
AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_PRIORITY=1 AEGIS_PHASE4D_T3_LIVE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts:. ../../.venv/bin/python -m pytest -q tests/phase4e/test_withdrawal_delivery.py tests/phase4d/test_ownership.py -k 'C05_agent_death_on_both_sides_of_durable_commit or C05_agent_partition_holds_until_reconciliation or live_independent_jetstream_leases_cannot_override_home'
```

Local Docker and Unix socket access are needed for the live commands. No production targets, external agents or master merge are involved.
