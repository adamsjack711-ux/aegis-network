# Phase 4E-A withdrawal delivery and recovery

The integration lead approved Phase 4D `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f` as the common baseline. Phase 4E-A is isolated on `feat/phase4e-withdrawal`. The priority profile is opt-in for disposable labs.

Phase 4D/T6 observed four ordinary publications ahead of a queued withdrawal on broker restart and one SIGKILL-path acknowledgement at 30.45 seconds. The broker held the identity until its 30-second lease expired. Phase 4E separates delivery and observation from that takeover interval. The historical five-second gate still includes every expected report and requires the missed crash sample to remain visible.

## Delivery and ordering

- With `AEGIS_PHASE4E_PRIORITY=1`, the coordinator splits the transactional outbox into separate dispatch loops. Findings keep `AEGIS_FINDINGS`. Withdrawals use a separate file-backed `AEGIS_WITHDRAWALS` stream and a distinct durable pull consumer per deployment. Findings can exhaust their broker quota or block their own dispatch without taking the withdrawal stream’s space or pull slots.
- PostgreSQL still commits the event, journal position and outbox row together. A dispatcher uses the original event ID as the broker deduplication ID and marks the outbox row sent after the publish confirmation. On an uncertain publish, retry uses the same signed envelope and event ID. Transport can redeliver after the broker deduplication window. Local verified decisions and exact denial keys remain idempotent.
- The canonical journal and `/v1/events` cursor keep their existing order and positions. Findings retain their original stream and publisher-order rules. The critical dispatcher queries pending withdrawals in canonical position order. Parallel publishers, coordinators, and redelivery can change when a withdrawal is observed. The priority consumer applies a verified denial immediately and records sequence ownership. In the priority profile, only complete ordered replay through that position promotes a withdrawal to the traditional publisher high-water mark. The lower-sequence ordinary findings admitted before it retain their normal appraisal unless the withdrawal targets them.
- The separate `GET /v1/revocations` repair cursor advances over withdrawal positions only. It can find a withdrawal after any number of ordinary rows, including withdrawals retained in PostgreSQL after broker retention expires. It commits the local audit before advancing its cursor. A replay-only recovery establishes local denial with no corresponding broker ACK. This coordinator projection has the same trust boundary as the legacy journal and cannot establish independently witnessed completeness.
- The HTTP response acknowledges durable intake. It does not attribute a local decision, a broker ACK, or an observation to any deployment. Critical worker logs distinguish the committed local denial from a confirmed broker ACK. The benchmark also uses a read-only SQLite connection and a separate reporter, which can observe a committed denial after the worker has stopped.

## Authorization, takeover, and capacity

The opt-in actuator profile requires independently witnessed Mesh history, independent Evidence status, an exact durable Rapid decision, local approval and current ownership and target fences. Signed delivery can add a denial for the exact publisher, artifact and digest. The guarded writer and loopback HTTP fixture read that durable denial independently of the broker acknowledgement. An inaccessible audit, lost local identity session, unavailable witness quorum or unavailable Evidence status holds authorization closed within the existing freshness rules. A broker delivery or lease cannot grant target authority. The witnessed and Evidence deadlines, signed approval semantics and target-generation transaction checks retain their Phase 4D settings.

The broker lease keeps its 30-second TTL. A lost or expired holder cannot recreate an absent lease. Renewals check the compare-and-swap revision and a conservative monotonic deadline. A fresh process must claim the identity after release or expiration. Critical delivery checks the current lease again after committing the audit and before requesting the broker ACK. A process that dies before commit leaves pending work for redelivery or replay. A process that dies after commit leaves a durable denial for the observer and an idempotent event for the next holder. A short network interruption can recover with the same current session. An expired session must exit and let a supervisor relaunch it. The separate T3 ownership generation still guards the actuator after any broker-side takeover.

The priority profile caps unsent ordinary and critical rows independently at 2,048 and 256. Full lanes reject new admission with HTTP 503 and `Retry-After`. The sender must retry with the same signed ID. Events larger than 256 KiB receive HTTP 413. The broker caps the ordinary stream at 64 MiB and the critical stream at 16 MiB with `DiscardNew`, 24-hour retention, a one-message pull and at most 16 unacknowledged critical deliveries per consumer. Critical outbox and repair batches are 16. Critical intake and replay each have an independent four-worker limit on coordinator thread use. PostgreSQL event history and local audit history are retained for replay and investigation. They require an explicit retention and archive policy before a sustained deployment.

## Cutover and rollback in the disposable lab

Set `AEGIS_PHASE4E_PRIORITY=1` consistently for the coordinator, worker and guarded fixture on an isolated lab. Stop old binaries before cutover. The first updated coordinator pins the profile in PostgreSQL after migrating its existing outbox and journal rows. Same-profile coordinator bootstrap leaves the schema and cursors alone. Updated coordinators starting in the other profile fail startup. Older binaries cannot read the profile pin and must stay offline during cutover.

For an offline rollback, put the guarded fixtures in independently verified safe hold. Stop intake and drain both outbox lanes, then verify that the canonical replay cursors cover the committed withdrawals for every retained audit. Stop every participant. Retain PostgreSQL, JetStream and audit volumes and their existing authority pins. The pre-4E binary recovers withdrawals already published to the isolated stream from the canonical journal. Do not purge either stream or rewind any history or generation. Before switching profiles again on retained disposable data, stop all participants, back up the lab, and remove only the `mesh_delivery_profile` table so bootstrap can pin the selected profile and backfill rows written by a pre-4E binary. Fixture transition back to service still requires its normal authorization and target fencing. The rollout is an offline coordination procedure.

## Verification and clocks

| Clock | Definition |
| --- | --- |
| Intake | Local benchmark starts the HTTP request. The HTTP 202 timestamp separately marks durable coordinator acceptance. |
| Receipt | Worker obtains the signed message from its durable pull. Journal-only recovery has a separate replay path. |
| Local denial | Independent read-only SQLite query observes the exact durable Rapid denial. A distinct actuator experiment times the loopback HTTP oracle across all three replicas and nine routes. |
| Durable ACK | Worker confirms JetStream acknowledgement after the audit commit and lease recheck. |
| Report | Independent benchmark runner writes and flushes the observed denial result. This uses a 25 ms polling interval. |
| Recovery | Kill-to-observed denial and kill-to-replacement-ready/confirmed ACK remain separate. Zero kill-to-denial means the durable denial existed at the instant of the kill. |
| Drain | Restart request to the last ordinary ACK, including broker reconnect and the intentionally slow consumer. |

Run only with the disposable cached Docker images and loopback bindings. The transport runs use two coordinator processes, one worker with a 3 ms per-finding delay, 1,000 findings from four publishers, and a withdrawal queued during a broker interruption. The crash arm uses two workers with separate SQLite audits. One worker is killed before withdrawal intake. The other stops at a barrier after committing its denial and before sending an ACK, then receives SIGKILL. The SQLite regression also kills a child inside the audit transaction after both inserts have executed. Recovery observes neither insert until a verified retry commits both. A separate live fault cuts only a worker’s broker link while the ordinary stream rejects new publications. An independent HTTP fixture test withholds the broker ACK while probing quarantine. The witness and Evidence status tests use temporary local stores and synthetic signing material.

```bash
PYTHONPATH=src python scripts/benchmark_phase4e_withdrawal.py --authorize-local-lab \
  --control-root ../phase4d --repeats 5 --crash --output /tmp/aegis-4e-live.json

PYTHONPATH=src python scripts/benchmark_phase4e_withdrawal.py --authorize-local-lab \
  --partition-only --output /tmp/aegis-4e-partition.json

PYTHONPATH=src python tests/phase4d/benchmark_native.py --withdrawals 12 \
  > /tmp/aegis-4e-fixture.json

AEGIS_PHASE4A_LIVE=1 AEGIS_PHASE4D_T3_LIVE=1 AEGIS_PHASE4D_LIVE=1 \
  PYTHONPATH=src python -m pytest -q -p no:cacheprovider
```

## Results

Five matched pairs ran on one arm64 macOS host with Python 3.15.2, Docker 29.5.2, NATS 2.10 and PostgreSQL 16. The control was the clean Phase 4D baseline. The candidate transport measurements were taken during development before the branch commit. Landed transport changes after that run were limited to legacy replay compatibility, legacy dead-letter ID compatibility, keeping critical reporting off the pre-ACK path, and removing an unused instrumentation hook. The final lab fault and full-suite runs exercised the candidate worktree. Percentiles are interpolated from five pairs and describe this workload.

| Transport measurement | Phase 4D p50 / p95 / p99 | Phase 4E p50 / p95 / p99 |
| --- | --- | --- |
| Intake to independently observed local denial | 4.098 / 4.956 / 4.980 s | 2.229 / 2.675 / 2.726 s |
| Intake to confirmed durable ACK | 12.368 / 13.874 / 14.167 s | 2.247 / 2.669 / 2.717 s |
| Intake to local denial report | 4.098 / 4.956 / 4.980 s | 2.229 / 2.675 / 2.726 s |
| Backlog drain | 11.771 / 13.267 / 13.559 s | 13.185 / 13.629 / 13.672 s |
| Worker CPU | 3.304 / 3.442 / 3.455 s | 3.680 / 3.942 / 3.982 s |
| Worker peak RSS | 62.89 / 63.21 / 63.22 MiB | 63.22 / 63.37 / 63.37 MiB |
| Two coordinators’ combined CPU | 12.341 / 12.750 / 12.807 s | 13.977 / 14.604 / 14.726 s |
| Higher coordinator peak RSS | 80.69 / 80.87 / 80.87 MiB | 80.83 / 81.03 / 81.07 MiB |

All 1,000 findings were acknowledged ahead of the withdrawal in each control run. The priority worker acknowledged the withdrawal first in all five runs. All findings were eventually acknowledged, and the observer found one authenticated withdrawal row per trial. The matched candidate-minus-control deltas for p50/p95/p99 were **+429/+648/+680 ms** worker CPU, **+1,727/+2,179/+2,268 ms** coordinator CPU, **+0.16/+0.50/+0.54 MiB** worker peak RSS and **−0.05/+0.46/+0.52 MiB** higher coordinator peak RSS. CPU includes setup, reconnect and full drain. Memory excludes PostgreSQL, NATS and the observer. [Matched rows and SIGKILL traces](../benchmarks/phase4e/mesh-live.json)

| SIGKILL recovery measurement | p50 / p95 / p99 across two fault samples |
| --- | --- |
| Crash to durable local denial observed | 15.195 / 28.871 / 30.086 s |
| Crash to replacement ready after claim and ordered replay | 30.373 / 30.380 / 30.381 s |
| Crash to confirmed ACK | 30.362 / 30.370 / 30.371 s |

The two crash samples represent different conditions. A kill before intake delayed the durable denial report to **30.383 s** after intake. When the audit had already committed, the report appeared in **55 ms** and the durable ACK arrived at **30.476 s**. Retained audits contained one logical withdrawal decision after takeover in both cases. The **five-second gate passed for the five connected priority workers in the matched workload, and remained unmet for all-agent reporting under SIGKILL**. Both crash ACKs crossed five seconds. [SIGKILL traces](../benchmarks/phase4e/mesh-live.json)

The asymmetric partition and full ordinary stream run confirmed one critical broker ACK in **1.910 s** from intake, with independently observed local denial in **1.923 s**. Its ordinary outbox row was still unsent at the withdrawal ACK and drained after quota was restored. Admission at the ordinary cap rolled back the event and outbox insert together. The live repository rejected the mismatched profile and allowed same-profile startup while an existing transaction held a journal read lock. The twelve native trials observed quarantine across all nine routes while ACK was withheld, in **50.983 / 56.492 / 58.401 ms** p50/p95/p99 from direct agent wire intake. That experiment bypasses coordinator and broker transit and includes two independent HTTP observation rounds. [Partition trace](../benchmarks/phase4e/partition.json) · [Fixture trials](../benchmarks/phase4e/fixture.json)

## Remaining risks

- Five seconds is unproven for every expected disappearing-agent report. Conservative takeover can take roughly 30 seconds. A live independent reporter can report a committed denial sooner, and an isolated actuator can deny on freshness loss. A crashed worker with no committed denial cannot attest an event-local denial. Fleet-level reporting of observable hold, agent unavailability, and delivery completion has no deployed service.
- File-backed JetStream and PostgreSQL share one host in this lab. Broker store replacement, failure across independent administration, lost authority anchors, and a durable fence across separately hosted target writers still need the Phase 4D release evidence. The broker checks are revision-scoped and separate from the ACK protocol. The target transaction’s generation fence remains the independent write boundary.
- Reserved delivery does not bound CPU, network, storage or locks shared below the two lanes. Shared saturation, the critical lane’s own quota, repeated lapses or long partitions can exceed the reporting budget. Coordinator replay polling cost at fleet scale and archive growth need measurement. Durable delivery under broker or coordinator data loss remains subject to the existing recovery and retention assumptions.
- The independent HTTP fixture uses separate readback from a disposable local proxy and local SQLite. A successful probe demonstrates local state for the enrolled routes. Multi-host actuation and reporting latency, external custody, and independence from a shared host failure remain open.
