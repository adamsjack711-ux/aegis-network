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

## Follow-up review of the authorization boundary

This review starts from A's `4c6f674c1915ee255222f02c38c2e2c010421b1f`. The opt-in stream, reserved admission, signed bytes, canonical journal and watermark, separate repair cursor, and audit-before-ACK contract remain the transport baseline. The five-second all-agent reporting gate stays **OPEN**.

On the native guarded fixture, `MeshIntake.fresh` checks the broker lease before and after witnessed Mesh refresh. `EvidenceGate.refresh` obtains independent T5 status only after those steps. `MeshIntake.withdrawal_clear` also closes eligibility if the critical task has stopped, the broker lease expired, or the exact withdrawal audit is unreadable. A controlled call at the reviewed pin confirmed that failure of the first lease check bypasses witnessed refresh entirely. Failure of the second discards the usable result even when witnessed refresh and exact scope checks succeed. Stopping the critical consumer also closes the target's readiness predicate. These are fail-closed paths. A fast NATS recovery remains necessary to refresh the current native positive path, and a crashed worker cannot attest an event it never durably received. The HTTP fixture is hosted by the lab process and a crash that also takes down its proxy leaves the independent observer without a verified target response. [Native intake and gate](../src/aegis/phase3c.py) · [Fixture lifecycle](../src/aegis/mitigation/lab.py)

### Repeat checks at the pinned implementation

Seventeen focused withdrawal and native fixture tests passed. One additional matched localhost trial repeated the 1,000-finding workload. All 1,000 ordinary ACKs preceded the withdrawal on the Phase 4D control. The priority worker ACKed the withdrawal first, with the denial reported at **2.396 s** and the ACK confirmed at **2.400 s**. A separate worker-link cut with the ordinary stream full reported local denial at **1.936 s** and confirmed the withdrawal ACK at **1.921 s**, while the ordinary row remained unsent.

The repeated SIGKILL experiment reported denial at **30.366 s** after intake when the worker died before intake. The after-audit case reported denial at **55 ms**, followed by broker ACK at **30.467 s**. All times are single samples on one physical host. The crash traces record durable Rapid state and ACK. They establish no independent actuator hold time. [Repeat restart and crash traces](../benchmarks/phase4e/safety-boundary-review-live.json) · [Repeat worker-link cut](../benchmarks/phase4e/safety-boundary-review-partition.json)

### Proposed lab experiment

| Component | Contract |
| --- | --- |
| Delivery worker | Keep the existing broker lease and commit-before-ACK check. The worker can apply a verified exact denial to its audit and repair from the projection. It cannot approve a target write, clear target quarantine, lower a writer floor, or advance a successor's authority-bearing state. |
| Target | Keep a single target-owned mutation path. The same transaction boundary serializes denial latching, transfer fences, and ordinary protected commits. A locally verified exact tombstone can trigger hold immediately. Unavailable or stale safety inputs remove eligibility by the earliest existing deadline, without waiting for NATS reclaim. A deny-only latch can suspend an active plan. It conveys no positive permission. |
| Positive authorization | Require a live exact owner assignment and writer incarnation, a signed intent and reviewed plan for the exact target and version, current witnessed Mesh with protected continuity, the exact local Rapid decision, mandatory independent T5 appraisal and a matching evidence binding. Check the minimum remaining expiry and installed fence at the effect boundary. Recovery holds until a fresh generation and all enrolled writer barriers are verified, followed by fresh exact approval. Any positive availability during a NATS outage needs independent evidence and review before an experiment permits it. |
| Observer | Independently verify serving denial on every enrolled route with the expected writer incarnation, generation and fence. Read the durable hold separately. Observer credentials carry no authority to install a fence, clear a hold or record an ACK. For a timing claim, prove the target transition can happen without an observer request triggering it. Record unreachable or ambiguous as unknown and retain it in the denominator. |

Broker recovery may finish after the target has verified hold. A pre-intake crash can therefore yield a verified **target hold** under a freshness deadline, with the **event-specific local decision and broker ACK** still pending. The hold is durable for that rollout across dependency reconnect. An authenticated publisher/UUID/finding-body digest tombstone persists across generations. Neither a fresh broker claim nor replay of a previous approval can clear either condition. A different target or a new subject requires its own enrolled scope and exact appraisal. If the target or independent observer is unreachable, retain an unavailable result alongside the sticky holds and durable decisions. This is a proposed separate actuator measurement, and does not replace the historical reporting gate.

### Cross-workstream contracts

- **4E-B** confirmed `11ecb948de82ef094f4fc48261786ff7600d64de`, with evidence at `330294e1326ab30fb1ade096b089d5c175d957cd`. The separate marker lab checks the authenticated exact home assignment against its anchor, target, installed generation and boot, signed intent, broker peer identity, separate exact approval, expiry, nonce and target version inside the actual writer lock. A held generation cannot re-fence. Only the authenticated home can install an exact target fence for a preparing higher generation. All writers must durably acknowledge that barrier before activation. The lab's observer read can cause the target to notice loss and latch its own quarantine during the read. That result establishes a target-owned durable hold for the exercised path; an idle or observer-independent hold deadline remains to be demonstrated. The marker protocol carries no native NATS ACK or cursor proof.
- **4E-C** confirmed `f1692340b03521d44877b6ba4a2799db66a4576d` as shadow-only. It uses three of four fresh nonce-bound views on a converged checkpoint, protected continuity, complete verified replay and separately signed and recomputed Evidence appraisal for the exact subject and audience. A stale or conflicted floor, incomplete proof, or unavailable required authority holds. One missing view can be tolerated when the other three converge. A withdrawal below quorum admission can remain unseen. Keep native T4 coverage and the two mandatory independent T5 operators on the writer, the existing one-second refresh budget and all shorter applicable deadlines. Do not transplant the shadow's three-second challenge or twenty-second maximum cut age into the active writer.
- **4E-D** independently tested A `4c6f674` and the combined build `4918dadacc8dedd96d1c4b506e5f746040a01941`. The crash and broker fault cases measured dry-run transport. Separate external HTTP and SQLite probes verified quarantine on the inherited native T6 writer. The combined adapter still needs an independent target-hold timing test.

### Independent crash and broker observations

The independent evidence is pinned at `1e378a5ce58b8f4176eb84072daa68c40ab96333` on `test/phase4e-adversarial`. The durations are first-observation upper bounds for individual faults.

| Dry-run fault | Independent observation |
| --- | --- |
| Pre-intake SIGKILL | Durable denial first observed at 30.434 s on A and 30.479 s on the combined build, measured from HTTP submission. |
| SIGKILL after audit and before ACK | Durable denial observed at 50.269 ms on A and 47.655 ms on the combined build. Independent broker ACK readback followed at 30.434 s and 30.477 s respectively. Each recovered worker in both crash cases retained exactly one durable decision row. |
| Agent-only broker partition | The worker showed no durable denial or ACK advance during isolation. After rejoin, the observer saw denial at 1.964 s and ACK at 1.968 s. |
| Broker restart with a full ordinary stream | The observer saw a durable denial by 1.658 s from the restart request. All four ordinary findings progressed after the capacity limit was lifted. |

Target state in these transport runs is **unknown**. The separate T6 probes confirm quarantine for their exercised writer faults. They do not bound target hold during the transport crash or partition. 4E-D also passed the receipt contract regression at `c1e5702202ad317396856ee4af89590e14a57a16`, whose patch matches A's `4af51b4` proposal. The **five-second all-agent reporting gate remains OPEN**. [Independent report](../../phase4e-adversarial/docs/phase4e-adversarial.md) · [Independent readback and JUnit traces](../../phase4e-adversarial/benchmarks/phase4e-adversarial/)

[Priority and crash traces at the original pin](../benchmarks/phase4e/mesh-live.json) · [Commit and serving checks](../src/aegis/mitigation/store.py) · [Existing witnessed continuity](../src/aegis/journal/client.py) · [Existing T5 writer appraisal](../src/aegis/trust_lab/native_evidence.py)

## Proposed verified transport-to-Trust adapter

Review pins are A transport `4c6f674c1915ee255222f02c38c2e2c010421b1f`, B writer fencing `11ecb948de82ef094f4fc48261786ff7600d64de`, and C shadow Trust `f1692340b03521d44877b6ba4a2799db66a4576d`. The proposal uses the existing native T4 Mesh and native T5 Evidence contracts for a future disposable writer trial. It introduces no activation or signed wire change.

### Match original records to independent proofs

1. **Identify the exact event.** Parse the original Mesh envelope with the existing native model. Preserve the signed payload bytes, signature and key ID. Correlate delivery by event UUID and verify T4 admission against `digest(envelope)` from `journal.protocol`, the canonical digest of the complete native envelope. A scoped v1.1 withdrawal names the target publisher, artifact UUID and SHA-256 of the canonical **finding body**. Repacking identical JSON does not change the native digest. An altered body, signature, key ID or target requires its own verification. A v1.0 revocation with no signed publisher scope cannot acquire scope from a header, cursor or lookup.
2. **Obtain receipt evidence without the coordinator.** The enrolled origin submits the original, signed envelope directly to independently authenticated witness endpoints under the pinned cohort, issuer and role. Each witness validates and durably records before voting. The native HTTP router's configurable authorization dependency must enforce the enrolled caller and operation. The relying target checks that three distinct enrolled witnesses voted on the same native `Admission(context, epoch, event)`, verifies the original envelope and historical revoker grant through `Policy.check_leaf`, and rejects future or uncertain admission coordinates under the configured clock bound. Verify with the policy that governed admission. A later properly reviewed replay can retain an authenticated historical denial after expiry; new admissions still require current grants.
3. **Discover receipts during an outage.** The proposed target-side reader polls a bounded, authenticated, witness-owned withdrawal admission feed or consumes an equivalent durable subscription directly. Preserve the original envelope and votes or retrieve them with the existing `HTTPWitness.admitted(epoch, event)` lookup. That lookup needs both coordinates and cannot discover an unknown event by itself. The independent discovery feed and its checkpointed recovery are missing from the current native path. Broker delivery and the coordinator replay projection can supply lookup hints. An empty feed, a local feed offset or a partial set of votes cannot prove completeness. Bound bytes, timeouts, pending work and fan-out independently of the finding lane. Out-of-profile records or exhausted required capacity leave proof-dependent eligibility held. The C shadow's tagged digest, 8 KiB record limit and 256-record history use a different policy context. Keep them scoped to the shadow profile.

### Decisions and durable ordering

| Input | Allowed consequence |
| --- | --- |
| PostgreSQL/HTTP 202, JetStream publish or consumer ACK, or either transport replay cursor | Record the corresponding delivery milestone. A keeps its existing scoped Rapid denial, priority dispatch and commit-before-ACK; witness latency stays off that path. None of these signals satisfies a proof or status check. |
| Matching verified native withdrawal receipt, before sealing | Record a sticky deny-only tombstone for the exact enrolled subject and hold a matching active target. Commit the verified proof reference, tombstone and observed hold under the target's existing effect transaction. The receipt establishes admission, with inclusion still pending. Any valid scoped denial already made by Rapid retains precedence. |
| Exact leaf included in a certified cut | Verify cut quorum and deadline, consistency from the retained floor, and the leaf's receipt, Merkle path and index. For positive appraisal, the native reader also verifies complete replay through that cut. One leaf cannot establish that the target is unwithdrawn. A missing merge proof at the native deadline is recorded separately. Later proof may resolve inclusion; it cannot backdate the observation or clear the tombstone. |
| Missing, invalid, contradictory, stale or rolled-back required proof, unreadable pin or incomplete replay | Block dependent positive authority and preserve verified denials. An unauthenticated hint or a partial receipt cannot create an event-specific tombstone. Record an unreachable target as unknown. Native T5 still requires both pinned operators; a C quorum or fresh signature does not substitute for them. |

Persist receipt progress before advancing a witness discovery cursor. Deduplicate the event by pinned policy context, UUID and canonical envelope digest, and retain distinct receipt epochs with the earliest verified outstanding merge obligation. An alternate digest for the same UUID or conflicting publisher sequence is contradictory, not a second valid transition. Scope denial by the exact target triple so a retransmission, late withdrawal or proof recovered from a mirror cannot erase a denial or repeat a holding effect. The early path does not advance A's canonical journal cursor, publisher high-water mark or B's writer floor. Those remain with ordered A replay and the designated home respectively. Restore requires continuity of the protected receipt and denial state; an older audit or unverified cursor cannot reopen a target.

### Positive authority and validation

Only the existing guarded writer can authorize an effect. Bind a versioned review of the exact action, target and expected fence/version to the original finding, verified current Mesh checkpoint, exact current Rapid decision, native T5 audience and exact cohort, claim, bundle, material and environment binding, active B assignment/generation and writer incarnation. Check the earliest applicable deadline and those bindings again in the actual effect transaction. The target re-reads the installed assignment, local hold and tombstone under that transaction. A matching withdrawal persists across owner changes. An obsolete generation, missing fence, incomplete writer barrier or old approval blocks positive effects. A held generation requires the home barrier for a fresh generation and new exact review before any recovered positive operation. An unprivileged receipt reader can provide proof material to the target's deny-only check, and cannot clear a hold, allocate an owner or acquire a writer capability.

The isolated receipt test re-packs a native withdrawal, verifies its quorum receipt before inclusion, rejects a valid altered target and an under-quorum receipt, and verifies eventual idempotent inclusion and denial. It deliberately confirms that the existing T4 reader holding only the preceding cut does not receive the early receipt automatically. The focused native suite passed 65 tests with four live cases deselected. The pinned C shadow suite passed nine private Unix-socket tests separately. The proposed combined trial still needs independent target readback during a broker outage, restore with a pending receipt, feed loss or saturation, stale-writer races and crash/rejoin. Record direct admission, receipt verification, inclusion, target hold, local audit, reporting and ACK separately. The historical **five-second all-agent reporting gate remains OPEN**. [Native contract test](../tests/phase4d/test_journal.py) · [Existing delivery regressions](../tests/test_phase4e_withdrawal.py)
