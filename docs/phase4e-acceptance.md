# Phase 4E-D acceptance criteria

These criteria were frozen against the approved intake pin `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f` before reviewing Phase 4E implementation. Phase 4C identified three High findings. 4C-01 concerns independent withdrawal coverage, 4C-02 concerns ownership across broker scopes, and 4C-04 concerns independent Evidence status. Phase 4D/T6 retained those release blockers alongside a five-second withdrawal reporting threshold miss and ordinary findings overtaking a queued withdrawal. The Phase 4D release checklist also requires authenticated roles, rollback-resistant anchors, and barriers across all writers.

## Invariants

1. An authenticated, in-scope withdrawal takes priority over ordinary findings already pending at the next dispatch selection. A previously in-flight publication may complete. From durable acceptance to the affected agent's durable denial, the inherited reporting ceiling is five seconds when the required services are reachable. Measure recovery separately from restored connectivity to durable denial with the same ceiling. During isolation, each protected writer loses authority at the earlier of its freshness deadline or lease expiry. Authority resumes only after independently proven current history. Preserve the original withdrawal and denial through restart and replay.
2. Every writer binds authorization to an authenticated owner and current generation from the enrolled authority. At most one generation can commit across brokers. Expiry, conflict, and restore ambiguity stop writes. A successor requires a durable barrier covering every enrolled writer, cursor, and acknowledgement lane. Retained generation and trust anchors must survive recovery independently of a restored snapshot.
3. Authority requires independently verified signatures and a fresh, consistent status cut bound to the exact Evidence scope and approval. Unknown, withdrawn, expired, contradictory, or unverifiable state denies positive authorization. The relying party retains an observed denial and monotonic status across restart. Unavailable coverage denies progression by the freshness deadline.
4. Each control transition requires exact, unexpired approval and current ownership, history, Evidence and target fences. An invalid or stale decision creates zero new restrictions. After a partial rollout, loss of authority prevents expansion. Affected targets stay restrictive through fault handling and recovery. Quarantine may be called verified only once independently observed at the recorded fence across the required inventory.
5. Combined faults must satisfy every applicable invariant. A passing fault recovery keeps denial state, uses fresh authority for any later activation, and never exposes a previously protected marker route. Restoring one dependency cannot substitute for the others.

## Test specifications

| ID | Scenario | Required independent observation |
| --- | --- | --- |
| W01 | Ordinary finding burst with a queued withdrawal | Durable admission order, first eligible dispatch, and affected agent's durable denial within the reporting ceiling. |
| W02 | Broker restart and delayed delivery | Retained withdrawal survives restart, is prioritized when offered again, and reaches the durable denial and replay cursors within the recovery ceiling. |
| W03 | Incomplete withdrawal coverage | Signed admission and independent history cutoff show a denial or missing proof. No new target writes after the accepted cut expires. |
| W04 | Long-disconnected agent | No authority before reconciliation with current history and trust across rotation. Durable tombstone and current cut survive reconnect. |
| I01 | Duplicate identity | Competing enrollment for the same deployment yields at most one authorizing principal. Compare signed home state and durable writer/ACK records. |
| I02 | Competing brokers | Observe authenticated principals on both broker scopes and one authoritative generation across all durable writer and ACK lanes. |
| I03 | Stale generation | Generation and durable write readback show zero writes or ACK progress under the previous owner after transfer. |
| I04 | Expired credential | A signed credential crosses expiry under controlled time. Independent target and audit show no new authority and hold by deadline. |
| I05 | Restored ownership snapshot | A separately retained anchor and all durable barriers prevent older ownership from advancing any writer or ACK lane. |
| E01 | Untrusted attestation signatures | An independent verifier check denies an unauthenticated assertion. No acceptable Evidence binding is issued. |
| E02 | Contradictory Evidence | Conflicting legitimate fixture observations for one scope deny appraisal. Durable records retain conflict across readback. |
| E03 | Withdrawn verifier key | Independently signed withdrawal persists across restart. Exact appraisal and later writes lose authority. |
| E04 | Stale and conflicting status checkpoints | Relying pins and independent signed-state inspection deny stale or conflicting heads with no advancement of target state. |
| E05 | Unavailable or untrusted witness | The required independent cutoff is unavailable or untrustworthy. Writable authority expires without silent reuse. |
| M01 | Stale authorization | Expired or superseded exact approval produces zero new writes at the target and durable audit. |
| M02 | Missing local authorization | A healthy, fully appraised plan without exact local approval leaves all target fences and audit unchanged. |
| M03 | Partial rollout | After canary-only activation, loss of authority leaves peer restriction counts at zero, with HTTP and audit agreeing on target fences. |
| M04 | Unsafe rollback | Recovery after observed protection preserves restrictive behavior, monotonic fences, and previous denials upon restart. |
| M05 | Quarantine failure | Missing independent observation prevents a recorded verified safe hold. Previously protected marker routes remain unexposed on reachable targets. |
| M06 | Protection during recovery | Continuous independent probes spanning the exercised recovery windows see no protected marker reopen, including after dependencies recover. |
| C01 | Broker crash and Evidence withdrawal | Separate transport and status faults overlap. Even if replay recovers first, independently withdrawn Evidence blocks expansion and prior protection stays restrictive. |
| C02 | Ownership transfer and stale Evidence checkpoint | Durable generation and signed status both constrain the writer. Reconciliation of either alone grants zero new writes. |
| C03 | Coordinator authority unavailable or untrustworthy during a partition | Independently witnessed coverage or deadline expiry blocks authority. Partition healing requires a current anchored cut. |
| C04 | Witness outage and actuator restart | Probe the already protected route during restart and afterward. Current signed status remains required for new writes and independently verified recovery. |
| C05 | Delayed withdrawal and agent recovery | Recovery under stale or missing status leaves the actor ineligible. Durable denial precedes any subsequent fresh authorization. |

## Decision rule

- **Pass** requires the stated independent observation, the healthy control for that path, and retained results tied to the exact candidate pin. A positive component response alone is insufficient.
- **Fail** requires observed violation with a usable oracle. Repeat each violation in a fresh lab to distinguish reproducible from single-observation results. Retain failed trials, including those followed by a pass.
- **Partial** records narrower executed evidence. **Blocked** records unavailable prerequisites or missing coverage. Both leave the full gate open. Inherited evidence retains its original pin and topology.
- **Critical** applies to independently observed unsafe activation or reopening at the tested protected boundary. **High** applies to loss of an essential authority, continuity, or isolation property. **Medium** applies to bounded service or observation gaps while safety holds. Environment and tooling errors carry no product severity.
- Distributed enforcement requires one pinned integrated Phase 4E revision, full scenario coverage, and evidence from authenticated and independently administered failure domains with durable anchors and writer barriers. Keep enforcement in the disposable lab while any required evidence remains open.
