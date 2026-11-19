# Phase 4E-C integration review

**GO for additive lab and shadow appraisal. NO-GO for binding 4E-C to the shared writer or releasing distributed enforcement.** The integration candidate retains the native T4 journal, mandatory-two native T5 appraisal, exact durable Rapid decision, local approval and native T3 ownership checks. The 4E-C package can run in that source tree as an additional assessor. The two paths confer different withdrawal guarantees.

## Reviewed revisions

| Surface | Pin |
| --- | --- |
| Approved Phase 4E baseline | `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f` |
| C isolated prototype and original verification | `f1692340b03521d44877b6ba4a2799db66a4576d` |
| A implementation and benchmark handoff | `4c6f674c1915ee255222f02c38c2e2c010421b1f` |
| B canonical durable latch implementation | `11ecb948de82ef094f4fc48261786ff7600d64de` |
| B independent latch review | `f77712ee388793dc96db44245a728a61992d0f86` |
| Shared implementation reviewed before the shadow import | `4c586bb61dcd2588bff9ab4d91fb605893029828` |
| Exact local candidate with C imported for shadow use | `4918dadacc8dedd96d1c4b506e5f746040a01941` |

The integration lead had recorded shadow-only intake in 4E-ADR-04C. The integration worktree showed an in-progress cherry-pick of C during this review and then advanced to `4918dad` with the `STATUS.md` overlap resolved by its owner. This review left shared files and Git operations untouched. The C protocol, appraisal and tests match `f169234` at that candidate. The A runtime and B identity-lab source also match their canonical handoffs. The subsequent integration pin `f16a46eb644a705b2ee750f151be6710381cf380` carries additional review and test artifacts with matching application source. [Original C contracts](phase4e-trust.md)

## Contract conflicts and integration blockers

| Boundary | Review finding | Required evidence before writer integration |
| --- | --- | --- |
| **C versus native T5 withdrawal coverage** | The native 2-of-2 Evidence path denies on split history after one of its required operators durably admits a withdrawal. In C, one of four witnesses can durably admit an Evidence withdrawal and stop answering fresh challenges while the other three still corroborate the earlier positive cut. Three matching direct admissions reach the current C coverage guarantee under its fault assumptions. A Mesh withdrawal received by A references a distinct native record and does not close this Evidence gap. | Retain mandatory-two native T5 for the writer or obtain approval for an independently validated equivalent denial path. Preserve durable partial-intake handling, withdrawal reserve and exhaustion holds. Recheck migration of existing denials and interruption across restart. |
| **4E-A delivery and 4E-C admission** | A preserves native signed Mesh events and applies exact local denial by target publisher, artifact UUID and canonical finding-body digest. Its PostgreSQL commit and HTTP 202, JetStream ACK, critical projection cursor and denial-audit write have their own meanings. C authenticates to each witness with a revoker- and key-bound credential and counts receipt votes over a tagged canonical wire digest and epoch. A's priority relay has no adapter to C direct intake or C inclusion proofs. C has an 8 KiB per-record and 256-leaf prototype profile, including eight reserved withdrawal slots. A's 256 KiB serialized event limit and pending-queue limits are different bounds. | Version canonical envelope conversion and stable event correlation across retries. Preserve exact signed bytes, denial precedence, ordered canonical replay and commit-before-ACK. Reconcile partial receipt formation, capacity, out-of-profile payloads, and missing paths without weakening denial. Verify separately at durable intake, quorum receipt, sealed inclusion and target readback. Retain A's historical crash reporting miss. |
| **4E-B ownership and 4E-C status** | B's mTLS marker service has its own enrollment, generation, fence/hold, command and approval signatures. C verifies trust scope and cut for an audience. Its one-use `VerifiedStatus` does not bind B's target inventory, action, generation, expected version or writer incarnation. There is no adapter from the B marker contract into the native target transaction, and broker-local A lease/ACK checks do not establish the B generation. | Establish a versioned exact review binding across action, claim and Evidence, history cut, deployment, authenticated owner, generation, enrolled writer inventory, expected target fences and deadlines. On every actual effect transaction, verify the independent trust input and generation before commit, with a durable interruption latch. Test partial barriers, earlier assignments, old sessions and restores of the home, target, audit and cursor independently. |
| **Freshness and writer transaction** | The prototype's 3,000 ms challenge and 20-second maximum cut age are independent of the shared writer's one-second refresh budget. A digest or transferable checkpoint vote alone cannot establish current scoped status. C's full replay and signed status are checked independently by publisher and reader. No tested adapter feeds its status into `EvidenceGate` and `TargetStore`. | Use the earliest applicable history, Evidence, plan, ownership, fence and credential deadline. Convert trusted UTC to local monotonic deadlines conservatively at each writer. Test cancellation, loss at pre-commit, and fresh evidence on reconnect. An old approval cannot resume an interrupted plan. Benchmark tails, including load at the reserved capacity and on the actual multi-host topology. |
| **Recovery and administrative domains** | C demonstrated one-host process and credential separation. Multiple service stores and keys are reachable by the same lab OS account and controller. The anchor can detect a stale dependent store while the anchor remains current. Neither the SQLite CAS nor role configuration establishes independently administered custody or prevents correlated restoration of the anchor. | Exercise ambiguous interruption between the witness write and anchor CAS, stale or unavailable anchors, and authenticated recovery through key-roster changes. Require verified independent administrations, restore domains and service identities on authorized multiple hosts before any distributed enforcement release. |

## Security assumptions to retain

Four pinned witness domains, quorum three, at most one Byzantine witness domain, trustworthy enrollment, bounded clocks and an independently retained current anchor. Two colluding witnesses can invalidate the quorum intersection argument. Declared domain separation alone cannot corroborate real custody. A relied-on missing or conflicting status, incomplete replay, expired approval or missing writer fence blocks new authority. A verified safe restriction may remain under its existing safety and expiry rules. A receipt does not prove inclusion or the absence of unpublished withdrawals.

## Validation ledger

The focused compatibility run from an archive of `4918dad` passed **60 tests** spanning the A priority unit and fault suite, B loopback mTLS marker fixture, C real Unix-socket services, inherited native writer and native T5. The shared-writer cases in this run used the ordinary native profile. The A priority tests exercised their own profile. This shows coexistence of the pinned interfaces. It leaves the combined effect path untested.

A separate live-socket probe against `f169234` verified the different receipt thresholds. A healthy scope first returned `reproduced`. With one durable revocation vote from `w0`, a fresh challenge still returned `reproduced` through the other three. Two additional admissions of the same bytes formed a quorum and the next refresh held before inclusion. Native T5's `test_independently_received_withdrawal_cannot_be_omitted` independently asserts `divergent-status` after one admission. This is the observed compatibility conflict.

The original C full default suite passed 278 tests, including nine C cases, with an inherited Starlette/httpx warning. Preserve the three opt-in Docker cases below as outstanding on the exact combined candidate. Equivalent tests on earlier source or local fixture checks do not retire this work.

| Outstanding Docker validation | Flag |
| --- | --- |
| Distinct processes and fault recovery | `AEGIS_PHASE4A_LIVE=1` |
| Independent JetStream leases cannot override ownership home | `AEGIS_PHASE4D_T3_LIVE=1` |
| Broker loss and replacement with independent archive reconciliation | `AEGIS_PHASE4D_LIVE=1` |

4E-D independently passed **15 shared-writer checks on each of `16e71ed` and `4918dad`**, including the healthy control, quorum loss, unresolved cut followed by an older cut, Evidence revocation after canary, exact intent, and stale ownership. Independent durable and route readback establishes these results for native T6, which the shared writer still invokes. D also passed the C Unix-socket probe twice at `f169234`, verifying receipt, scope and cut, mirror failover with three witnesses, denial with two, retained revocation after restore, and the original canary expiry. [4E-D shared-writer result](../../phase4e-adversarial/benchmarks/phase4e-adversarial/shared-writer-4918dad.xml) · [4E-D standalone C result](../../phase4e-adversarial/benchmarks/phase4e-adversarial/trust-C-2.xml)

The 4E-D challenge using the new services at the shared writer remains **blocked on wiring**. Promotion requires the exact candidate to invoke C with A's local denial input and B's authenticated fence. It must show independent durable readback, zero unauthorized effects, and continued restrictive recovery under the declared fault model.
