# Phase 4F native enforcement and recovery

## Scope and baseline

This branch starts at the approved Phase 4E integration commit
`ee739cacfaa3f81a0994b4d7802fd2943c067d86`. It changes the existing
native `TargetStore` and its disposable local fixture lifecycle. It does not
alter Phase 4E-B's separate marker target, signed ownership records, the
JetStream protocol, native T4/T5 appraisal, or production enforcement.
Shared contract changes require coordination with Main Astra and are deferred.

Phase 4E-D measured the native ownership-loss failure at
`1fff1c572a461adf7fc4bad057f092cb2f61f70d`: the first health probe
started while the durable rollout was still confirmed. The serving proxy
denied, but the monitor committed quarantine later. The separate B marker
target at `11ecb948de82ef094f4fc48261786ff7600d64de` also failed its
original ordering test because a `/read` installed the hold. B's later
target-owned watchdog at `79cd10a72aac169047f63fe137988ce881304f25`
passed its own local fixture. That result did not cover the native writer.

The Phase 4E final integrated run recorded 346 passes, a Trust fixture startup
error, and a Trust key-retirement admission failure among 348 cases. Both
affected cases passed in isolation. The broad exact-pin gate was therefore
failed, not treated as clean. The prior withdrawal reports measured a
pre-intake SIGKILL local denial near 30.5 seconds and a post-audit denial near
50 ms with its broker ACK still near 30.5 seconds. These are dry-run transport
observations, not native target hold times. The five-second all-agent reporting
gate remains **OPEN**.

The original Phase 4E defensive-validation oracle expected a restricted
canary at fence 1 and two open peers at fence 0 after lease expiry or retired
owner rejection, with only an effective HTTP denial before controller
rollback. On this branch the target-owned hold is already durable at fences
2/1/1 before any route probe. The inherited assertions failed against that
stronger state in the retained interrupted broad run
[full-local.xml](../benchmarks/phase4f-native/full-local.xml): two failures,
150 passes, 36 skips before interruption. The branch-local oracle now waits
for the hold and checks the persisted fences and unchanged observer snapshot.
The predecessor evidence and its original failure remain in Phase 4E.

## Writer changes

The identity-fenced native lab starts a target-owned watchdog when it enters
the fixture. Every 20 ms it checks the current native T4/T5 status and opens
the actual native SQLite writer transaction to check the installed ownership
generation and lease. On either locally established loss it
commits all target modes as `quarantined`, advances their fences, changes the
rollout to `recovery_required`, and records one audit row. It does this without
a serving request, observer, broker message, or controller recovery call. The
transition uses the same `BEGIN IMMEDIATE` lock as protected mutations and
ownership changes. A status-loss sample also latches a process-local deny
under a commit mutex shared with guarded mutations before waiting for the
SQLite writer lock. An in-flight guarded mutation that already holds this
mutex may finish first; the watchdog then establishes the latch and durable
hold. A writer that committed before the ownership cut precedes
the hold; after the cut or hold commits, the old generation cannot commit.
Ordinary fixture restart reconciles an existing hold before proxies open.
Same-generation ownership restoration does not change the held rollout or
target modes. The native target is single-use: it has no API to relax a hold.
A successor command with either the old approval or a fresh approval cannot
reopen this fixture. Authorized positive recovery in a new deployment needs a
separately reviewed versioned contract. B's higher-generation marker recovery
is not a native recovery proof.

Native proxy routes now use SQLite `mode=ro` and `query_only`. Observation
does not acquire a writer transaction, update the target, advance an audit or
alter the process-local outage flag on a read error. Effective route denial
still fails closed when local status or ownership is unavailable before the
watchdog commits. The response path makes a fresh read-only check before
sending a benign response, so a local owner transfer committed during an
earlier route snapshot closes that response. The monitor checks status and attempts the native hold
before requesting a health observation.

The existing plan digest binds the fixture, template, target inventory,
expected fences, evidence binding and owner assignment binding. The signed
command binds the plan, exact action, target, assignment generation, broker,
holder and nonce. The native writer checks those inside the protected
transaction. Phase 4F additionally rechecks the existing local start approval
or target grant after staging and before commit, and applies the earliest
plan, approval, command, ownership and rollout deadline at the final check.
The native T4 witnessed Mesh and mandatory-two T5 status guard remains the
positive authority; a shadow C status does not replace it. A late denial
rolls back the staged target effect, command receipt and success audit together.

## Results and reproduction

The exact-source full local run passed **325**, skipped 37 opt-in live cases,
and emitted one dependency deprecation warning in 213.94 seconds. Its raw
JUnit record is [full-local-final.xml](../benchmarks/phase4f-native/full-local-final.xml).
The prior focused native and withdrawal run passed **97**, skipped six live
cases, and emitted one dependency deprecation warning. Its raw JUnit record
is [focused-regression.xml](../benchmarks/phase4f-native/focused-regression.xml).
The opt-in disposable Docker priority, SIGKILL-before-intake,
SIGKILL-after-audit and agent-partition checks passed **3/3**. The two-broker
ownership and broker-replacement controls passed **2/2**. Their raw records
are [live-withdrawal.xml](../benchmarks/phase4f-native/live-withdrawal.xml)
and [live-broker-ownership.xml](../benchmarks/phase4f-native/live-broker-ownership.xml).
The new native writer cases cover idle loss before any observer request,
read-only independent observation, same-generation restore and restart,
transfer with a stale plan, final approval expiry, T4/T5 status expiry between
checks, and the remote-failure race after the final check.

Eight fresh disposable one-host ownership-loss trials and eight idle native
status-loss trials all found a durable hold in a separate read-only SQLite
connection before the first HTTP observer request. Hold readback after the
ownership cut ranged from 8.619 to 27.135 ms, with observer completion from
49.809 to 62.654 ms. Status-loss hold readback ranged from 6.820 to 28.418
ms, with observer completion from 49.131 to 69.998 ms. Each observer made 18
requests and left target, rollout and audit rows unchanged. The observed
latencies are samples, not a deadline or cross-host bound. Full individual
rows are in [idle-ownership-order.json](../benchmarks/phase4f-native/idle-ownership-order.json)
and [idle-status-order.json](../benchmarks/phase4f-native/idle-status-order.json).

From this worktree, with the repository Python environment and local socket
permission:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q \
  -p no:cacheprovider -o junit_family=xunit1 \
  --junitxml=benchmarks/phase4f-native/full-local-final.xml tests

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q \
  -p no:cacheprovider -o junit_family=xunit1 \
  --junitxml=benchmarks/phase4f-native/focused-regression.xml \
  tests/phase4d tests/phase4d_t5 tests/test_phase3c_pipeline.py \
  tests/test_phase4e_withdrawal.py tests/phase4e/test_withdrawal_delivery.py \
  tests/phase4e/test_defensive_validation.py

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests/phase4d \
  ../../.venv/bin/python scripts/benchmark_phase4f_native.py --fault ownership --trials 8 \
  --output benchmarks/phase4f-native/idle-ownership-order.json

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests/phase4d \
  ../../.venv/bin/python scripts/benchmark_phase4f_native.py --fault status --trials 8 \
  --output benchmarks/phase4f-native/idle-status-order.json

AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_PRIORITY=1 PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q -p no:cacheprovider \
  --junitxml=benchmarks/phase4f-native/live-withdrawal.xml \
  tests/phase4e/test_withdrawal_delivery.py \
  -k 'critical_lane_progress or agent_death or agent_partition'

AEGIS_PHASE4D_T3_LIVE=1 AEGIS_PHASE4D_LIVE=1 PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q -p no:cacheprovider \
  --junitxml=benchmarks/phase4f-native/live-broker-ownership.xml \
  tests/phase4d/test_ownership.py::test_live_independent_jetstream_leases_cannot_override_home \
  tests/phase4d/test_journal.py::test_live_broker_loss_and_replacement_reconcile_with_independent_archive
```

## ACK, cursor and 30-second lease investigation

`agent_runtime.process_message` commits a verified local audit before
`ack_sync`, and critical delivery rechecks the broker-local `IdentityLease`
before ACK. Its ordinary and critical consumers use stable deployment-derived
durable names. The separate critical repair cursor tracks withdrawal replay;
the canonical journal cursor and same-publisher high-water mark remain
ordered. None of those ACK or cursor operations binds the authoritative
`OwnershipHome` generation. A broker-local lease can remain valid while the
native target owner transfers. The target's own generation check prevents a
stale protected mutation, but stale ACK or cursor progress across transfer is
still an open transport contract. Generation-specific physical consumers,
generation-scoped cursor writes, and an all-writer barrier require a coordinated
versioned design and adversarial old-connection ACK tests before adoption.

Waiting for the 30-second broker lease is unnecessary for target-side denial
after locally established authority loss: the target watchdog latches a hold
from its own current ownership record. A separately authenticated and scoped
withdrawal receipt delivered directly to the target could also install a
deny-only hold before broker recovery, provided its provenance, scope,
anti-replay floor and persistence are independently verified. A stale or
unavailable T4/T5 status already blocks positive native authority at its
shorter deadline. Neither path lets an unauthenticated hint create an
event-specific tombstone or lets broker delivery grant positive permission.

## Achievable guarantee and remaining failures

The local guarantee is serialization: once a native writer transaction has
established ownership loss and committed its hold, later protected
transactions cannot use that generation. A remote failure immediately after
the final successful check cannot be atomically observed across machines.
One adversarial test pauses a writer after its owner check, attempts to fence
the owner, and observes that the home fence waits behind the writer's SQLite
transaction. The prior write can commit before the fence; the hold follows
the fence. A separate test makes a remote Trust status become invalid just
after the final local status check and observes that the in-flight local
transaction can still commit. The writer sees denial on its next check. A
failure in an independent remote machine between the last check and local
commit requires a bounded freshness lease or a remote barrier protocol to
limit that interval. No perfect remote-to-local atomicity is claimed.

Remaining gates: native generation-bound ACK and replay cursors; direct
withdrawal-to-target receipt proof; independently administered home, writer,
Trust and recovery anchors; cross-host clock uncertainty and partitions;
watchdog supervision when the target process is SIGKILLed or storage is
unavailable; a clean exact-pin broad suite; and the five-second all-agent
reporting result. The disposable local tests do not authorize production
enforcement.
