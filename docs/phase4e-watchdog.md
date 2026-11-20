# Phase 4E-B proactive ownership-loss quarantine

This follow-up covers the two disposable 4E-B marker writers. Phase 4E-D's independent evidence at `e64bd4d639d9dfd25646650c6a988c7ab0e57718` records the original 4E-B and native ordering failures. The proactive result applies to the B marker fixture at the new pin. The native writer at `1fff1c572a461adf7fc4bad057f092cb2f61f70d` retains its independent **FAIL** disposition.

## Authority and mutation ordering

Each target starts a local watchdog when its process starts. At 50 ms intervals, the watchdog reads the installed fence from SQLite and appraises the exact target and assignment through authenticated Home RPC `/authority`. TLS verifies the pinned Home URI. The Home verifies the target URI, exact deployment, broker assignment and generation against its authoritative database and separate continuity anchor. An exact preparing state is kept closed to positive writes and can continue through the existing fence barrier. An expired assignment, rejected check, failed dependency check, or restart of a writer with an active fence causes a deny-only transition. The watchdog uses a 250 ms timeout per socket operation. Socket scheduling, lookup and SQLite can increase elapsed time.

The target first registers the detected loss under a local mutex shared with protected commit. It then latches the generation and quarantines the marker in the same `BEGIN IMMEDIATE` transaction used for protected marker changes. The detected loss and prepared timestamp are stored with the fence. The marker update leaves existing protected command receipts intact. There is no broker request, recovery callback or serving request in this trigger. The serving `/read` route uses a read-only SQLite connection. If the stored marker is observing, it verifies current authority and checks for a local loss before returning effective state. Readback may report effective quarantine before the durable transaction becomes visible.

A protected write stages the marker and receipt under the writer lock, checks current authenticated authority before commit, then checks the local deny state and earliest credential, command, approval and lease deadline under the commit mutex. A failed check rolls back the staged marker and receipt. SQLite writer commit refuses to wait behind a busy reader. An expiry or an already accepted loss cannot authorize a new commit. The existing generation, target version, exact approval, instance and broker checks remain in the write path.

An explicit Home retirement of a live anchored generation now collects exact target-specific durable deny receipts from every writer before publishing vacancy. It leaves the old generation current if any receipt is missing. An already closed writer stays held on retry. The Home does not hold its SQLite lock while requesting target barriers. A higher generation still requires the complete existing activation barrier and a fresh exact approval before a positive write. Returning connectivity, replayed commands or approvals and same-generation refencing cannot reopen a hold.

The two new RPCs are private fixture contracts. `/authority` is for the enrolled target named in the fence. `/retire` is for the enrolled Home and seals only the exact locally installed fence. Coordinate shared contracts separately before adoption. The native Mesh, Mitigation, T4/T5, and broker ACK paths are outside the marker adapter. Lease duration stays at the existing 30 seconds in the normal profile. The expiry trial uses the existing two-second test profile. Lease duration provides no substitute for per-writer fencing and an anchored single Home.

## Security assumptions and remaining limits

The measured trigger is a target's authenticated observation of loss or its local expiry. A physical remote failure between the final successful authority response and the start of SQLite commit cannot be detected instantaneously by an asynchronous client. An already-started commit cannot be recalled on a remote event, and a short failure between polls may escape detection. Scheduled live retirement orders the deny barrier before revocation, so it does not have that remote-cut ambiguity. The local pre-commit deadline does not bound a suspended process, arbitrary filesystem latency or clock error. Physical multi-host validation, measured clock uncertainty, watchdog process supervision and independent storage custody remain release gates.

The fixture assumes protected target and Home files and process identities, a trustworthy anchor outside the Home restore set, and working local SQLite durability. A stopped writer cannot persist a hold until restart. Its new boot blocks the old fence, and the watcher checks active ownership and latches on restart. An unavailable or locked durable store can delay holding but limits writes through the local guard and store error. Correlated restore of every authority domain and a privileged local writer remain outside the model. Independently governed Evidence and journal enforcement still apply to the native path.

## Measurements

The measured implementation is `79cd10a72aac169047f63fe137988ce881304f25`. All 18 trials began with an approved committed marker on each target. In the eight anchor-loss trials the former broker was stopped first. In all trials, separate SQLite readers confirmed that both target writers had durably quarantined before an observer process issued any serving request. Both serving requests then reported quarantine without changing the database. Each writer retained exactly its one pre-loss command receipt. [Raw timing and readback](../benchmarks/phase4e-watchdog.json)

The table reports nearest-rank p95 on one arm64 macOS host. Anchor-loss time starts at the stop request. Expiry is projected from a paired wall and monotonic sample. Retirement starts with the operator request, including the anchor query. Individual target samples include both writers. The both-holds row is the slower writer per trial.

| Stage | Anchor loss, 8 trials | Lease expiry, 4 trials | Authenticated retirement, 6 trials |
| --- | ---: | ---: | ---: |
| Target accepted loss | 53.141 ms | 29.078 ms | 14.502 ms |
| Target observed durable commit return | 53.974 ms | 30.018 ms | 15.150 ms |
| Both durable commits returned | 53.974 ms | 30.018 ms | 15.150 ms |
| Independent SQLite confirmation | 55.190 ms | 31.758 ms | 22.149 ms |
| Target report emission | 53.982 ms | 30.035 ms | 15.162 ms |
| Observer confirmed serving denial | 283.014 ms | 271.425 ms | 312.454 ms |
| Home received target retirement receipt | N/A | N/A | 15.493 ms |

The independent serving observer started after both database confirmations. Its measured interval includes interpreter startup and mTLS and provides an upper bound on the first observed denial. `observed_ns`, `detected_ns` and `prepared_ns` distinguish when a check returned loss, a local commit mutex accepted the loss, and the hold was prepared. `commit_observed_ns` measures return from commit and `report_ns` marks log emission. The retained SQLite reads independently bound durability. The Home receives target retirement receipts from authenticated writers after commit. Broker ACK timestamps are N/A because the hold never uses a broker flow. Successful protected writes before fault injection took 19.155 ms p95 across 36 requests. These were isolated immediate-refusal, expiry, and orderly retirement trials. A network black hole, loaded hosts, or storage stalls remain outside the measured timing.

Clean recovery at the same generation preserved both holds. Stale approvals and former-owner commands failed at the writer. Fresh approval in a later fenced generation restored only the intended marker. Additional transaction tests staged a marker and receipt, induced failed final authority or a concurrent local deny signal, and verified both artifacts rolled back. A separate read-only observer probe while the writer lock was occupied reported effective denial and left the durable state unchanged.

## Reproduction

All 290 regression tests passed with local live modes enabled, including 18 focused identity tests. The five selected ownership-loss, expiry, retirement, partial-transfer restart and broker-loss cases also passed in separate Docker network namespaces. The full run recorded the inherited Starlette/httpx deprecation warning. [Retained test results](../benchmarks/phase4e-watchdog-tests.json)

Run from the B worktree using its project and test dependencies.

```sh
AEGIS_PHASE4E_LIVE=1 PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  ../../.venv/bin/python -m pytest -q -p no:cacheprovider tests/identity_lab

AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_TOPOLOGY=docker PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  ../../.venv/bin/python -m pytest -q -p no:cacheprovider tests/identity_lab \
  -k 'lost_anchor_latches or lease_expiry or live_retirement or target_restarts_during_partial or broker_loss_and_reconciliation'

AEGIS_PHASE4E_LIVE=1 PYTHONDONTWRITEBYTECODE=1 \
  ../../.venv/bin/python scripts/benchmark_phase4e_watchdog.py --output /tmp/phase4e-watchdog.json
```
