# Phase 4E independent pre-observation enforcement

**Safety gate FAIL.** The native ownership-loss path did not establish durable quarantine before the first observer probe. The isolated 4E-B marker target also failed this gate. Its first `/read` latched quarantine during the outage. Later denial and successful recovery tests do not satisfy the ordering requirement.

| Subject | Exact tested commit |
| --- | --- |
| 4E-B mTLS marker target, run from a Git archive | `11ecb948de82ef094f4fc48261786ff7600d64de` |
| Native Phase 4E integrated writer, monitor and serving proxy | `1fff1c572a461adf7fc4bad057f092cb2f61f70d` |

The native trials used the integrated fixture with signed Mesh and Evidence records, local status fixtures, T3 ownership, and live loopback HTTP proxies. The B trials used the separate mTLS brokers, ownership home, anchor and marker targets. These were disposable one-host trials. The validation harness used the original writer implementations and fixture entry points. Its sole native observer hook sampled the committed database and recorded the first internal probe without changing the probe or recovery behavior.

## Ordering results

Every authority-loss arm ran twice with fresh state. The healthy controls first confirmed positive marker state on B and checked native restricted marker routes and healthy benign routes. At fault injection all serving probes were withheld until the scenario's first recorded request. SQLite inspection used separate `mode=ro`, `query_only` transactions. Once authorized to observe, the independent native HTTP subprocess received loopback addresses only and issued GET requests.

| Scenario | State before the first post-loss probe | What the probe and recovery showed | Gate |
| --- | --- | --- | --- |
| B anchor outage | Both targets still held their prior observing marker with `held=false` after 501–505 ms. | Target A's first `/read` returned quarantine and persisted the hold. Target B remained observing. When the same anchor returned, A stayed held and B still served observing on its first request. B's exposed marker view provides no side-effect-free HTTP oracle for this exercise. | **FAIL** |
| Native ownership loss, monitor idle | At about 503 ms the durable state was still `confirmed` with all three targets restricted at fence 1. | The independent first GETs returned HTTP 503 for all nine routes at the old fences. A read-only snapshot after the GETs showed the same target rows and audit. Durable quarantine came later through the monitor. | **FAIL** |
| Native ownership loss, monitor running | The first internal health probe started 59–61 ms after authority changed. Its pre-request SQLite snapshot still showed `confirmed` and fence 1 on all three writers. | The health probe expected HTTP 403 but saw HTTP 503 at fence 1. The monitor then committed quarantine and verified it at fence 2. The separate GET-only observer verified all nine routes and left target state unchanged. | **FAIL** |
| Native Evidence outage, monitor running | The `quarantined` audit row, incremented fences and restrictive modes were already committed when the first internal recovery probe started, 57–59 ms after the cut. | All nine routes returned HTTP 503. The monitor reached `safe_hold` after its checks. The separate GET-only observer verified the same denial without changing the database. | **PASS for this ordering arm only** |

The native serving proxy denied access even before the ownership-loss hold was durable. The first health probe exposed that denial and the monitor persisted the hold afterward. In 4E-B the observer request itself changed durable marker state. The Evidence-outage arm shows that pre-observation commit is possible on the native monitor path. It does not cover ownership loss.

The traces retain authority-cut intervals, request starts and completions, SQLite snapshots and the native audit clock. An audit timestamp is taken inside the transaction. The first external SQLite snapshot that contains that row bounds when the commit became visible. Durations are from one monotonic host clock. Two runs establish reproducibility for these fixtures and provide no failure-rate or latency guarantee elsewhere.

## Recovery and serialization

- **4E-B.** Same-generation anchor recovery kept target A latched. An observer credential could not fence the target. After retirement and activation of a higher generation, both writers rejected direct former-broker writes and successor commands paired with old approvals. Approved successor writes then committed with fresh exact approval. In a second outage, an observer read and a correctly signed command both waited behind the same target's independent SQLite `BEGIN IMMEDIATE` lock for 105–106 ms. The database remained unchanged while locked. On release the durable hold and quarantine appeared together and the protected receipt count stayed at one.
- **Native.** After the durable hold, both the former assignment and the replacement using the old plan and approval failed in the writer path. Restoring Evidence and restarting the native fixture left all nine routes in quarantine. A separate serialization control queued the actual local quarantine transaction and an eligible peer write behind a target SQLite writer lock. Neither changed state during the 65 ms measured lock interval. In that run the peer write completed before quarantine, and the audit preserved that order. After quarantine another peer command was denied. This was a lock control with live authority before release. The ownership-loss arms separately demonstrated stale-owner rejection.

## Reproduction and raw evidence

From the validation worktree, use the Aegis Python environment with project and test dependencies installed. The harness archives the exact B pin locally and checks that the native source and tests match the native pin.

```sh
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase4e_observer_order.py b \
  --output /tmp/observer-order-b.json
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase4e_observer_order.py native \
  --output /tmp/observer-order-native.json
```

[4E-B first run](../benchmarks/phase4e-adversarial/observer-order-b.json) · [4E-B repeat and lock timing](../benchmarks/phase4e-adversarial/observer-order-b-repeat.json) · [Native first run](../benchmarks/phase4e-adversarial/observer-order-native.json) · [Native repeat, failed-probe and lock timing](../benchmarks/phase4e-adversarial/observer-order-native-repeat.json) · [Validation harness](../scripts/phase4e_observer_order.py)
