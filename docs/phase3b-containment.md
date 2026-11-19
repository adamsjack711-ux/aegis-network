# Phase 3B Aegis Mitigation

Phase 3B contains one declarative route restriction for a disposable HTTP lab. At baseline, an unauthenticated request to the fixture's marker route returns inert text. Three proxies expose the fixture on ephemeral IPv4 loopback ports. Each upstream listens on a Unix socket inside a private temporary directory. The package has no Mesh subscription, remote administration endpoint, command runner, configurable forwarding destination, or production integration.

## Run the lab

From the Phase 3B checkout, using the project's Python environment on a Unix host with Unix and loopback sockets enabled:

```sh
PYTHONPATH=src python -m aegis.mitigation --lease-ms 3000
PYTHONPATH=src python -m pytest -q tests/test_phase3b_containment.py
PYTHONPATH=src python scripts/benchmark_phase3b.py > benchmarks/phase3b-containment.json
```

The first command shows the exact plan and accepts its digest as local approval. It reports the elapsed time through confirmed protection, verifies quarantine as the operator stop, and discards the fixture. The benchmark uses the same authorization and rollout path with scripted local approval. Each episode begins with freshly initialized fixture state, and the JSON retains all episode outcomes.

## Controls and transitions

| Gate | Lab behavior |
| --- | --- |
| Allowlist | The only template is `restrict-fixture-route/v1` for `GET /fixture-marker` on the compiled inventory `canary`, `replica-a`, and `replica-b`. The proxy forwards only its three exact fixture paths. |
| Preflight | The plan binds the fixture ID, template, exact path, ordered inventory, expected fences, lease and review expiry. Before leasing, the HTTP oracle must independently see the inert marker and both benign responses on all three replicas at their expected fences. The adapter rechecks the plan, authorization, inventory and pre-state inside the transaction. |
| Scoped authorization and fencing | The process-local approver signs the plan digest with an ephemeral HMAC key. Separate, target-bound capabilities authorize each restriction. SQLite consumes each capability through the one-way compare-and-set on its expected target fence. The mutation, fence increment and audit record commit together. Replay, stale fences and cross-target grants are denied. Marker requests serialize with target writes. The proxy rechecks the deadline before sending a forwarded response. |
| Bounded lease | The lease is 250 ms to 30 s and cannot outlive approval. Expansion and confirmed status also require an observation less than 750 ms old. The proxy checks deadlines on admission and fails closed on state-access errors even when the controller is down. There is no automatic renewal. |
| Canary and confirmation | Restrict the canary and verify it before expanding. The observer runs two rounds at least 20 ms apart. Confirmation requires all three replicas to return the exact proxy denial for the marker and both expected upstream responses at their new fences. The SQLite confirmation records scope, fences, request count and observation interval. The monitor polls every 50 ms between checks and repeats the all-replica observation while the lease is valid. |
| Safe rollback | An operator stop, a failed rollout, a failed health check or expiry leads to quarantine across the whole leased inventory. Quarantine serves 503 and advances every target fence once. A separate HTTP observation must verify quarantine everywhere before the adapter records `safe_hold`. Missing evidence or failure to commit leaves `recovery_required`. Startup reconciles an interrupted or previously confirmed rollout to quarantine before admitting traffic. |

During a partial rollout, replicas awaiting promotion keep their baseline behavior while the lease and any required canary evidence are current. The lab has no full-scope confirmation in that interval. An expired lease or stale canary observation quarantines the entire scope on request, even if the controller never records rollback. Quarantine is terminal for a disposable inventory.

The observer uses only the enrolled HTTP endpoints and expected fixture IDs and fences. It checks actual status, body and identity on every request. An upstream failure, silent listener, wrong replica, missing path or incomplete observation cannot establish protection. The observer runs in the lab process under the same local trust boundary as the controller. The lab trusts the host, local operator, SQLite files and proxy process. Host compromise, database tampering or snapshot restoration, and externally administered observer identity are outside the experiment.

## Verification

The focused suite probes real proxies independently of the adapter. It covers baseline exposure, benign traffic, out-of-scope plans, negative preflight, approval replay and forgery, competing grants, stale or incomplete evidence, failed canary and expansion health, upstream and proxy outages, store loss, expiry without a controller, and restart reconciliation. For the transaction fault, a spawned process exits immediately before or after the expansion commit while the proxy stays live. The test verifies that the fence, route behavior and audit agree, then restarts the fixture and verifies quarantine on every replica.

The baseline slice has a separate failing test, `test_invalid_signature_does_not_poison_sequence`, reproduced at the unmodified base revision `14440ee`. It expects the reason `invalid or expired signature` and receives `invalid signature`.

## Measured time to confirmed protection

Run on 2026-11-19 on macOS arm64 with 10 logical CPUs, Python 3.15.2 and SQLite 3.54.1. The recorder starts before the controller validates the local scenario and stops immediately after the durable all-replica confirmation commit. The measured span includes plan construction, scripted approval, live preflight, canary and expansion commits, and both observation rounds. The recovery timer starts at initiation of an upstream shutdown and ends when the recorder reads the independently verified safe hold.

| Scenario | Completed | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| Confirmed protection, idle | 30/30 | 116.030 ms | 121.962 ms | 127.214 ms |
| Confirmed protection, benign load | 30/30 | 120.852 ms | 126.918 ms | 129.215 ms |
| Upstream outage to verified quarantine | 10/10 | 102.729 ms | 108.448 ms | 108.448 ms |

The benchmark saw zero marker escapes in 1,440 post-confirmation probes and zero errors in 1,267 concurrent benign requests. All 60 operator-stop rollbacks and all 10 outage recoveries reached verified quarantine. [Benchmark protocol, environment and raw samples](../benchmarks/phase3b-containment.json)

These are empirical single-host results for one three-replica fixture family. The benchmark used scripted approval and omitted human review time, remote finding delivery and larger deployments. The interactive demo includes the operator's approval time in its elapsed measurement.
