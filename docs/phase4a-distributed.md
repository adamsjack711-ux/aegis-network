# Phase 4A distributed reliability

## Handoff

Phase 4A starts from `7744ebd7f80e6f2aabb253d5cc3ec9972c86cffd` on `feat/phase4a-distributed` in `.worktrees/phase4a-distributed`. The Phase 3C architecture, threat model, acceptance report, raw results and current worktrees were reviewed. Phase 3C's headline loop shared one event loop and broker connection across logical agents. The Phase 4A profiles use a new process for each deployment. The pinned baseline passed all 129 existing tests. The main benchmark implementation is `bf0a57a600c87b4effcd487e83fe3928e76fbef2`.

The largest completed profile delivered 8,100 expected decisions to 300 independent agents. The 500- and 1,000-agent attempts launched 25 processes each before the memory projection exceeded the configured budget. Those attempts have startup measurements only. Phase 4A establishes single-host distribution of signed defensive findings and withdrawals and exercises one independent, locally authorized fixture process. Real multi-host operation and broker or database failover remain unverified.

## Reproduce

Use a disposable lab on a POSIX host with Python 3.12+, a local Docker socket, Docker Compose, and the `postgres:16-alpine` and `nats:2.10-alpine` images available locally. The harness uses a unique Compose project and disposable keys, allocates IPv4 loopback ports, writes private state below `--directory`, and removes its service containers, network and volumes at teardown. The private directory retains logs and SQLite audits for readback. Run profiles sequentially to keep the host utilization comparable. Set a per-host memory budget that leaves room for other lab processes and the Docker VM.

```sh
python -m pip install -e '.[test]'
export PYTHONPATH=src
python -m pytest -q -p no:cacheprovider
AEGIS_PHASE4A_LIVE=1 python -m pytest -q -p no:cacheprovider tests/test_phase4a_distributed.py

run_dir="$(mktemp -d)"
run_profile() {
  profile="$1"
  shift
  python scripts/phase4a_bench.py --authorize-local-lab --directory "$run_dir" \
    --output "$run_dir/$profile.json.gz" --summary "$run_dir/$profile-summary.json" "$@"
}
run_profile three-hundred-two --agents 300 --coordinators 2 --agent-memory-budget-mib 18000 --timeout 150
run_profile three-hundred-repeat --agents 300 --coordinators 2 --agent-memory-budget-mib 18000 --timeout 150
run_profile hundred-one --agents 100 --agent-memory-budget-mib 18000
run_profile hundred-two --agents 100 --coordinators 2 --agent-memory-budget-mib 18000
run_profile five-hundred --agents 500 --agent-memory-budget-mib 20000 --timeout 150
run_profile thousand --agents 1000 --agent-memory-budget-mib 20000 --timeout 150
run_profile ten-faults --agents 10 --faults --protection 5
run_profile hundred-burst-faults --agents 100 --coordinators 2 --burst 40 --faults \
  --agent-memory-budget-mib 18000 --timeout 180
```

Exit codes are 0 for a passing profile, 1 for a failed assertion or lab error, and 2 for a resource-limited run. The driver starts agents in batches of 25 by default. It projects per-host agent memory from the observed batch footprint and stops before launching the next batch when the requested population exceeds the ceiling. The default is 4,096 MiB per host. Darwin reports physical footprint and Linux reports proportional set size when available, with peak RSS as a fallback. The driver supports 10–1,000 agents including intermediate sizes. The 250,000-delivery bound limits retained instrumentation per run.

### Optional isolated SSH peers

Use pre-enrolled hosts on a dedicated, authorized IPv4 lab network. The controller requires a user and literal private IPv4 address per peer. Configure trusted host keys and key-based SSH access in advance. All peers need the same checkout path with identical agent code, a Python environment with dependencies, and SSH remote forwarding. The loopback test used `AllowTcpForwarding remote` and `AllowStreamLocalForwarding remote` on its disposable daemon. The harness requests reverse Unix socket listeners. Keep at least three agents on the controller for the local fault probes. The peer counts are included in `--agents`.

```sh
run_profile private-two-host --agents 100 --coordinators 2 --agent-memory-budget-mib 8000 \
  --ssh-peer lab@192.168.77.20=50 --peer-checkout /opt/aegis-phase4a \
  --peer-python /opt/aegis-phase4a/.venv/bin/python
```

SSH carries the broker and coordinator connections through Unix sockets under a private directory on each peer. The peer process exposes only loopback proxy listeners and receives public trust and policy configuration. It verifies the source fingerprint, launches one dry-run process per identity, and returns event traces and the closed audits for controller-side readback. Protection fixtures stay on the controller. Peer E2E measurements use controller-observed upper bounds that include telemetry forwarding. Stage durations within each peer use its own monotonic clock.

## Measurement

Each deployment is a separately launched OS process with its own event loop, NATS connection, UUID lease, JetStream durable and SQLite audit. The controller checks distinct PIDs on each host. Coordinators are independently launched FastAPI processes with one PostgreSQL journal, one outbox table and one JetStream broker. The two-coordinator profile distributes publishers and agent journal reads across both HTTP processes. Four lab publisher identities use a disposable signing key and issue findings in sequence within each publisher. The default sends five steady findings, then a 20-finding burst across the four publishers and two scoped withdrawals. A fixed mix exercises exact local allow, local authorization denial and inventory mismatch. The stress profile uses 160 burst findings. Faults inject process pauses and restarts only into this disposable run.

Latency starts at the controller's HTTP submission. First decision ends at the first measured durable SQLite write, via pull delivery or signed journal reconciliation. Confirmed delivery ends when `ack_sync()` returns. Per-event broker timestamps and outbox `sent_at` values use their own clocks. Stage durations use a single monotonic clock and may overlap. Burst ingest throughput counts accepted submissions. Burst fan-out throughput counts confirmed agent acknowledgements from burst start until the last ack. Per-event observations share publishers, storage, CPU and transport, so the reported percentiles describe these workloads without establishing statistical confidence bounds or a service-level objective.

The raw reports include OS processes and version fingerprints, HTTP timings and status codes, signed event IDs and payload digests, outbox positions, broker state and consumer backlog, audit and lease timings, ack delivery attempts, durable audit readback, and CPU, memory, network and storage samples. Broker byte counters are NATS client protocol counters per broker epoch. Docker snapshots also capture container network and block I/O. The harness measures SQLite size after stopping the agent. PostgreSQL reports database size and JetStream reports logical store bytes. Some component metrics are sampled and can miss brief peaks.

## Results on 2026-11-19

The controller, agents and coordinator ran on one macOS 27.0.1 arm64 host with ten logical CPUs and 32 GB of RAM. NATS 2.10 and PostgreSQL 16 ran in two Docker containers inside the host's Colima Linux VM with six vCPUs and approximately 7.74 GiB of memory. The runs used Python 3.15.2, nats-py 2.17.0, psycopg 3.3.9 and uvicorn 0.54.0. Each raw report pins dependency versions, Docker image IDs and source hashes. The 300-agent repeat, largest startup probes and SSH check used `47873a3`, which adds a bounded retry for Docker loopback port conflicts before workload creation.

| Agents / coordinators | Started | First durable decisions | Confirmed / expected ACKs | Steady decision p50 / p95 / p99 (ms) | Burst decision p50 / p95 / p99 (ms) | Burst confirmed ACK p50 / p95 / p99 (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [10 / 1, faults](../benchmarks/phase4a/ten-faults.json.gz) | 10 | 310 | 309/309 | 33.90 / 114.12 / 117.44 | 173.14 / 1,781.52 / 1,814.50 | 174.15 / 1,782.36 / 1,815.28 |
| [100 / 1](../benchmarks/phase4a/hundred-one.json.gz) | 100 | 2,700 | 2,700/2,700 | 62.64 / 338.37 / 585.02 | 492.50 / 860.84 / 879.35 | 509.87 / 880.34 / 890.04 |
| [100 / 2](../benchmarks/phase4a/hundred-two.json.gz) | 100 | 2,700 | 2,700/2,700 | 59.82 / 490.89 / 624.89 | 557.67 / 830.38 / 852.07 | 578.61 / 847.07 / 860.32 |
| [300 / 2](../benchmarks/phase4a/three-hundred-two.json.gz) | 300 | 8,100 | 8,100/8,100 | 205.34 / 499.60 / 550.62 | 2,164.72 / 4,226.36 / 4,516.40 | 2,286.37 / 4,476.88 / 4,910.74 |
| [300 / 2, repeat](../benchmarks/phase4a/three-hundred-repeat.json.gz) | 300 | 8,100 | 8,100/8,100 | 178.50 / 464.55 / 504.98 | 3,218.78 / 5,570.45 / 6,074.92 | 3,937.70 / 6,299.69 / 6,548.19 |
| [100 / 2, stress and faults](../benchmarks/phase4a/hundred-burst-faults.json.gz) | 100 | 17,100 | 17,099/17,099 | 60.67 / 221.12 / 388.52 | 3,043.71 / 16,740.49 / 18,221.90 | 6,015.75 / 17,439.59 / 19,061.16 |
| [500 / 1, startup only](../benchmarks/phase4a/five-hundred.json.gz) | 25 | — | — | — | — | — |
| [1,000 / 1, startup only](../benchmarks/phase4a/thousand.json.gz) | 25 | — | — | — | — | — |

The counts include findings and withdrawals submitted by the driver. Each fault run includes one intentional journal-only recovery after broker purge, which contributes a durable decision without a broker ACK. Fixture findings and deliberate broker-only probes are recorded separately. The 500- and 1,000-agent startup projections were **21,560 MiB** and **43,091 MiB** against a 20,000 MiB agent-memory budget. No workload was submitted on either attempt.

| Agents / coordinators | Agent CPU (core-s) | Coordinator CPU (core-s) | Agent median peak RSS (MiB) | SQLite audits (MiB) | NATS sampled peak RSS (MiB) | NATS sampled peak CPU (%) | NATS protocol in / out (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 / 1, faults | 5.60 | 3.79 | 61.89 | 0.74 | 19.62 | 7 | 0.17 / 0.45 |
| 100 / 1 | 43.77 | 3.53 | 61.75 | 7.42 | 39.25 | 48 | 0.57 / 2.63 |
| 100 / 2 | 43.32 | 3.24 | 61.79 | 7.42 | 39.62 | 46 | 0.59 / 2.63 |
| 300 / 2 | 154.69 | 13.07 | 60.78 | 22.27 | 82.50 | 85 | 2.16 / 8.35 |
| 300 / 2, repeat | 153.52 | 12.29 | 60.79 | 22.27 | 84.88 | 93 | 2.06 / 8.21 |
| 100 / 2, stress and faults | 112.47 | 17.53 | 62.33 | 11.21 | 54.75 | 61 | 4.18 / 15.99 |

CPU covers the run lifecycle as captured by the processes. The SIGKILL predecessor contributes only its startup resource sample. Container CPU snapshots, memory, network and block I/O are available in the raw files. At 300 agents, reported JetStream storage peaked at 76,098 bytes and the PostgreSQL database reached 7.66 MiB, including its initial database allocation.

### Throughput and bottlenecks

- At 100 agents, one and two coordinators accepted 43.47 and 35.61 burst findings per second, with 1,386.56 and 1,460.21 agent ACKs per second. Burst submission p95 was 135.38 ms and 171.45 ms. Journal request p95 was 150.85 ms with one process and 124.91 ms / 121.76 ms with two. Adding a coordinator split journal work. Both processes used the same database and broker. This pair of runs does not establish a consistent fan-out improvement.
- At 300 agents, the 20-finding burst achieved 9.35 accepted findings/s and 950.50 confirmed ACKs/s. Burst p95 was 836.83 ms for HTTP submission, 98.53 ms for the broker lease check and 97.80 ms for the final ACK round trip. The sampled database connection count reached 57. The journal route p95 was 856.52 ms / 855.66 ms across the two coordinators, and their HTTP traces recorded 0 server error responses. The evidence shows pressure in journal and ingestion work as well as broker-bound stages. The repeat measured 5,570.45 ms burst p95. These timings share PostgreSQL, JetStream and host scheduling.
- In the 100-agent stress profile, a 160-finding burst reached 28.72 accepted findings/s and 806.79 agent ACKs/s. The sampled outbox peaked at 89 pending events. Ten agents paused and ten delayed delivery processing by 80 ms per message. The ten paused agents accumulated 1,600 outstanding deliveries and the last ACK arrived 1,536.93 ms after resume. The drain snapshot recorded zero pending and zero outstanding ACKs. Journal catch-up can commit a decision before its broker copy is confirmed. [Stress traces](../benchmarks/phase4a/hundred-burst-faults.json.gz)

### Recovery, revocation and isolation

- The concurrent UUID claim was refused. In the 100-agent fault run, the killed eligible agent reclaimed its lease after 30,397.20 ms, completed startup after 30,474.60 ms, and confirmed the withdrawal after 30,477.74 ms. The 30-second lease TTL accounted for most of its observed unavailability.
- During broker restart the coordinator retained one unsent event in PostgreSQL. Agent reconnect p95 was 2,190.59 ms, and all agents confirmed the queued event 2,278.63 ms after the stop began. With JetStream storage limited to current usage, the new event remained in the outbox until capacity was restored. The final ACK followed restoration by 262.23 ms.
- The journal test gracefully disconnected one agent before submitting a scoped withdrawal, waited for the others to ACK, and purged the disposable stream. The disconnected agent restored the exact withdrawal from the signed journal after 355.00 ms from relaunch. Independent readback found zero missed withdrawals and zero stale effective decisions at completion. The 10- and 100-agent fault runs each had one withdrawal commit beyond the five-second reporting threshold, on the deliberately killed identity. At 300 agents, ordinary withdrawal commits were 341.30 / 549.80 / 579.68 ms.
- The two fault profiles recorded 10 and 117 extra broker confirmations for existing logical event IDs, including the deliberate replay. SQLite readback found zero duplicate logical decisions. The forged high-sequence finding was rejected independently by all agents in both runs. A valid lower-sequence scoped withdrawal was accepted and replay of a withdrawn finding remained denied.

### Verified finding to protection

One separate fixture process used the unchanged Phase 3C path with ten other dry-run agents active. It ran five sequential enrollments with fresh identities. Each episode verified the signed evidence, received a broker-confirmed decision, used scripted exact-plan approval, and fenced a three-replica route restriction. From completed verification and signing to committed HTTP observation, p50 / p95 / p99 was **375.67 / 381.70 / 382.56 ms**. Independent post-confirmation probes made 90 requests, with zero marker escapes, and each fixture reached verified safe hold. The ten ordinary agents confirmed all 50 companion deliveries. [Fixture traces](../benchmarks/phase4a/ten-faults.json.gz)

### SSH transport

A disposable loopback SSH listener exercised the peer path with five agents launched through SSH and five started directly. Both endpoints were on one physical host. In the raw topology, agent hosts count the configured endpoints. The run confirmed 130/130 expected deliveries and transferred the peer SQLite ledgers for readback. [SSH loopback traces](../benchmarks/phase4a/ssh-loopback.json.gz)

The final full suite passed **134 tests**, including the opt-in live reliability test, with one third-party Starlette TestClient deprecation warning. Source compilation, Git diff checks and artifact readback passed.

## Remaining limits

- All service and agent measurements share one physical host. One JetStream broker and one PostgreSQL server remain common dependencies in the two-coordinator profile. Agents are assigned an individual coordinator URL. This setup leaves automatic coordinator failover, replicated broker failover, PostgreSQL failover and long network partitions open.
- The 500- and 1,000-agent starts exceeded the configured memory budget at the first batch. They require more host capacity or explicitly authorized peers before their latency, throughput and recovery can be assessed.
- The signed journal enforces authenticity and ordering on events it returns. A compromised coordinator can still omit a withdrawal. Broker leases are scoped to one broker cluster and do not provide authenticated enrollment or cross-broker identity.
- The isolated fixture exercised exact-plan local approval and HTTP effectiveness with scripted review. It leaves human review latency, sustained benign traffic, and simultaneous protection at fleet scale unmeasured.
- The larger profiles measure bursts and short faults. Extended retention pressure, sustained overload, cross-host clock uncertainty, identity enrollment changes and administrative independence remain open.

The workload uses the baseline agent signature, ordering, scoped revocation, local policy, commit-before-ack, and journal reconciliation code. The runtime hooks expose observations and an optional lab delay. Moving shared topic names into a lightweight module retains their values and the original coordinator exports. No shared wire format or persistence contract changed.
