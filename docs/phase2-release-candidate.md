# Phase 2 release candidate

## Candidate and scope

The candidate for local dry-run use is `ffe5c322b144ab3fb40d2ee29b1486b917d339f1` on `integration/phase2-release-candidate`. The service source is identical to `db90aa09b5b388275f15fc728a21985bf4b82a80`, which was built and benchmarked. The later implementation commit adds two live harness checks. The documentation and benchmark artifacts are in a separate handoff commit. Candidate approval here means the integration checks for the isolated lab passed. Independent review and release approval are pending.

The RC worktree was created from clean Phase 2C `65ebb3ab14d4a57651919b17106bcb01fec9a4a0`. Phase 2D's branch pointed to `14440ee`, with its completed implementation, tests, and reports present as tracked and untracked working changes in `.worktrees/phase2d`. The reviewed tracked source, scripts, and tests diff against `14440ee` has SHA-256 `d34b48910bc9fdac0ef7f7eb73437ce4c7fe38dbda314bfa49664ee4990b2bd0`. The untracked benchmark script, edge fault script, and edge tests have SHA-256 prefixes `9d3525a720b8`, `5e7e023cf180`, and `3b3210819f327`, respectively. The 2D worktree was read in place. The RC has no master merge or production, mitigation, or Phase 3 integration.

## Compatibility and port decisions

| Area | Release-candidate behavior |
| --- | --- |
| Trust and revocation | Retains Phase 2C's canonical signed payloads, locally pinned roles and validity windows, scoped v1.1 withdrawals, denial of new unscoped v1.0 withdrawals, and existing durable tombstones. The 2D v2 envelope has different signed bytes and was excluded. |
| Identity and delivery | Retains canonical UUIDv4 IDs, `aegis-<uuid>` durables, broker KV ownership checks, split v1 subjects on `AEGIS_FINDINGS`, local audit identity, and `ack_sync()` after the SQLite decision. The 2D single subject, stable string IDs and unconfirmed `ack()` were excluded. |
| Ordering and recovery | Retains transactional event/journal/outbox writes, commit-ordered journal positions, stale-finding rejection, late unique withdrawals, replay validation, and cursor advance after audit. The page query now bounds positions by its captured head so a concurrent append cannot make a valid page appear ahead of its own head. |
| Retention and malformed input | Keeps 24-hour/64 MiB discard-new findings retention, the 256 KiB broker message limit, dead-letter copy before termination, and retries for unaudited withdrawals. The 2D 64 KiB HTTP and parser cap and immediate terminal rejection were excluded because they alter intake and dead-letter behavior. |
| Wakeup | `f73813b` ports the post-commit dispatcher signal, retains the 200 ms poll fallback and failure delay, drains full successful batches, and preserves stable message IDs and broker acknowledgment before marking sent. |
| Worker offload | Trial `5d66f65` serializes each agent's SQLite access, waits for a started write on cancellation, and retains synchronous broker acknowledgment. At 100 agents, p95 rose from 854.794 to 980.287 ms and median host CPU from 1.560 to 3.888 s compared with wakeup alone. `db90aa0` restores the synchronous evaluation path. |
| Measurement | Ports local stage measurement through `process_message` in `b27895d`. It uses a single monotonic clock, so the candidate needs no diagnostic HTTP route or publish timestamp header. |

## Reproduction

Run from the RC checkout with the test dependencies installed. The host used macOS 27.0.1 (26A434), arm64, Python 3.15.2, and Docker Compose 5.5.1. Host package versions included nats-py 2.17.0, Psycopg 3.3.9, Pydantic 2.14.4, httpx 0.28.1, cryptography 46.0.7, and pytest 9.2.0. Compose uses Python 3.12, PostgreSQL 16, and NATS 2.10. The commands use disposable lab keys and loopback published ports 18080, 14222, and 15432. Use a fresh Compose project or fresh local volumes for a clean full-suite rerun.

```sh
export AEGIS_DB_PASSWORD=local-phase2c
export PYTHONPATH=src
python -m pytest -q -p no:cacheprovider
python -m compileall -q src scripts tests
python scripts/setup_lab.py
docker compose -p aegis_phase2_rc -f compose.yaml -f compose.hardening.yaml config -q
docker compose -p aegis_phase2_rc -f compose.yaml -f compose.hardening.yaml up -d --build
docker compose -p aegis_phase2_rc -f compose.yaml -f compose.hardening.yaml stop agent agent_b
python scripts/phase2c_live.py --project aegis_phase2_rc --override compose.hardening.yaml \
  --benchmark-only --samples 20 --repeats 3
docker compose -p aegis_phase2_rc -f compose.yaml -f compose.hardening.yaml start agent agent_b
python scripts/phase2c_live.py --project aegis_phase2_rc --override compose.hardening.yaml \
  --integration-only --extended-faults
docker compose -p aegis_phase2_rc -f compose.yaml -f compose.hardening.yaml down
```

Benchmark cohorts each have separate UUID durables, broker KV leases, and SQLite files. They share one host Python process and NATS connection, start with new subscriptions, and exclude periodic journal reconciliation. The independent container agents exercise startup and periodic replay and are stopped for timing. The timed interval starts immediately before each sequential HTTP POST, then records receipt, the lease check, completion of the SQLite evaluation and commit, and broker-confirmed acknowledgment. Coverage requires both durable decisions and confirmed acknowledgments. Throughput is decisions divided by elapsed time from start of the submission window through the last confirmed ack. Host CPU and process peak RSS exclude services. Stage percentiles use linear interpolation. Peak RSS is cumulative across repetitions within each process.

The fresh before/after comparison used the Phase 2C poll-only coordinator built at `65ebb3a` with the observer harness from `b27895d`, wakeup at `f73813b`, the host worker trial at `5d66f65` with the same wakeup coordinator, and the final runtime at `db90aa0`. Each used 20 signed findings per run and three runs per scale in sequence. The same local broker and database volumes were reused. The comparison with old Phase 2C and 2D published numbers is historical context because their harnesses differed.

## Performance

Figures are medians of three runs, each with the stated agent count and 20 findings. Latency is in milliseconds. Each run’s detailed stage percentiles, CPU, peak RSS, and counts are available in the linked raw records.

| Stage | Agents | Audit p50 / p95 / p99 (ms) | Confirmed ack p95 (ms) | Decisions/s | Host CPU (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 3 | 159.485 / 307.429 / 312.981 | 308.648 | 119.84 | 0.106 |
| Wakeup | 3 | 26.988 / 32.013 / 33.372 | 33.391 | 206.32 | 0.101 |
| Worker trial | 3 | 29.375 / 33.743 / 35.421 | 34.901 | 211.42 | 0.141 |
| Final | 3 | 28.479 / 33.685 / 37.107 | 35.501 | 194.36 | 0.104 |
| Baseline | 10 | 170.770 / 312.558 / 316.151 | 315.840 | 371.74 | 0.219 |
| Wakeup | 10 | 26.579 / 30.816 / 33.404 | 33.994 | 603.15 | 0.223 |
| Worker trial | 10 | 31.098 / 35.966 / 37.111 | 37.073 | 632.90 | 0.451 |
| Final | 10 | 27.203 / 32.396 / 33.828 | 35.484 | 590.72 | 0.239 |
| Baseline | 100 | 713.015 / 936.173 / 981.200 | 967.834 | 1,108.40 | 1.604 |
| Wakeup | 100 | 526.640 / 854.794 / 889.297 | 892.367 | 1,185.09 | 1.560 |
| Worker trial | 100 | 589.848 / 980.287 / 1,018.350 | 986.740 | 1,209.61 | 3.888 |
| Final | 100 | 574.483 / 876.545 / 919.426 | 931.580 | 1,047.70 | 1.747 |

Per run, coverage was 60/60, 200/200, or 2,000/2,000 at 3, 10, or 100 agents. All 36 runs had zero duplicate logical rows and zero unexpected denials in the valid-finding workload. Peak host RSS in the final run series reached 125,190,144 bytes (119.39 MiB). At 100 agents, final audit p95 ranged from 849.065 to 989.618 ms against 710.320 to 1,019.978 ms at baseline. Final median throughput was 5.5% lower. The 100-agent evidence is mixed and does not establish a repeatable speedup. The low-agent wakeup effect was consistent across all three repetitions. At 100 agents the final median p95 for submission to agent receipt was 817.337 ms, with 75.769 ms for the lease check, 1.050 ms for local evaluation, and 67.000 ms for the broker acknowledgment span. Separate stage percentiles cannot be added. The receipt interval includes several stages, so it does not isolate broker or network time.

The raw records cover all four stages. [Baseline](../benchmarks/phase2-rc-baseline.jsonl) · [Wakeup](../benchmarks/phase2-rc-wakeup.jsonl) · [Worker trial](../benchmarks/phase2-rc-worker-trial.jsonl) · [Final](../benchmarks/phase2-rc-final.jsonl)

## Security and failure verification

Ran on 2026-11-19. The Phase 2C baseline passed 38 tests. The final candidate passed **40 tests**, compilation, Compose config validation, and diff checks. The only pytest warning came from Starlette's deprecated TestClient integration with httpx. The suite covers invalid signatures and sequence poisoning, exact matching and local denials, stable audit identity, scoped and legacy withdrawal handling, late withdrawals and stale findings, replay gap and expiry handling, dead-letter ordering and retry behavior, publish/mark failure, cross-thread wakeup, and key rotation against a previously audited finding. Live results came from separate containerized UUID agents on the same local Compose project. The first live harness invocation lacked the disposable database variable in its subprocess environment. Exporting it resolved the harness error. The successful rerun reused the benchmark and audit volumes.

| Live check | Observed result |
| --- | --- |
| Signed delivery, duplicate HTTP and broker delivery, invalid signature | Both agents committed once per logical finding. The duplicate produced zero extra rows. Invalid signature returned HTTP 400. |
| Scoped withdrawals before and after a finding | Both agents recorded the scoped withdrawals and preserved their ledgers across restart. An out-of-scope withdrawal returned HTTP 400 and a stale finding HTTP 409. |
| Lease uniqueness | A second live claimant of the same UUID was rejected. |
| Broker stop and journal recovery | An accepted event stayed in the outbox until the broker restarted. After a later full findings-stream purge, an offline agent recovered both a finding and its withdrawal from the PostgreSQL journal. |
| Malformed and oversized broker input | Two dead-letter copies of malformed input, one per agent. JetStream rejected a message one byte over the 256 KiB limit. |
| Slow durable consumer | 10 messages pending while stopped. All 20 agent-event decisions were present 1.338 s after restart was requested. |
| Coordinator SIGKILL during broker outage | 40 committed rows stayed pending. Restart drained all 40 and both agents recorded all 80 decisions within 2.161 s. |
| Agent network partition | The connected agent recorded a new finding while the isolated one had no row. Both had it 0.499 s after reconnect was requested. |
| Agent SIGKILL | Both agents recorded the new finding and the crashed agent preserved its previous rows. Recovery took 30.650 s, including lease expiry and takeover. |

Raw outcomes are in [live results](../benchmarks/phase2-rc-live.jsonl). Measurements include restart or reconnect calls and polling delay. Docker client and server were 29.8.0 and 29.5.2. Running service versions were Python 3.12.16, PostgreSQL 16.16, and NATS 2.10.29. Tested local image identifiers follow.

| Service | Image SHA-256 |
| --- | --- |
| Coordinator | `d55d13f8619f513ec38687b6077f1cbe3d8e5c0b0b4585967b607f88e055c6a9` |
| Agent A | `7e712f6fa8356eebed9abd5feff5d030e2d007c4be8e04655e9fc58e3bd2936e` |
| Agent B | `29ae97e07649c5c480cf7eb4cc83d36bbd53b03f9da75658b489d681add5ff07` |
| PostgreSQL | `1d5b02d3a9941fbd52437db4107f8c52d6297dac553ca1e5c299ebb3756b4857` |
| NATS | `b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927` |

The RC Compose containers and network were removed after verification. Named lab volumes were retained.

## Residual risks and release limits

- The lab broker has no per-agent authentication or ACLs. Its lease gives one-account process uniqueness. Cross-broker clone detection and resistance to a hostile broker remain open.
- Journal replay validates signed items and detects some gaps. The coordinator supplies the head and contents. Completeness against withholding, authenticated replay, failover, backup/restore and journal retention still require work. The captured-head query fix addresses concurrent appends only.
- Historical key trust, signed key rotation governance, and replacement of unscoped legacy withdrawals remain operational risks. Audit exports have no independent integrity proof.
- Outbox admission quotas and sustained overload behavior remain open. The 40-row probe demonstrates bounded catch-up under the measured fault. Dead-letter storage can contain untrusted message bytes and needs ACLs, capacity monitoring, and reviewed retention.
- Results cover a single host and three short runs per scale. The 100-agent tail includes shared host scheduling and broker operations. A crash can take about one full identity lease to recover. None of these measurements establishes multi-host performance, independent evidence verification, or mitigation effectiveness.

The [Phase 2C risk register](phase2c-risk-register.md) remains the detailed security handoff. The candidate is ready for review within the local dry-run scope.
