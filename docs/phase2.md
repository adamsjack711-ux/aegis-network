# Phase 2 design and measurement protocol

## Reliability contract

Each lab deployment has a stable `agent_id`, a JetStream durable named from that ID, and its own SQLite file. Every durable is an independent view of the same stream; agents never share a durable. The event ID is the signed artifact or revocation UUID. PostgreSQL inserts the event and outbox row atomically. The dispatcher publishes with `Nats-Msg-Id` set to the event ID, acknowledges from JetStream, then marks the row sent. Redelivery is expected; each agent persists one logical decision per event ID before ack.

Trust is local to every agent. A grant binds `(publisher_id, key_id)` to Ed25519 key bytes, allowed roles, `not_before`, `expires_at`, and `revoked_at`. Both coordinator and agent check the current time. A signed revocation event can deny a specific finding digest, including when it arrives before the finding. Local key revocation in the trust file is independent of coordinator messages. Neither signature nor revocation event authorizes execution.

## Controlled faults

Tests stop/restart an agent and the NATS broker, repeat the same event, corrupt a signature, expire or revoke a key, and submit a stale sequence. After recovery, expected coverage is every healthy agent receives every accepted event once logically, with no invalid finding yielding `allow_dry_run`. Faults target only local Compose services; no external network or host policy is touched.

## Benchmark

`scripts/benchmark.py` runs against local Compose PostgreSQL and NATS, creating 3, 10, or 100 simulated agents as separate durable consumers and SQLite files in one Python process. It submits a fixed number of synthetic findings per run, records time from the start of coordinator submission to each agent's committed decision, and reports p50/p95/p99, coverage, throughput, duplicate logical decisions, invalid findings accepted, process CPU seconds, peak RSS, and recovery time for a controlled agent pause. The 100-agent run measures event fanout and local decision work on one host, not 100 independent machines. Record hardware, software versions, sample size, and exact command. No claimed 30-second mitigation or 10x verification result follows from this benchmark.
