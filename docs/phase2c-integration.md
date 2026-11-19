# Phase 2C integration review

## Baseline and pre-change contract comparison

This comparison was recorded before either feature commit was applied to the integration worktree. `feat/mesh-reliability` at `ef490c0` and `feat/rapid-policy` at `6f47e32` both have `14440ee226c58aa6e8e06517ab1601b2d672798c` as their merge base. The integration worktree starts at that commit. The original feature worktrees and the dirty canonical `master` checkout are out of scope.

| Surface | Mesh branch | Rapid branch | Integration decision |
| --- | --- | --- | --- |
| Signed event format | Finding envelope unchanged; adds HTTP and JetStream delivery of existing `SignedRevocation` on `aegis.revocations.v1`. Event ID is finding or revocation UUID. | Uses the baseline finding and revocation models only in local evaluation. No wire change. | Preserve both versioned subjects, strict envelope parsing, and stable message IDs. |
| Signature and trust | Coordinator and agent independently check locally pinned Ed25519 key, role, time, and signature. Legacy finding-only trust format remains accepted. | Same trust checks; maps rejection reasons to stable codes. | Keep both validation boundaries and Rapid reason codes. Invalid events must not advance replay state. |
| Revocation | Mesh delivers and audits signed revocations, including before a finding. Target ID and exact SHA-256 digest are permanently denied. Historical finding row remains. | Rapid applies the same ledger locally and exposes `FINDING_REVOKED` for effective reads. It also persists local denial overrides when policy tightens. | Combine transport with effective decision and override logic; retain historical rows. A revocation never authorizes an action. |
| Consumer identity | Requires `AEGIS_AGENT_ID`; durable is `aegis-<agent_id>`, and each agent owns a separate SQLite file. | SQLite binds an `agent_id`, but runtime falls back to `lab-agent` and uses a fixed `lab-agent` durable. | Require stable identity and one durable plus audit file per agent; reject identity reuse. |
| Audit record | SQLite findings, rejected events, revocation decisions, and target ledger; decision includes event and correlation IDs but lacks a stable reason code. | Adds reason codes, legacy schema migration, and durable local denial overrides. | Migrate all audit tables, preserve existing decisions, and include agent/event/correlation IDs and reason codes in exported records. |
| Acknowledgement | Calls JetStream `ack_sync()` after SQLite commit; malformed/conflicting events are terminated; transient audit failures retry under `max_deliver=5`. | Uses asynchronous `ack()` after SQLite commit and consumes only findings. | Keep synchronous acknowledgement after durable audit and both event kinds. Exercise retry, restart, and broker failure paths. |

The baseline `docs/contracts.md` describes finding delivery and marks revocation as proposed. Mesh's `docs/phase2a-integration.md` and Rapid's `docs/proposed-shared-contracts-rapid.md` describe the proposed changes. This document records the concrete reconciliation before integration code changes.

## Verification and handoff

### Integrated behavior

Mesh commit `ef490c0` was cherry-picked as `9e3a6b8`, then Rapid commit `6f47e32` as `c3cd6cc` after resolving conflicts in `STATUS.md`, `agent_runtime.py`, `storage.py`, and `test_slice.py`. The separate Phase 2C changes keep Mesh's `aegis.>` pull consumer, `ack_sync()` after audit commit, required stable agent ID, and revocation transport. Rapid's exact local inventory set, default-deny checks, reason codes, denial overrides, and audit migration are retained. The audit identity migration recognizes both the Mesh `audit_identity` table and Rapid `agent_identity` table. The agent retries a broker fetch failure while NATS reconnects; it does not acknowledge an event it has not audited.

The integrated contract uses a signed finding on `aegis.findings.v1` or a signed revocation on `aegis.revocations.v1`, both in `AEGIS_FINDINGS`. `Nats-Msg-Id` equals the event UUID. Both coordinator and every agent validate pinned Ed25519 grants, role, time, and signature independently. Every agent uses a distinct durable `aegis-<agent_id>` and bound SQLite audit file. Historical decision rows are preserved; `SqliteAudit.get()` computes an effective denial from revocation and local override ledgers. Every outcome is dry-run.

### Test environment and exact commands

Run on 2026-11-19, macOS 27.0.1, ARM64 MacBookPro18,3, Apple M1 Pro (10 CPU cores), 32 GB RAM. Host Python 3.15.2; `cryptography` 46.0.7, FastAPI 0.165.0, `nats-py` 2.17.0, Psycopg 3.3.9, Pydantic 2.14.4, pytest 9.2.0, httpx 0.28.1. Docker client 29.8.0, server 29.5.2, Compose 5.5.1. Compose containers used Python 3.12, PostgreSQL 16.16 and NATS 2.10.29. The two lab agents ran as separate containers; benchmark agents were 3, 10, or 100 distinct JetStream durables and SQLite files in one host Python process. All published ports bound only to `127.0.0.1`.

Commands from `.worktrees/phase2c`:

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 /Users/jackadams-lovell/aegis-network/.venv/bin/python -m pytest -q -p no:cacheprovider
PYTHONPATH=src /Users/jackadams-lovell/aegis-network/.venv/bin/python scripts/setup_lab.py
AEGIS_DB_PASSWORD=local-phase2c docker compose -p aegis_phase2c -f compose.yaml -f /private/tmp/aegis-phase2c-override.yaml config -q
AEGIS_DB_PASSWORD=local-phase2c docker compose -p aegis_phase2c -f compose.yaml -f /private/tmp/aegis-phase2c-override.yaml up -d --build
PYTHONPATH=src AEGIS_DB_PASSWORD=local-phase2c /Users/jackadams-lovell/aegis-network/.venv/bin/python scripts/phase2c_live.py --project aegis_phase2c --override /private/tmp/aegis-phase2c-override.yaml --samples 20
AEGIS_DB_PASSWORD=local-phase2c docker compose -p aegis_phase2c -f compose.yaml -f /private/tmp/aegis-phase2c-override.yaml down
```

The temporary override at `/private/tmp/aegis-phase2c-override.yaml` was:

```yaml
services:
  postgres:
    ports: ["127.0.0.1:15432:5432"]
  nats:
    ports: ["127.0.0.1:14222:4222"]
  coordinator:
    ports: !override ["127.0.0.1:18080:8000"]
```

The generated `lab-config/` holds disposable local credentials and is gitignored. The Compose project name is unique to this integration. No production target, external distribution, mitigation, or Daybreak connection was used.
The final `docker compose down` removed only this project's containers and network; its named PostgreSQL, NATS, and agent audit volumes remain for inspection.

### Results

The combined local suite passed **28 tests**, with one third-party Starlette/httpx deprecation warning. It includes a migration from an existing Mesh audit containing an allowed finding and revocation; the revocation remains effective, its history remains intact, and a different agent ID is rejected. Compose configuration parsed and all five services built and started.

The live Compose scenario delivered a signed finding to both distinct containerized agents, with one `EXACT_MATCH_ALLOWED` row in each audit. A duplicate HTTP submission returned `accepted: false`; a forced second JetStream delivery of the same envelope produced no extra logical row. An invalid signature returned HTTP 400. With `agent_b` and NATS stopped, a newly accepted finding remained unsent in PostgreSQL outbox. After NATS and `agent_b` restarted, the outbox became sent and both agents audited the finding. A signed revocation then reached both agents and permanently recorded the exact target digest. A second signed revocation was delivered *before* its target finding; both agents recorded `FINDING_REVOKED` for that later finding. The first finding and revocation repeated over HTTP returned `accepted: false`. Restarting both agents preserved each audit exactly at the integration checkpoint: **3 finding rows, 2 revocation rows, and 2 ledger entries per agent**. Benchmark findings arrived afterward. All were dry-run outcomes.

For each benchmark scale, 20 unique synthetic signed findings were submitted through the coordinator HTTP API into PostgreSQL, the outbox, and NATS. A distinct durable and SQLite file were created for every simulated agent. Timing started immediately before each HTTP submission and ended after its agent's SQLite decision commit, before the JetStream acknowledgement. Percentiles cover all agent-finding deliveries, using linear interpolation. These are one-run observations, not confidence intervals.

| Simulated agents | Expected / committed | Coverage | p50 ms | p95 ms | p99 ms | Host CPU s | Elapsed s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 60 / 60 | 100% | 248.987 | 284.850 | 286.926 | 0.101 | 0.448 |
| 10 | 200 / 200 | 100% | 182.427 | 334.506 | 341.446 | 0.193 | 0.520 |
| 100 | 2,000 / 2,000 | 100% | 726.944 | 814.114 | 837.044 | 1.396 | 1.583 |

All scales had zero duplicate logical rows and zero unexpected allow decisions. Peak host Python process RSS was 119,390,208 bytes by the end of the 100-agent run. The 3- and 10-agent runs reported 96,796,672 and 98,353,152 bytes respectively; peak RSS is cumulative across runs in one process.

### Limits and remaining security risks

- The benchmark uses 20 findings per scale, one host process and one run per scale. It measures signed finding fanout plus local dry-run audit, not 100 independent hosts, mitigation, recovery latency distribution, availability under sustained faults, or 30-second execution safety. The 3-agent percentile being above the 10-agent percentile reflects run variability and startup timing; it is not a scaling claim.
- The live outage test demonstrates pending outbox recovery after one broker stop. JetStream retention, disk exhaustion, prolonged outage, `max_deliver=5` exhaustion, and dead-letter handling remain untested or undefined. An agent offline beyond retention can miss a revocation.
- A duplicated `AEGIS_AGENT_ID` with a *different* audit volume can join the same pull durable; deployment-wide uniqueness is not enforced by a broker lease or registry. The tested distinct IDs and same-file identity guard do not close this deployment risk.
- PostgreSQL enforces unique `(publisher_id, sequence)` pairs but does not enforce increasing sequence order. Each agent rejects a lower sequence unless the exact target was already revoked. Ordering across publishers and delayed events still needs an explicit protocol and test matrix.
- A locally trusted key with the `revocation` role can withdraw a target from another publisher when its artifact ID and digest match. That broad role is intentional for this lab, but revoker scope and governance need a decision before wider distribution.
- The disposable Compose fixture gives one key both finding and revocation roles. Separate key and role enforcement is covered by the local tests, but the live Compose run did not exercise distinct signing keys. Independent revocation credentials need a deployment test before broader use.
- An audit's historical `allow_dry_run` row remains after expiry or revocation. Effective reads through the local agent revalidate trust and time, and `SqliteAudit.get()` applies the revocation ledger, but consumers of raw audit rows must not infer present authorization. No executor exists.
- A signed finding's evidence digest and URI identify claimed data but do not prove independent verification. Key rotation, revocation ordering across publishers, signed audit export, external audit integrity, and an independent attestation contract remain open. Neither coordinator acceptance nor local dry-run allow authorizes execution.

Phase 2C stops here for review. Do not merge into `master` automatically. No production targets, autonomous mitigation, or Daybreak integration were included.
