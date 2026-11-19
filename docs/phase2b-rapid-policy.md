# Phase 2B — Rapid agent policy and reliability

This branch changes only the local Rapid agent, its SQLite audit, tests, and a local benchmark. Every output remains a dry-run decision. Nothing executes a mitigation or fetches an evidence URI.

## Local decision rules

The agent first checks its locally pinned publisher grant, role, signature, and finding validity. It compares the finding's package URL and enumerated affected versions against a snapshot of exact local `(purl, version)` pairs. It does not infer version ranges, normalize package URLs, resolve URLs, or treat signed evidence as local authorization. Lab authorization and the template allowlist must both be present for `allow_dry_run`. All other paths deny.

Each authenticated finding has at most one historical SQLite decision row per artifact ID. Its payload digest, publisher, sequence, outcome, stable reason code, text reason, and timestamp persist before acknowledgement. Invalid or conflicting events go to `rejected_events` and cannot advance the publisher sequence. The audit database is bound to one agent ID; reopening it as another agent fails. A duplicate after restart returns the stored decision after current trust checks. If local authorization, inventory, or template policy has since tightened, a former allow becomes a durable denial override. Reopening the audit under a looser policy does not restore that old allow; a new signed finding is required. A revocation has its own audit row and changes the effective lookup result to `FINDING_REVOKED`, even if the original historical row was allowed. The original row remains as history.

The local reason codes are `EXACT_MATCH_ALLOWED`, `LAB_NOT_AUTHORIZED`, `TEMPLATE_NOT_ALLOWED`, `INVENTORY_NO_EXACT_MATCH`, `STALE_SEQUENCE`, `FINDING_REVOKED`, `REVOCATION_ACCEPTED`, `ARTIFACT_ID_CONFLICT`, `REVOCATION_ID_CONFLICT`, `UNKNOWN_PUBLISHER_KEY`, `PUBLISHER_ROLE_DENIED`, `PUBLISHER_KEY_INVALID_TIME`, `PUBLISHER_KEY_REVOKED`, `FINDING_INVALID_TIME`, `REVOCATION_INVALID_TIME`, `INVALID_SIGNATURE`, and `INVALID_EVENT`. Migrated rows from the original schema use `LEGACY_REASON` because the historical text cannot always be mapped unambiguously.

`AEGIS_AGENT_ID` can set the local audit identity; the existing lab default is `lab-agent`. The NATS durable name is unchanged in this branch. Each deployment still needs its own SQLite path and a separately configured durable consumer before a multi-agent deployment. The Mesh ingestion and event delivery contracts were not changed; the revocation evaluator is currently exercised locally, not through the v1 coordinator route.

## Verification on 2026-11-19

Command: `PYTHONPATH=src /Users/jackadams-lovell/aegis-network/.venv/bin/python -m pytest -q -p no:cacheprovider`

Result: **19 passed**, one existing third-party Starlette/httpx deprecation warning. Negative cases cover missing local authorization, disallowed templates, exact package/version mismatches, range-like strings, forged signatures, unknown and revoked publisher keys, key role denial, expiry, ID conflict, wrong revocation digest, duplicate delivery, restart with tightened policy, audit identity collision, and migration of a legacy audit row. No live Compose or broker failure-injection test was run in this branch.

The local benchmark command, run separately for each scenario, was:

`PYTHONPATH=src /Users/jackadams-lovell/aegis-network/.venv/bin/python scripts/benchmark_rapid.py --decisions 1000 --inventory-size 1000 --scenario SCENARIO`

Machine: macOS 27.0.1, ARM64, Python 3.15.2. Each run used 1,000 unique signed findings, 1,000 simulated inventory items, a fresh SQLite file, and one agent process. Timing starts immediately before local `evaluate` and ends after the audit commit; envelope creation and signing are outside the timer.

| Scenario | Allowed | p50 ms | p95 ms | p99 ms | CPU s | Decisions/s | Logical rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `allow` | 1,000 | 0.766 | 0.970 | 1.077 | 0.697 | 1,268 | 1,000 |
| `inventory-deny` | 0 | 0.785 | 0.979 | 1.124 | 0.723 | 1,250 | 1,000 |
| `policy-deny` | 0 | 0.753 | 0.973 | 1.084 | 0.687 | 1,299 | 1,000 |

The duplicate probe added zero logical rows in each run. Peak process RSS was about 49 MiB. These are single-host local decision measurements, not Mesh delivery latency, mitigation latency, recovery time, or proof of safety under coordinator compromise.
