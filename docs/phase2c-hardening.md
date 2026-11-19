# Phase 2C integration and trust hardening

## Scope and starting point

This work started from clean `integration/phase2c` at `4973df1`. The [Phase 2C integration report](phase2c-integration.md) and [threat model](../threat-model.md) were read before code changes. Work remains on the integration branch/worktree; neither feature branch nor `master` was merged or edited. All findings, revocations, audits, replay, and benchmarks use synthetic local data and produce dry-run decisions only. There is no AI, mitigation executor, production target, or Daybreak connection.

## Contract changes

1. **Deployment identity.** Runtime `AEGIS_AGENT_ID` is now a canonical UUIDv4. `aegis-<uuid>` is the durable. Before subscribing or processing, an agent atomically claims a 30-second JetStream KV lease keyed by its UUID. It renews by compare-and-swap and checks the lease before every event and journal replay. A second active process with the same ID cannot consume under the same broker account. Graceful shutdown releases the lease; abrupt restart waits up to 45 seconds for expiry. The local SQLite identity guard remains. This is broker-scoped active uniqueness, not cryptographic identity across independent brokers; see R-01 in the [risk register](phase2c-risk-register.md).
2. **Revocation scope.** Signed revocation schema `1.1` binds `target_publisher_id`, target artifact ID, and exact finding digest. A locally pinned revoker grant has an explicit `revocation_publishers` set; omitted scope defaults to its own publisher only. Coordinator and agent both enforce it. Legacy signed `1.0` revocations remain parseable with their original canonical signature bytes but cannot be newly accepted without a target publisher. Previously committed legacy ledger entries stay denied. The disposable Compose lab now uses separate finding and revocation keys.
3. **Ordering and replay.** Coordinator rejects a finding whose publisher sequence does not increase. A unique, signed late revocation is still accepted and applied as a permanent denial. Agents persist one logical decision per event ID, reject sequence collisions, keep older findings denied, and accept late revocations with unique publisher sequence values. PostgreSQL inserts an immutable signed-event journal row in the same transaction as the event and outbox row. A global transaction lock ensures journal positions become visible in commit order across publishers. Each SQLite audit persists a replay cursor only after an event decision commits. `GET /v1/events` pages signed envelopes from PostgreSQL; agents recheck their own trust, signature, role, time, scope, and policy during catch-up. A detected gap or invalid revocation stops the agent rather than advancing the cursor. A valid signed revocation can be replayed after its envelope expiry while its local key grant remains valid.
4. **Retention and dead letters.** `AEGIS_FINDINGS` uses file storage, limits retention, 24-hour max age, 64 MiB max bytes, and discard-new at capacity. A rejected publish leaves its PostgreSQL outbox row pending. `AEGIS_DEAD_LETTERS` is a separate file-backed 7-day/64 MiB stream. Consumers use unlimited broker redelivery; after five transient local audit failures, a finding is copied to the dead-letter stream and terminated only after the copy is acknowledged. A failed revocation is copied for review but remains unacknowledged until its local denial ledger commits. Malformed input is terminated only after its dead-letter copy is acknowledged. `scripts/review_dead_letters.py` prints read-only metadata and a body hash, without replaying payloads.
5. **Recovery beyond stream retention.** On startup and every five seconds, agents reconcile against the PostgreSQL journal. A fresh signed finding and revocation were recovered by a stopped agent after the entire findings stream was purged in the isolated Compose lab. The agent then continued normal JetStream delivery. The journal is the recovery source when the broker's retained copy is gone; its completeness and availability are limitations in the [risk register](phase2c-risk-register.md).

The original local policy still requires a valid local grant, exact inventory identity, lab authorization, and a local template allowlist. `allow_dry_run` cannot invoke a mitigation.

## Migration notes

- Existing human-readable agent IDs do not satisfy the new runtime UUIDv4 contract. The Compose fixture uses new UUIDs and new audit volumes; old volumes are left intact. Reusing an old audit under a new ID is refused by design. A real migration needs an operator-approved identity and audit transfer procedure.
- `mesh_journal` backfills existing PostgreSQL `mesh_events` on coordinator startup. The backfill preserves signed envelopes; historical cross-publisher ordering cannot be reconstructed from the old schema. New entries receive commit-ordered positions.
- SQLite adds a recovery cursor and a publisher-bound revocation target table. Old revocation ledger rows remain effective exact-digest denials. New v1.1 rows cannot be blocked by a legacy revoker's old primary key.
- Legacy unbound v1.0 revocations require reissuance as v1.1 to recover from an empty agent audit. This is an intentional fail-closed protocol break.

## Verification environment and commands

MacBookPro18,3 with Apple M1 Pro (10 CPU cores), 32 GB RAM; macOS 27.0.1 ARM64; host Python 3.15.2; Docker client 29.8.0, server 29.5.2, Compose 5.5.1. Containers used Python 3.12, PostgreSQL 16.16, and NATS 2.10.29. Host dependencies included `nats-py` 2.17.0, Psycopg 3.3.9, FastAPI 0.165.0, Pydantic 2.14.4, httpx 0.28.1, and pytest 9.2.0. The project `aegis_phase2c_hardening` published only loopback ports defined in `compose.hardening.yaml`; its keys and findings were disposable synthetic lab data.

Commands from the Phase 2C worktree:

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 /Users/jackadams-lovell/aegis-network/.venv/bin/python -m pytest -q -p no:cacheprovider
PYTHONPATH=src /Users/jackadams-lovell/aegis-network/.venv/bin/python scripts/setup_lab.py
AEGIS_DB_PASSWORD=local-hardening docker compose -p aegis_phase2c_hardening -f compose.yaml -f compose.hardening.yaml config -q
AEGIS_DB_PASSWORD=local-hardening docker compose -p aegis_phase2c_hardening -f compose.yaml -f compose.hardening.yaml up -d --build
PYTHONPATH=src AEGIS_DB_PASSWORD=local-hardening /Users/jackadams-lovell/aegis-network/.venv/bin/python scripts/phase2c_live.py --project aegis_phase2c_hardening --override compose.hardening.yaml --postgres postgresql://aegis:local-hardening@127.0.0.1:15432/aegis --samples 20
PYTHONPATH=src /Users/jackadams-lovell/aegis-network/.venv/bin/python scripts/review_dead_letters.py --nats nats://127.0.0.1:14222 --limit 10
AEGIS_DB_PASSWORD=local-hardening docker compose -p aegis_phase2c_hardening -f compose.yaml -f compose.hardening.yaml up -d --build
docker kill --signal=KILL aegis_phase2c_hardening-agent_b-1
AEGIS_DB_PASSWORD=local-hardening docker compose -p aegis_phase2c_hardening -f compose.yaml -f compose.hardening.yaml start agent_b
AEGIS_DB_PASSWORD=local-hardening docker compose -p aegis_phase2c_hardening -f compose.yaml -f compose.hardening.yaml down
```

## Results

The final local suite passed **38 tests** (one third-party Starlette/httpx deprecation warning). Tests cover UUID rejection, active lease collision and takeover, ambiguous SQLite identity, scoped and legacy revocation denial, late revocation, stale finding and sequence collision, expired-but-signed revocation replay, replay cursor gaps, dead-letter publish ordering, and an unaudited revocation that keeps retrying after dead-letter copy. Python compilation and Compose configuration parsing passed.

The clean Compose project built and started PostgreSQL, NATS, the coordinator, and two UUID-identified agents. Both agents persisted the same three signed findings and two signed revocations at the integration checkpoint, with two target-ledger entries each. A forced duplicate JetStream delivery did not add a logical row. An invalid signature returned HTTP 400. A broker stop left an outbox row pending; restart sent it and both agents caught up. Agent restart preserved the audits. A second active claimant of an agent UUID was blocked by the broker lease. A signed out-of-scope revocation returned HTTP 400; a stale finding sequence returned HTTP 409. After `agent_b` stopped, the entire findings stream was purged. The missed finding **and its signed revocation** were then restored from the PostgreSQL journal into `agent_b`'s audit. Two malformed deliveries, one per agent, entered the dead-letter stream and were read by the metadata-only review tool. PostgreSQL held **68 journal rows**, positions 1 through 68, after the benchmark. The findings stream reported 86,400-second max age and 67,108,864-byte max size; both streams reported discard-new, and the consumer reported unlimited broker redelivery.

An additional unclean-restart check used the retained lab volumes after the main run. `agent_b` was killed with SIGKILL and immediately started again. Its startup replay requested journal events after position 68, and read-only SQLite inspection showed recovery cursor **68**, **65** finding decisions, and **3** revocation decisions. This checks that an abrupt restart can reclaim its expired lease and retain local audit state; it does not prove recovery after losing the SQLite volume.

The benchmark reused the Phase 2C method: 20 unique synthetic findings per scale, HTTP submission start to local SQLite commit, distinct UUID durables and audit files in one host Python process. It is one run per scale; all outcomes were dry-run. Results from the final clean run:

| Simulated agents | Committed / expected | Coverage | p50 ms | p95 ms | p99 ms | Host CPU s | Elapsed s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 60 / 60 | 100% | 157.838 | 186.367 | 190.581 | 0.092 | 0.312 |
| 10 | 200 / 200 | 100% | 179.456 | 337.528 | 343.681 | 0.200 | 0.534 |
| 100 | 2,000 / 2,000 | 100% | 477.600 | 538.790 | 562.450 | 1.401 | 1.574 |

Each scale had zero duplicate logical rows and zero unexpected allow decisions. Peak host Python RSS by run was 98,484,224, 100,417,536, and 125,255,680 bytes respectively; RSS is a cumulative process high-water mark. The live run's deliberate broker stop produced expected connection errors while disconnected. An earlier integration attempt exposed an abrupt-restart lease collision; startup now waits for lease release or expiry, and the final clean run passed. An intermediate harness comparison of the NATS discard enum/string failed before being corrected; no service behavior changed for that fix.
After the live run, malformed replay JSON and a parsed revocation's local `ValueError` were tightened to stop replay or retain the source message respectively. The final 38-test suite covers those paths; the live scenario was not repeated for these error-only changes.
The Compose project was stopped with `docker compose down`; its named PostgreSQL, NATS, and agent audit volumes remain for review.

## Limits and references

The benchmark remains a one-run, one-host fanout measurement with 20 findings per scale. Its simulated consumers use UUID durables and independent audits but do not acquire runtime identity leases, so these timings exclude lease round trips. It does not measure production availability, mitigation, independent verifier compute, or a 30-second mitigation gate. The PostgreSQL replay endpoint currently lacks client authentication and a witnessed completeness proof. A broker operator can tamper with leases, and the NATS KV client API is marked experimental. See the [risk register](phase2c-risk-register.md) for the full residual list and next gates.

NATS references: [JetStream storage and retention](https://docs.nats.io/concepts/jetstream) and the [nats.py JetStream/KV API](https://nats-io.github.io/nats.py/modules.html).
