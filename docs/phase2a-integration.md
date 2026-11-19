# Phase 2A mesh reliability integration review

This branch changes shared delivery and trust inputs. Review these contracts with the Rapid owner before integrating. The Rapid inventory matcher, template allowlist, and local policy decision order were not edited.

| Surface | Proposed change | Compatibility and review point |
| --- | --- | --- |
| HTTP | Add `POST /v1/revocations` with a `SignedRevocation` body and `202 {revocation_id, accepted}`. `POST /v1/findings` stays in place. | Revocation keys need the `revocation` role. Sequence collisions return 409 across both event kinds. |
| NATS | Keep stream `AEGIS_FINDINGS` and finding subject `aegis.findings.v1`; add `aegis.revocations.v1`. Agents filter `aegis.>` with one unique durable per stable agent ID. | Existing stream is updated to add the revocation subject. A reused agent ID shares a durable and is rejected if it points at another agent's audit DB. |
| Agent deployment | Require `AEGIS_AGENT_ID`, lowercase ASCII letters/digits/underscore/hyphen, up to 63 characters. Durable is `aegis-<agent_id>`. | Existing Compose agent deployment must set the ID and keep it stable across restarts. Each ID needs its own SQLite volume. |
| Publisher file | Accept the old `{publisher_id: base64_public_key}` form for finding-only trust. Add `{ "grants": [{publisher_id,key_id,public_key,roles,not_before,expires_at,revoked_at}] }`. | `load_publishers()` now returns `TrustStore` rather than a dictionary; `Coordinator` and `LocalPolicy` already accept it. Review callers outside this repository before merging. Keys are pinned locally in both coordinator and agent files. |
| PostgreSQL | Add `mesh_events` with unique event ID and `(publisher_id, sequence)`, plus transactional `mesh_outbox`. On startup, copy legacy `findings` and `outbox` rows into the new tables. | A broker publish acknowledgement is required before `sent_at` is set. Repeated publish after a crash is expected and uses the same `Nats-Msg-Id`. The old tables are retained for rollback. |
| Local audit | Bind a SQLite file to one `agent_id`; add revocation decisions and a permanent target `(artifact_id, digest)` ledger. A previously allowed finding reads back as denied when its digest has been revoked. | A revocation-role key may withdraw a finding from another publisher. The historical decision row remains unchanged; effective trust is computed from the ledger on read. This behavior needs Rapid owner review before any executor is built. |

The `SignedRevocation` payload and `LocalAgent.evaluate_revocation()` already existed at the baseline. This branch wires them through HTTP, persistence, JetStream, and SQLite. No artifact schema fields were changed. The event ID is the finding `artifact_id` or revocation `revocation_id`; the correlation ID on a revocation is the target finding ID.

Delivery is at least once. PostgreSQL and JetStream have independent durability; two coordinator dispatchers may publish the same event concurrently. JetStream's message ID suppresses near-term duplicates, and each agent audit supplies durable logical deduplication. The five-delivery limit still requires dead-letter operations for prolonged local audit failures. Offline catch-up remains bounded by stream retention and disk capacity.

## Local verification, 2026-11-19

- `PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 /Users/jackadams-lovell/aegis-network/.venv/bin/python -m pytest -q -p no:cacheprovider`: 16 passed; one Starlette/httpx deprecation warning.
- Python bytecode compilation passed with `PYTHONPYCACHEPREFIX=/private/tmp/aegis-mesh-pycache` to keep generated files outside the worktree.
- `AEGIS_DB_PASSWORD=local-test docker compose -p aegis_mesh_phase2a -f compose.yaml -f /private/tmp/aegis-mesh-compose-override.yaml config -q`: passed. The temporary override removed host ports.
- Isolated Compose build and start: PostgreSQL, NATS JetStream, coordinator, and two agents started. First signed finding returned `accepted: true`; both agents wrote one `allow_dry_run` row and the outbox showed `1/1` sent.
- Stopped `agent_b` and NATS, then submitted another signed finding. Outbox showed two rows with one sent. Restarted NATS and `agent_b`; outbox reached `2/2` sent and both agents held exactly two distinct decisions.
- Submitted a signed revocation for the second finding. Both agents recorded one revocation decision and one target ledger entry. Repeating the finding and revocation returned `accepted: false` for each.
- The isolated Compose project was stopped with `docker compose down`; its named volumes remain for inspection.

These checks use only synthetic local data. They do not establish production availability, bounded offline replay, external audit integrity, or any mitigation safety claim.
