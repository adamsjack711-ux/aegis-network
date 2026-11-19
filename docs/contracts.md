# Service contracts, v1

## HTTP ingestion

`POST /v1/findings` accepts a JSON `SignedFinding` matching `src/aegis/artifact.py`. Success is HTTP 202 with `artifact_id` and `accepted` (`true` for new, `false` for exact duplicate). Unknown publisher, expired finding, invalid signature, or invalid schema returns 400/422. An already-used publisher sequence returns 409. The coordinator does not fetch `evidence.uri`.

Signature input is `json.dumps(finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. Signature is base64 of raw Ed25519 output. IDs are UUIDs; timestamps are RFC 3339 with timezone. `schema_version` is exactly `1.0`. All fields are required. Producers should use `aegis.artifact.sign` to avoid canonicalization mismatches.

## Event delivery

Stream `AEGIS_FINDINGS` carries findings on `aegis.findings.v1` and revocations on `aegis.revocations.v1`. The body is identical to the submitted signed envelope. Header `Nats-Msg-Id` is the finding artifact ID or revocation ID. Every agent requires a stable `AEGIS_AGENT_ID`, uses the independent durable `aegis-<agent_id>`, and binds one SQLite audit file to that ID. A consumer independently verifies the body and local policy, persists a decision, then calls `ack_sync()`. Delivery can repeat. A malformed event is terminated and logged; a transient audit failure is retried, bounded by consumer `max_deliver=5`.

## Agent output

SQLite `decisions` records one authenticated historical decision per artifact: SHA-256 payload digest, publisher, sequence, `allow_dry_run` or `deny`, stable reason code, reason, and timestamp. `rejected_events` stores unauthenticated attempts without changing replay state. `revocation_decisions` and `revoked_artifacts` hold signed withdrawals; `decision_overrides` durably records a tightened local denial. Effective reads deny a revoked digest or an overridden finding while preserving its original row. Exported finding rows include agent, event, and correlation IDs; a full versioned signed export remains undefined. `allow_dry_run` means only that a trusted, unexpired finding matched exact local inventory and local allowlist in an authorized lab. It never triggers an action.

## Phase 2A signed revocation contract (integration review)

`POST /v1/revocations` accepts `SignedRevocation` with `kind: "revocation"`, `key_id`, `revocation` and Ed25519 `signature`. The signed payload binds `schema_version`, `revocation_id`, `publisher_id`, monotonic `sequence`, `issued_at`, `expires_at`, `target_artifact_id`, `target_sha256`, and `reason`. Success is HTTP 202 with `revocation_id` and `accepted`. The revocation subject is `aegis.revocations.v1`; its `Nats-Msg-Id` is `revocation_id`. An agent with a locally pinned revocation-role key records the target ID and digest permanently, including when the revocation precedes the finding. An expired target finding can still be revoked while the revocation itself is valid. A revocation never requests execution. See [Phase 2C integration review](phase2c-integration.md) for tested behavior and limits.

Key rotation, ordering across publishers, and unbounded offline catch-up still need design and failure tests.

Verification attestations, template parameters, independent test evidence, execution request, preflight result, health signal, rollback token, and signed audit export remain undefined. They must be specified and tested before enabling mitigation.
