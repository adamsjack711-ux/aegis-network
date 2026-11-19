# Service contracts, v1

## HTTP ingestion

`POST /v1/findings` accepts a JSON `SignedFinding` matching `src/aegis/artifact.py`. Success is HTTP 202 with `artifact_id` and `accepted` (`true` for new, `false` for exact duplicate). Unknown publisher, expired finding, invalid signature, or invalid schema returns 400/422. An already-used publisher sequence returns 409. The coordinator does not fetch `evidence.uri`.

Signature input is `json.dumps(finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. Signature is base64 of raw Ed25519 output. IDs are UUIDs; timestamps are RFC 3339 with timezone. `schema_version` is exactly `1.0`. All fields are required. Producers should use `aegis.artifact.sign` to avoid canonicalization mismatches.

## Event delivery

Stream `AEGIS_FINDINGS` carries findings on `aegis.findings.v1` and revocations on `aegis.revocations.v1`. The body is identical to the submitted signed envelope. Header `Nats-Msg-Id` is the finding artifact ID or revocation ID. Every runtime agent requires a stable canonical UUIDv4 `AEGIS_AGENT_ID`, uses the independent durable `aegis-<agent_id>`, binds one SQLite audit file to that ID, and holds an active broker KV lease. A consumer independently verifies the body and local policy, persists a decision, then calls `ack_sync()`. Delivery can repeat. A malformed event is copied to `AEGIS_DEAD_LETTERS` before termination. Broker redelivery is unlimited; after five local audit failures a finding is dead-lettered and terminated, while an unaudited revocation remains pending until its denial ledger commits. `AEGIS_FINDINGS` has 24-hour/64 MiB file-backed limits and discard-new at capacity. Agents reconcile missing events from the PostgreSQL signed-event journal after stream loss.

## Agent output

SQLite `decisions` records one authenticated historical decision per artifact: SHA-256 payload digest, publisher, sequence, `allow_dry_run` or `deny`, stable reason code, reason, and timestamp. `rejected_events` stores unauthenticated attempts without changing replay state. `revocation_decisions` and `revoked_artifacts` hold signed withdrawals; `decision_overrides` durably records a tightened local denial. Effective reads deny a revoked digest or an overridden finding while preserving its original row. Exported finding rows include agent, event, and correlation IDs; a full versioned signed export remains undefined. `allow_dry_run` means only that a trusted, unexpired finding matched exact local inventory and local allowlist in an authorized lab. It never triggers an action.

## Phase 2C scoped signed revocation contract

`POST /v1/revocations` accepts `SignedRevocation` with `kind: "revocation"`, `key_id`, `revocation` and Ed25519 `signature`. New revocations use schema version `1.1`; the signed payload binds `revocation_id`, `publisher_id`, unique publisher `sequence`, `issued_at`, `expires_at`, `target_publisher_id`, `target_artifact_id`, `target_sha256`, and `reason`. The locally pinned revocation-role grant must explicitly permit the target publisher; omitted scope permits only the revoker's own publisher. Success is HTTP 202 with `revocation_id` and `accepted`. A signed, unique late revocation can arrive after higher publisher sequences and still withdraw its exact target. The revocation subject is `aegis.revocations.v1`; its `Nats-Msg-Id` is `revocation_id`. An agent records the target publisher, ID, and digest permanently, including when the revocation precedes the finding. A signed revocation can be recovered after its envelope expiry while its locally pinned grant remains valid. Legacy `1.0` revocations remain signature-readable but are denied on new ingestion because they lack a signed target publisher. A revocation never requests execution. See [Phase 2C hardening review](phase2c-hardening.md) for migration and limits.

Key rotation, independently witnessed ordering across publishers, and recovery after PostgreSQL journal loss still need design and failure tests.

Verification attestations, template parameters, independent test evidence, execution request, preflight result, health signal, rollback token, and signed audit export remain undefined. They must be specified and tested before enabling mitigation.
