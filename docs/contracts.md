# Service contracts, v1

## HTTP ingestion

`POST /v1/findings` accepts a JSON `SignedFinding` matching `src/aegis/artifact.py`. Success is HTTP 202 with `artifact_id` and `accepted` (`true` for new, `false` for exact duplicate). Unknown publisher, expired finding, invalid signature, or invalid schema returns 400/422. An already-used publisher sequence returns 409. The coordinator does not fetch `evidence.uri`.

Signature input is `json.dumps(finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. Signature is base64 of raw Ed25519 output. IDs are UUIDs; timestamps are RFC 3339 with timezone. `schema_version` is exactly `1.0`. All fields are required. Producers should use `aegis.artifact.sign` to avoid canonicalization mismatches.

## Event delivery

Stream `AEGIS_FINDINGS`, subject `aegis.findings.v1`, body identical to submitted signed envelope. Header `Nats-Msg-Id` is artifact ID. A consumer must independently verify body and local policy, then persist a decision before acknowledgement. Delivery can repeat. A malformed event is terminated and logged; a transient audit failure is retried, bounded by consumer `max_deliver=5`.

## Agent output

SQLite `decisions` records one authenticated decision per artifact: SHA-256 payload digest, publisher, sequence, `allow_dry_run` or `deny`, reason, and timestamp. `rejected_events` stores unauthenticated attempts without changing replay state. `allow_dry_run` means only that a trusted, unexpired finding matched exact local inventory and local allowlist in an authorized lab. It never triggers an action.

## Proposed revocation contract (unimplemented)

A future `SignedRevocation` envelope should bind `schema_version`, `revocation_id`, `publisher_id`, monotonic `sequence`, `issued_at`, `target_artifact_id`, `target_sha256`, `reason`, and Ed25519 signature. The local trust store should pin a separate revocation role and accept revocation even when the target finding has expired. A revocation must permanently deny use of the target digest and never itself request execution. Key rotation, ordering across publishers, and offline catch-up still need an ADR and failure tests. This contract is **not accepted by v1 code**.

Verification attestations, template parameters, independent test evidence, execution request, preflight result, health signal, rollback token, and signed audit export remain undefined. They must be specified and tested before enabling mitigation.
