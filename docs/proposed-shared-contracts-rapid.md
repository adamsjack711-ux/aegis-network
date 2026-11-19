# Proposed shared contract changes — review separately

These proposals are **not implemented** in Mesh, the event bus, or the v1 signed finding schema by this branch.

1. **Agent identity and durable delivery:** define a stable deployment ID, its permitted characters, and a one-to-one mapping to a JetStream durable name and SQLite audit path. Reject duplicate deployment IDs at startup. Include the deployment ID in decision exports.
2. **Versioned decision export:** define an agent audit export schema with `agent_id`, `event_id`, `correlation_id`, payload digest, `outcome`, stable `reason_code`, human-readable reason, `dry_run`, and UTC decision timestamp. Specify that an original finding row is historical and a later signed revocation changes its effective result.
3. **Revocation delivery:** accept a signed revocation envelope on a versioned subject with an independent revocation role, artifact ID, exact finding digest, sequence, and expiry. A revocation can arrive before a finding. Define ordering and retention across publisher key rotation before relying on it operationally.
4. **Evidence trust:** define verifier attestations that bind the exact signed finding digest, affected software identity, test environment, and result. Evidence URI and SHA-256 alone identify bytes but do not establish truth. No verifier or execution authority should be inferred from the current finding envelope.

Adopting any of these requires separate contract review, Mesh changes, and end-to-end tests. This branch does not enable enforcement.
