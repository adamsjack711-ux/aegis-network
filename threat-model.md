# Threat model

## Assets, attackers, and trust boundaries

Assets: local policy authority, inventory, audit history, private publisher keys, artifact integrity, evidence provenance, and lab availability. Untrusted inputs enter through the HTTP submission body and the NATS event. Evidence URIs are opaque references and are never fetched by this slice. The coordinator, NATS, and publishers can be compromised independently; local policy and pinned public keys are a distinct trust boundary.

| Threat | Current control | Remaining risk / planned control |
| --- | --- | --- |
| Malicious or compromised publisher | Per-key role, validity interval, local revocation state, strict schema, lab-only applicability, template allowlist and inventory match. | A trusted bad finding can still influence a dry-run decision. Require independent reproduction and multi-role approval before enforcement. |
| Poisoned finding or evidence | Signed canonical payload, SHA-256 evidence reference, no evidence URL fetch. | A digest proves identity, not truth. Add isolated verifier attestations and confidence gates. |
| Compromised coordinator or event bus | Agent independently rechecks signature, expiry, publisher key, sequence, and local policy. | Coordinator can withhold or delay findings; use transparency, peer reconciliation, and local feed fallback later. |
| Replay or duplicate event | Unique event ID, coordinator finding sequence monotonicity, per-agent sequence collision checks, idempotent audit, and late signed revocation acceptance. | Clock skew, database loss, or a withheld coordinator journal can weaken completeness; add trusted time and independently witnessed replay. |
| Shared consumer accidentally load balances | Runtime UUIDv4 deployment ID, independent durable and audit, and broker KV compare-and-swap lease. | A broker administrator or cloned ID on a different broker can spoof identity; add authenticated enrollment and cross-cluster registry. |
| Broker outage or network partition | Transactional outbox, bounded file-backed stream, unlimited consumer retry, dead-letter review, and PostgreSQL journal catch-up after stream loss. | PostgreSQL loss, full DLQ, prolonged outages, and missing alerts remain; test backup/restore and capacity limits. |
| Malicious mitigation | Artifact carries only an allowlisted template ID; current code never executes it. | Future template implementation needs sandbox, privilege boundaries, preflight, health checks, and rollback. |
| Compromised agent | No direct enforcement in this slice; local audit separate from coordinator. | A compromised agent can forge its own audit or inventory. Add attestation, restricted service account, and external audit replication. |
| Prompt injection via evidence or LLM | No LLM in current path; no evidence content fetched. | Later investigator must run in isolated lab, treat all source text as data, and lack publishing or execution credentials. |
| Secrets in messages/logs | Payload schema excludes secrets; logging emits artifact digest and decision only. | Operators must keep keys and database credentials out of general logs and backups. |
| Denial of service / malformed payload | Pydantic bounds fields, strict known fields, bounded consumer delivery. | Add HTTP rate/size limits, quotas, resource budgets, and dead-letter review. |

## Safety invariants

Only authorized local lab inventory is eligible. An artifact signature is never local authorization. No code path in this slice changes host or application state. Future enforcement must fail closed if verification, policy, preflight, or rollback preparation fails. No public scanning, uncontrolled exploitation, production mutation, or external artifact distribution is authorized by this repository.
