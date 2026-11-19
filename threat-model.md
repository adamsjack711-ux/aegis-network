# Threat model

## Assets, attackers, and trust boundaries

Assets: local policy authority, inventory, audit history, private publisher keys, artifact integrity, evidence provenance, and lab availability. Untrusted inputs enter through the HTTP submission body and the NATS event. Evidence URIs are opaque references and are never fetched by this slice. The coordinator, NATS, and publishers can be compromised independently; local policy and pinned public keys are a distinct trust boundary.

| Threat | Current control | Remaining risk / planned control |
| --- | --- | --- |
| Malicious or compromised publisher | Per-key role, validity interval, local revocation state, strict schema, lab-only applicability, template allowlist and inventory match. | A trusted bad finding can still influence a dry-run decision. Require independent reproduction and multi-role approval before enforcement. |
| Poisoned finding or evidence | Signed canonical payload, SHA-256 evidence reference, no evidence URL fetch. | A digest proves identity, not truth. Add isolated verifier attestations and confidence gates. |
| Compromised coordinator or event bus | Agent independently rechecks signature, expiry, publisher key, sequence, and local policy. | Coordinator can withhold or delay findings; use transparency, peer reconciliation, and local feed fallback later. |
| Replay or duplicate event | Expiry, monotonic sequence, stable event ID, per-agent idempotent audit, JetStream message ID. | Clock skew or agent database loss can weaken replay defense; add trusted time and backup/recovery design. |
| Shared consumer accidentally load balances | Durable consumer named from stable agent ID; separate local audit per deployment. | Reusing an agent ID or SQLite path would merge delivery state; configuration validation and deployment review remain necessary. |
| Broker outage or network partition | Transactional outbox and reconnecting clients; durable stream and consumers resume. | Recovery is bounded by broker retention, retry policy, and disk capacity; prolonged outages need operational monitoring. |
| Malicious mitigation | Artifact carries only an allowlisted template ID; current code never executes it. | Future template implementation needs sandbox, privilege boundaries, preflight, health checks, and rollback. |
| Compromised agent | No direct enforcement in this slice; local audit separate from coordinator. | A compromised agent can forge its own audit or inventory. Add attestation, restricted service account, and external audit replication. |
| Prompt injection via evidence or LLM | No LLM in current path; no evidence content fetched. | Later investigator must run in isolated lab, treat all source text as data, and lack publishing or execution credentials. |
| Secrets in messages/logs | Payload schema excludes secrets; logging emits artifact digest and decision only. | Operators must keep keys and database credentials out of general logs and backups. |
| Denial of service / malformed payload | Pydantic bounds fields, strict known fields, bounded consumer delivery. | Add HTTP rate/size limits, quotas, resource budgets, and dead-letter review. |

## Safety invariants

Only authorized local lab inventory is eligible. An artifact signature is never local authorization. No code path in this slice changes host or application state. Future enforcement must fail closed if verification, policy, preflight, or rollback preparation fails. No public scanning, uncontrolled exploitation, production mutation, or external artifact distribution is authorized by this repository.
