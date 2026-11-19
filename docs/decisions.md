# Architectural decisions

## ADR-001 — Local authority

**Decision:** agents pin publisher keys and evaluate their own policy and inventory. Coordinator validation is an early filter. **Reason:** a compromised coordinator cannot authorize local action. **Consequence:** deployments manage trust configuration independently.

## ADR-002 — Exact version matches first

**Decision:** v1 accepts enumerated affected versions and exact package URLs. **Reason:** package ecosystem range semantics vary and can create false positives. **Consequence:** coverage is intentionally low until OSV-compatible range evaluators are tested.

## ADR-003 — Signed JSON envelope

**Decision:** canonical JSON signed with Ed25519 for the smallest slice. **Reason:** inspectable bytes and a simple verifier. **Consequence:** this is not in-toto DSSE or TUF; migration requires a new schema and trust model.

## ADR-004 — Transactional outbox with JetStream

**Decision:** write the finding and outbox row in one PostgreSQL transaction, then publish to a durable NATS stream. **Reason:** a database commit must survive a transient broker outage. **Consequence:** delivery is at least once and consumers must deduplicate.

## ADR-005 — No enforcement in v1

**Decision:** a template ID may be considered by policy but is never run. **Reason:** revocation, independent verification, rollback, and runtime isolation are not yet implemented. **Consequence:** the current result is evidence for the decision path only, not safety or mitigation latency.
