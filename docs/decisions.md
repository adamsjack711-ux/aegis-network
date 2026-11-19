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

## ADR-006 — Freeze Phase 4 contracts at Phase 3C

Accepted for Phase 4 planning. Use `7744ebd7f80e6f2aabb253d5cc3ec9972c86cffd` as the compatibility reference. Keep the Phase 2 dry-run contract described in ADR-005. Phase 3C adds an explicitly approved disposable-fixture path with separately appraised evidence. Preserve historical decisions and effective denials when internal representations evolve. A reviewed and versioned proposal is required for a shared compatibility or authority change. [Contract freeze](phase4-contract-review.md)

## ADR-007 — Keep independent roles and target authority local

Accepted for Phase 4. Mesh can distribute findings and status but cannot issue capabilities. A verifier or cache can contribute a scoped, signed observation. Rapid owns the local trust and inventory appraisal. An exact plan gets authority only from a local approver, and writes must compare target fences. Protection requires a separate observation of all declared marker and benign paths. Treat a replica or observer sharing a host as a distinct process role but a shared fault domain. Approve any proposed distributed authority design separately. [Phase 3C decision and confirmation path](phase3c-integration.md)

## ADR-008 — Treat unknown status completeness as a protection release blocker

Accepted for Phase 4. The reachable Phase 3C journal may present a consistent view while withholding a valid withdrawal. Time freshness, local signature checks and broker-confirmed delivery alone do not establish completeness. A proposed solution needs an independently governed status path, freshness and replay rules, and explicit fail policy. A missing or conflicting view must block writes and prevent continued confirmation. An already leased lab target must maintain restrictive recovery. The particular witness protocol and fault quorum remain open proposals. [Risk P4-01](phase4-risk-register.md)

## ADR-009 — Integrate with pinned evidence in the order 4A, 4B, 4C

Accepted for Phase 4. Establish and test the distributed transport before layering Evidence portability, then exercise independent validation on that exact combination. Review each explicit commit list and compatibility change. Use a new integration candidate and keep original worktrees available. Independent validation can develop in parallel. Publish test, build, benchmark and fault records for the same release candidate. [Integration plan](phase4-integration-plan.md)

## ADR-010 — Compare only equivalent workloads and safety gates

Accepted for Phase 4. Keep the Phase 3C workload as the reference. Pair each candidate with a fresh control and retain the original Phase 3 results as historical evidence. Freeze eligibility, observer criteria, repeated trials, and negative outcomes before measuring. A successful decision, write, confirmed protection, and safe hold are different outcomes with different denominators. Report attainable scope and uncertainty with each result. [Benchmark protocol](phase4-integration-plan.md#benchmark-protocol)
