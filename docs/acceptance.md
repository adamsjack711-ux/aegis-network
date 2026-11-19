# Acceptance criteria and test plan

## Current vertical slice

- [x] Known publisher signs a versioned finding; coordinator validates the signature and expiry.
- [x] Coordinator persists the finding and outbox row in one transaction; live Compose check found one finding and one sent outbox row.
- [x] NATS JetStream dispatcher publishes pending findings with a stable message ID; live agent received the synthetic event.
- [x] Agent independently validates the signature against locally loaded trust, checks exact inventory and local template policy, and writes an audited dry-run decision.
- [x] Tests cover tampering, expiry, unknown fields, duplicate delivery, stale sequence, invalid-signature watermark poisoning, no inventory match, and local denial.
- [x] Container integration with live PostgreSQL and JetStream on 2026-11-19: initial POST accepted, replay returned `accepted: false`, and local SQLite contained one `allow_dry_run` decision.

## Phase 2A mesh reliability, local branch

- [x] Two independently named JetStream durables and separate SQLite volumes received the same synthetic finding.
- [x] PostgreSQL kept a finding pending while NATS was stopped; after broker and paused agent restart, both agents had two distinct audited decisions and the outbox was fully sent.
- [x] A signed revocation reached both agents and populated both durable revocation ledgers. Repeated finding and revocation submissions were idempotent.
- [x] Unit tests cover broker publish failure, database failure after broker acknowledgement, audit failure before consumer acknowledgement, role denial, invalid signature, revocation before and after finding, and agent restart deduplication.
- [x] Reconcile the Mesh and Rapid event, trust, revocation, agent-ID, audit, and acknowledgement contracts in [Phase 2C integration review](phase2c-integration.md). Review handoff is complete; no merge into `master` has occurred.

## Research questions and measurable gates

**A — latency:** In Phase 4/5, start timer at receipt of a independently verified finding. End at successful, locally authorized mitigation health check. Record p50/p95/p99, target eligibility, and failures over repeated trials. The proposed gate is p95 ≤30 seconds for eligible lab deployments, with zero unauthorized actions and verified rollback. The current dry-run path cannot answer this question.

**B — compute:** Use the same vulnerability corpus, hardware budget, and success definition for independent analysis per deployment versus shared verification plus local matching. Measure CPU seconds, memory, LLM tokens, and dollars if applicable at 10, 100, and 1,000 simulated deployments. Target aggregate compute ratio ≥10x with comparable verification coverage and false-positive rate. No benchmark exists yet.

**C — coordinator compromise:** Inject altered, replayed, withheld, and forged events through a compromised coordinator fixture. A locally unauthorized template or publisher must never yield an executable approval. Measure denial counts, delays, and audit completeness. This slice tests local dry-run independence but not actual enforcement.

## Safety gates before any execution

Independent container reproduction; evidence subject binding; key rotation; least-privilege executor; preflight snapshot; health-check oracle; automatic rollback; broader fault injection; and operator approval for any production or external distribution remain incomplete. Signed artifact revocation is implemented for dry-run trust decisions only.
