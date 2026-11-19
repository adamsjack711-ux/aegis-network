# Phase 4E contract review

## Freeze adopted at intake

Phase 3C remains the historical wire reference. The runtime compatibility baseline for this phase is Phase 4D `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f`. Preserve original signed encodings and original validators, locally appraised publisher and verifier grants, exact target commitment, and local approval. The T3 lease and intent, T4 checkpoint and receipt, and T5 endorsement namespaces are opt-in lab contracts. Reuse their version and bytes only where existing semantics hold. Shared changes need review before adoption. [Phase 4 contract freeze](phase4-contract-review.md) · [Phase 4D combination](phase4d-trust-integration.md)

| Surface | Frozen behavior and review obligation |
| --- | --- |
| Mesh findings and scoped withdrawals | Keep artifacts 1.0/1.1 and native Ed25519 bytes, stable event identifiers, grant/revoker scopes and exact target owner, UUID and digest. Preserve durable journal order, idempotent replay and tombstones. An earlier same-publisher finding still needs to pass sequence policy. Check old and new readers during backlog and restart. |
| Delivery and cursors | Event, outbox and replay journal write atomically. Mark sent only after broker publish ACK. Confirm consumer ACK only after durable exact local audit. Existing recovery cursor remains monotonic. Prioritizing dispatch must handle unsent, locked, already published and stalled requests and report shared capacity limits. |
| Ownership, identity and ACK | Authenticate broker and workload context using an enrolled trust root and proof of possession. Home generation and target fences are independent of broker-local UUID lease. Keep exact local approval and intent bytes. Any generation-bound broker ACK/cursor protocol or cross-writer receipt must be versioned and reviewed, including late results from the old session. |
| Witnessed history and Evidence status | Keep T4 native intake, coverage and continuity checks and T5 exact audience, digest, expiry and contradiction behavior. An additional endpoint must use pinned per-role credentials, explicit scope and separate durable continuity. A newer or conflicting view can invalidate approval. Retain old denials across migration and boot. |
| Local mitigation and observation | Only the fixed evaluated fixture with exact operator-reviewed plan, current status, ownership and current expected fence is eligible. Fail closed before commit and preserve the restrictive recovery path. Quarantine stays distinct from confirmed protection. No remote commands or authorizing messages are added. |
| Evidence portability | Existing exact/compatible distinctions, enrolled profile and cohort scopes, signed provenance, controls, tombstones and expiry remain mandatory. Missing or failed worker outcomes remain inconclusive. A compatibility result never substitutes for independent exact status. |

## Review decisions

- **4E-ADR-01 accepted** Start every workstream from the clean 4D integration baseline. Retain T6's detached candidate and later guarded fixture as independent validation inputs with their original verdict. Reconcile test assertions individually when their adapters differ.
- **4E-ADR-02 accepted** Add no enforcement entry point, signature domain change or migration at intake. Keep local dry-run and disposable fixture profiles. Changes that preserve observable behavior can proceed behind branch-local lab adapters.
- **4E-ADR-03 pending** Review A priority changes against original per-publisher ordering and commit-before-ACK. Document whether the available proof covers pending outbox selection, live same-stream delivery or guaranteed safety during ingress pressure; each is a different boundary.
- **4E-ADR-04 pending** Review B remote generation and C external continuity anchors before depending on them in a protected writer. Include replay, partial barriers, process restart, storage restoration and denial without fallback.
- **4E-ADR-05 accepted** The historical 4B strict availability sample remains part of the evidence. Any current instrumentation or reproducible oracle result is separate; preserve fail-closed outcomes and evidence schema.

A workstream seeking a shared change supplies exact before/after fields or ordering semantics, version and rollback policy, an old/new reader and writer matrix, positive and negative tests, migration behavior for prior denials, and exact commit. Relevant owners and D review before the integration lead approves adoption.

## Lab proposals and review boundaries

| Proposal | Current boundary |
| --- | --- |
| A · Critical delivery | A separate opt-in stream and filtered replay cursor are observable transport and persistence changes. The candidate must preserve scoped signed event verification and the regular cursor, and must allow only ordered full replay to advance the historical publisher watermark. Check shared database profile enforcement, old binary cutover, dead-letter identity per stream, restart during pending publication, and protection when the separate lane is unavailable. A fast denial read cannot supply a fresh positive history. |
| B · Authenticated lab ownership | Candidate identity services use an isolated namespace for synthetic claims, exact approval, command and coarse writer receipts. Lab transport and credential boundaries can be verified separately from native JetStream consumer ACK/lease fencing. A local TLS controller on one machine does not establish independent identity administration or physical fault tolerance. |
| C · Unified history/status epoch | A separately namespaced native-record experiment can corroborate Mesh and Evidence at one cut. It must stay separate from the frozen T5 writer appraisal unless equivalent denial behavior is demonstrated. With a 3-of-4 roster, a sole witness can hear a withdrawal that three other witnesses have not received. Until quorum admission, that intake may have narrower denial coverage than the baseline T5 2-of-2 policy. Capacity exhaustion must leave unknown status held. |

### 4E-ADR-03 · Approved for the local priority profile

Review of A implementation `6e8bedccb184f3b4268670c93bc22310234c4f5e` approves its opt-in interface for the disposable lab. The canonical event and journal commits and signed finding and withdrawal bytes are preserved. Separate withdrawal transport and filtered replay may establish a local exact denial early. Only ordered replay advances the ordinary withdrawal watermark and cursor. Legacy stream and deduplication identities remain stable. Critical dead-letter records add stream attribution so matching numeric sequences in different streams cannot suppress the durable copy.

The PostgreSQL profile name prevents updated coordinators with inconsistent configurations from sharing a repository. Bootstrap across profiles is an offline lab operation with existing participants stopped, because older binaries cannot enforce the new profile. The separate admission limits reserve a bounded envelope. Findings and critical work still share PostgreSQL, network, broker, storage, host and legacy broker-lease ownership. This approval conveys no absolute delivery bound, broker generation-bound ACK proof, or release approval. Report the crash-before-audit sample separately from observed safety transitions. [Independent authority boundary](phase4e-architecture.md)
