# Aegis Trust integration plan

**Branch handoff · 2026-11-19.** The prototype is on `feat/aegis-trust` in `.worktrees/aegis-trust`, based on the reviewed `7744ebd7f80e6f2aabb253d5cc3ec9972c86cffd`. It uses synthetic inputs, temporary SQLite stores, and a single local target. Promotion requires a separate change review under AT-01. [Contract proposal](contracts-proposal.md)

## 1. Mesh and Identity

- Keep Phase 3C's signed event bytes, journal/outbox atomicity and durable ack rules. Add authenticated cohort replay with SPIRE-issued X.509-SVIDs, exact peer authorization and per-identity broker ACLs. Use two separate brokers in the isolated pilot. Test wrong workload, instance, broker and generation on every privileged endpoint.
- Route exact withdrawal envelopes to independent intake alongside Mesh. Publish durable quorum receipts. Define authoritative cutoffs, authenticated range delivery, mirror service and monitor gossip. Add independently retained admission and checkpoint floors plus a quorum view-change and recovery protocol. Reserve ingress and archive resources for withdrawal traffic.
- Enroll the immutable deployment identity and broker assignment at one home. Use a transactional owner row and idempotent operations. Install the deployment generation at every authority-bearing write boundary before transferring. Exercise split home, partial barriers, lost acknowledgments and restoring stale primary or target snapshots.
- Seed reviewed genesis or migration checkpoints with exact boundaries on historical coverage. Import prior denials and retain them throughout rollout and downgrade. Measure first-receipt-to-seal and first-known-denial-to-target latency under loss, pressure and restarts.

## 2. Evidence

- Onboard distinct verifier and revoker administrators and independent status operators. Use a dedicated Evidence intake path and witnessed cohort history. The initial production pilot should require 3-of-4 independently operated status signers and a common sealed epoch and policy across Mesh and Evidence.
- Preserve Phase 3A signed manifest, attestation and withdrawal encodings, pinned materials, claim digest, worker profile, two-organization corroboration, and local appraisal. Extend versioned status with withdrawals for exact bundles, attestations and keys and durable contradiction holds keyed by material scope. Verify signers and deterministic replay under historical delegated grants. Require a separately approved disposition before releasing a durable contest.
- Prove that missing, mis-scoped and equivocal status from a collector or status role never supplies positive eligibility. Exercise a receipted Evidence withdrawal and contrary observation independently of Mesh, including a loss between canary and peer stages.

## 3. Rapid and Mitigation

- Add a shadow evaluator that reads independent proofs and durable floors while preserving the existing dry-run path. Compare it with Phase 3C, audit changes attributable to new denials, and require authenticated catch-up before advancing the authoritative replay cursor or making a broker acknowledgement at a new generation.
- Bind the exact review digest to the applicable finding, Evidence attestations, trust metadata, matched cut, inventory, holder, generation, target fences and deadlines. Keep local approval separate from the coordinator. Serialize newly learned denials with target writes and recheck the latest accepted state at each stage.
- Extend the target actuator to enforce the current generation and lease at the mutation and serving paths. Use exact operator-approved inventory, canary gating and separately administered HTTP observations for marker and benign behavior at current fences. Preserve verified restrictive behavior where possible. Report recovery as unverified when observation is missing.
- Qualify staged failover, clock uncertainty and suspend, TUF root and broker credential rotation, stale backup recovery, and restricted behavior during prolonged partitions. Track ambiguous results by operation ID and require target readback.

## Pilot exit evidence

Run the original Phase 3C and Phase 4C regressions, the isolated Trust suite, independent multi-service fault tests, and a measured shadow rollout against synthetic traffic. Record authority and witness membership, organizational independence, key custody, trusted clock bounds, signed encodings, backup restore proof, and capacity for timely withdrawal and recovery. The integration owners must approve stricter behavior and availability trade-offs before any rollout beyond the isolated pilot. [Acceptance tests](acceptance-tests.md)
