# Phase 4D trust integration

## Intake and compatibility record

This plan was recorded from Phase 3C `7744ebd7f80e6f2aabb253d5cc3ec9972c86cffd` before source changes. Master had existing changes. Source worktrees are read-only for this integration. The Phase 4 contract freeze, threat models, all three feature handoffs, the Trust architecture and proposed contracts, and the completed identity and transparency research were reviewed.

| Input | Reviewed ancestry and interface decision |
| --- | --- |
| Phase 4 architecture `e8e03ee` | Child of Phase 3C. Import architectural and measurement decisions and frozen contract references. |
| 4A `bc1b52f66494c0f49ca085eb494bf534212cfba0` | Descends from Phase 3C. Mesh subject relocation and optional runtime callbacks preserve signed bytes, audit-before-ack and default behavior. Separate-process harness and retained timings are candidates for regression. One broker account still supplies legacy ownership. SSH peer tooling is retained for its authorized lab role. This integration exercises loopback only. |
| 4B `e3a526d4109f0879a8da649c9c9b680bfc82c59a` | Child of Phase 3C. Explicitly enrolled experimental portability profile, new synthetic worker and local relation appraisal. Preserve original worker and signed manifest semantics. Keep compatibility results outside the mitigation gate. The handoff records four strict oracle/provenance misses in a heterogeneous 1,000-deployment run. |
| 4C `52a4dc43f129e1087fb29b3410dcda389f324c1b` | Child of Phase 3C. Import unchanged defensive tests and threat proposals. 4C-01, 4C-02 and 4C-04 are the three High findings. |
| Trust prototype `300252d9c09f52681db8c947f65dd466776faef0` | Child of Phase 3C. Full-prefix SHA-256 commitment, distinct Ed25519 domains, simulated authority keys and broker names, a separate host-local anchor, and a fixed synthetic writer. The prototype's signed `Event`, `Cut`, `EvidenceStatus` and `Plan` are different from native Mesh, Evidence, and mitigation records. No conversion or signature substitution is authorized. Test as a bounded prototype and keep distributed target writes disabled. |
| T3, T4, T5 and T6 status | T3 is present as a separate repository based on 4C; T4 is present as a separate repository based on 4A plus the 4C handoff; T5 is a linked worktree based on 4C and showed in-progress local changes. T6 starts from the reviewed 4C cases and this integration review. No additional active agent appeared in this task tree. Only pinned reviewed work is imported; in-flight files and histories are preserved. |

The imports overlap in `STATUS.md`. Reconcile that file by preserving the relevant source handoffs and recording the integration status. The shared wire contracts remain frozen. A future published ownership, Merkle, or Evidence status protocol needs an explicit version, golden vectors, old/new reader behavior, and migration review. The two research reports are read-only source inputs under the original checkout's `docs/research/`.

## Dependency order

1. Import the architecture freeze, the process harness, the portability study, the independent 4C tests and the Trust prototype in that order. Verify inherited tests before adopting any integration seam.
2. T3 must establish enrolled transport identities, a durable home generation and target-side barriers across every enrolled writer before broker reassignment can grant a new write generation.
3. T4 must establish independent admission first. A checkpoint and Merkle consistency proof prove a commitment and prefix extension. Receipt custody and a coverage threshold are also needed to reject an omitted admitted withdrawal. Keep coordinator replay separate from an authority-bearing cursor.
4. T5 needs separately administered verifier enrollment and status sources, scoped Evidence withdrawals and persistent contradiction decisions. Bind the accepted status to the same subject and current trust cut used by the relying party. Native Evidence still verifies material and worker pins.
5. Only combine T3–T5 at the real target boundary after T6 verifies the frozen native inputs, ownership, exact local approval, replay and status together. Test each with a healthy control and independent SQLite and HTTP readback. Use the 4C results to prioritize cases.
6. In this candidate take the conservative migration path. Exercise the real legacy lab and Trust prototype separately. Add a read-only correlation check where exact native bindings can be checked safely. A positive shadow result conveys no write capability. Do not expose trusted distributed mitigation until live hosts, authorities, original signed inputs and target barriers are tested in the same candidate.
