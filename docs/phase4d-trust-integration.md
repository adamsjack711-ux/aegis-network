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

## Candidate intake execution

The Phase 4 architecture notes, three feature handoffs and Trust model were imported in this order as explicit commits. No original ref was merged or rebased. The `STATUS.md` overlaps were resolved by preserving each section. The legacy distribution pin is `8edcfa5077f45faa0cb98bcc2f357476c8508ed3`. The read-only comparison and Trust metric changes are at `9af6e43dc2984e8dbe6e4bf6d9ea5534be110430`. No frozen Phase 3C signed payload changed.

The comparison takes the locally appraised finding digest, native bundle digest and deployment UUID and requires the prototype's fresh result for the same subject. It always clears pending prototype authority, even on mismatch. It exercises the exact native audit and Evidence inputs without importing a new activation path. The native prototype component ownership is tracked below.

| Workstream | Review and integration boundary |
| --- | --- |
| T3 | Own the transport-authenticated identity adapter and durable deployment ownership. Use one authoritative home and a real fence at each enrolled writer. The isolated branch must preserve an exact local plan and approvals when composing with T4's prepare and refresh gates. |
| T4 | Own receipt, history and coverage semantics. Native Mesh intake remains transport and audit. Checkpoint and expiry should intersect the ownership and Evidence deadlines; a blind fallback to coordinator replay cannot grant authorization. |
| T5 | Own the signed status protocol and independent verifier and revoker intake. An enrolled relying party should bind locally resolved native digests, status authority and expiry. Keep compatibility or cache results outside authority. |
| T6 | Re-run original assertions and cross-component review on the pinned candidate. A simulated broker or witness can establish logic, with live endpoint custody and recovery a separate gate. No recent result enables an unproven capability. |

### Native workstream compatibility review

T5 `852a0f87d6ae44bc11c8250904ff6236c69c6f56` adds an isolated Evidence status namespace and original native record verification without changing a frozen payload. Its only import overlap is the additive status log. Native collector votes have a longer maximum lifetime than T5's independent 60-second observation profile. Use fresh direct verifier observations over the same signed manifest for T5. Keep the legacy collector's signed votes and approvals intact, and do not up-convert them into independent attestations. The reviewer observed the long-lived vote rejected in the first cross-test; the resolved experiment uses the stricter direct path.

T3 `86e995ff9c94593369bfdd68eeaa1ace0b13c351` descends from Phase 4C in a separate repository. It adds optional ownership to lab plans, preserves serialization of legacy plans when absent, seals command intent and expiry, and checks ownership inside the same fixture transaction as target mutations. The shared prepare hook also changes in T4. Preserve the T4 checkpoint binding, native Evidence checks and expiry, then apply T3's ownership commitment and intersect its earlier deadline. No dual path may replace exact local approval. Ownership still trusts adapter-supplied peer and broker identities. Existing local test profiles operate in one target transaction domain and are separate from deployment authorization.

T4 `2de4d1b3ff924424c88c23766283069ebb5d1ea6` is based on pinned Phase 4A plus an equivalent 4C replay in a separate repository. Import only the T4 commit. The native candidate adds scoped FastAPI proof/intake interfaces with a caller-supplied authorization dependency, a versioned experimental namespace, and an opt-in journal cut in the shared fixture gate. A verified T4 prefix can serve as the audit for its witness-only test profile. The combined T6 profile also requires the Phase 2 local Rapid decision and digest before it grants fixture authority. Witnessed cursor recovery stays separate from legacy broker cursor and ACK transactions.

T4's independent handoff and additional restore tests are pinned at `aeb3a602ea1fed207f2fe8d1d356df7af9e8236b`. The second import strengthens corrupt-cache readback, witness recovery and rejection of a prepared plan after an empty newer epoch. It adds raw three-trial measurements and preserves the original T4 and 4C assertions. The additive status overlap retains both source sections.

The tested composition adds the independent Evidence binding to the exact local plan, pins its audience and expiry and requires T3 identity alongside it. The external status and native receipt lookup run within the existing one-second refresh budget. An observed refresh failure or new binding invalidates the prepared plan. Even after connectivity returns, its previous exact approval cannot resume a partial rollout. The ordinary runtime and frozen shared contracts keep their existing scope. [Architecture](phase4d-architecture.md) · [Security tests and dispositions](phase4d-security-review.md)
