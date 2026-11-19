# Phase 4D T3 identity and ownership

## Disposition

The identity-fenced lab profile addresses 4C-02 at the ownership home and the disposable fixture writer. It is opt-in through `VerifiedLab(..., identity=session)` on top of Phase 4C `52a4dc4`. The profile's two broker assignments share one SQLite home. Release beyond this lab depends on authenticated transport and broker admission, durable recovery, and the other Phase 4C gates. [Phase 4C finding](phase4c-adversarial.md#4c-02--high--broker-local-leases-cannot-establish-deployment-wide-identity)

The design follows *Aegis T1 research · Trust, identity, and cross-broker fencing* and *Aegis T2 research · Verifiable event history and independent Evidence status* in the parent checkout's `docs/research/`, the Aegis Trust prototype at `300252d`, and the Phase 4 contract freeze at `e8e03ee`. The prototype informed the shared transaction boundary, scoped instance proof and separation of identity from local approval. This branch uses the actual Phase 3C Evidence, operator, and target paths.

## Threat model

| Actor or failure | Boundary and expected behavior |
| --- | --- |
| Two brokers claim the same UUID during failover | A locally pinned home serializes both contenders. An unexpired assignment excludes the other broker. At expiry or on an operator fence, the durable generation advances before a replacement becomes current. Both brokers may retain delivery sessions. |
| Impersonator copies the UUID, SPIFFE ID, or a signed request | Lease admission checks the workload and broker identities supplied by the trusted adapter, exact provisioned scope, instance-key signature, request expiry, and durable nonce consumption. A claimant must pass every check. |
| Old holder retains a valid key, outstanding commands, or local approval | The writer checks the current fixture, deployment, principal, key, broker, generation, and deadlines under its write lock. It also requires the command's exact action, plan, and target. Old signatures and approvals remain bound to the prior generation. |
| Holder or broker tries to exercise enforcement | A command proof expresses intent. The fixture still requires current Rapid and Evidence appraisal, an exact local operator approval or an already approved rollout, the applicable target fence and canary/observation gates. The fixture has no network command endpoint. |
| Failed commit, restart, or partial rollout during reassignment | A target effect, its audit and the command receipt commit together. A guarded active rollout with missing, expired or different ownership serves quarantine before controller recovery. Restrictive recovery retains the existing observer requirement for `safe_hold`. |

The trusted computing base includes the provisioning operator, isolated fixture and home writer, SQLite filesystem and locking, host clock and kernel, and the local Rapid, Evidence and approval code. A broker can delay or withhold facts. Journal completeness remains 4C-01. A trusted operator configures one authoritative home for a deployment and its entire inventory. A UUID or broker reply cannot select a home. Read/write access to the home file and the fixture process is privileged.

## Identity and lifecycle

| Mechanism | Role |
| --- | --- |
| SPIFFE/SPIRE | Use a pinned trust domain and exact X.509-SVID URI. SPIRE node and workload attestation determine which workloads receive an SVID. Provision selectors under operator control and use short-lived credentials. The deployment UUID, exact workload URI, instance key, allowed brokers and fixture scope are separate enrollment data. [SPIRE registration](https://spiffe.io/docs/latest/deploying/registering/) · [X.509-SVID profile](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/) |
| TLS 1.3 mutual authentication | Use mTLS at home, broker admission and replay endpoints. Verify the peer chain, expected exact URI and entitlements from the authenticated connection. Disable privileged early data and end the session at the earliest applicable credential or assignment deadline. Transport supplies `peer_principal` and the pinned broker identifier to the home adapter. [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) |
| Ed25519 | The separate enrolled instance key proves possession over each lease request and command intent. The lab verifies request, assignment, and target intent in distinct signature or commitment domains. Existing finding, withdrawal and Evidence signatures keep their wire formats and roles. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) |

1. A trusted local operator initializes the disposable target database and registers one immutable deployment, exact SPIFFE URI, allowed brokers and public instance key. Provisioning uses role separation at the process and filesystem boundary. The first claim requires proof of possession of the provisioned key.
2. The holder signs a five-second claim request naming the proposed broker, current generation and fixture. The home validates it and commits the next generation, broker, ten-second lease window and nonce before returning the assignment. Renewal requires a fresh signed request from the current holder and matching broker while both clocks show a live lease. It keeps the generation and commits a new deadline. The returned assignment is public metadata.
3. For failover, allow the lease to expire or have the trusted operator fence the expected current generation. Fencing clears the broker and advances the generation. Reacquisition from an allowlisted broker advances it again. The target write transaction and all three protected replicas share the same database lock and row, so the fence is the barrier for the whole enrolled fixture.
4. Rotate by fencing the expected generation and pinning a previously unused instance key in one commit. Retire by fencing the expected generation and retaining the retired enrollment. A deployment's broker reassignment or key rotation changes the exact plan digest and requires fresh local approval. Once used, the existing fixture stays subject to its baseline one-rollout rule and recovery.
5. Every guarded target intent binds the assignment, exact approved plan digest, operation, optional target and a short-lived nonce. The target records each consumed nonce with the effect and audit. The writer rechecks lease, command, plan and rollout lifetime before committing. Active HTTP serving checks the current generation and deadline independently of operator recovery.

The lease and target proof models live in [ownership.py](../src/aegis/ownership.py). They use the existing canonical JSON encoder over strict typed records. UTF-8/ASCII byte strings use the respective prefix `AEGIS-OWNERSHIP/v1\0lease\0` and `AEGIS-OWNERSHIP/v1\0target-intent\0` before the canonical body. The assignment commitment is SHA-256 over `AEGIS-OWNERSHIP/v1\0assignment\0` and the canonical assignment. Proof fields presently use the shared host's monotonic nanosecond clock. This is a local Python contract for review.

## Evidence and reproduction

Run from the branch checkout with Python 3.12 or later and the project's test extras. The full and integrated commands need disposable Unix socket and loopback port access.

```sh
python -m pip install -e '.[test]'
PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/phase4d
PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_phase3c_pipeline.py -k phase4d
PYTHONPATH=src python -m pytest -q -p no:cacheprovider
```

Run the live two-broker scenario with an accessible Docker daemon and a locally cached `nats:2.10-alpine` image. The test creates and removes two disposable loopback containers.

```sh
AEGIS_PHASE4D_T3_LIVE=1 PYTHONPATH=src python -m pytest -q -p no:cacheprovider
```

| Reproduce | Observed state |
| --- | --- |
| `test_simultaneous_cross_broker_claims_have_one_durable_winner` | Two independent broker contenders race in separate processes with valid proofs from the same enrollment. Readback through a new handle finds one current assignment and one committed claim. |
| `test_unentitled_claims_leave_home_unassigned`, `test_renewal_requires_current_broker_new_proof_and_the_lease_domain` | Wrong peer, broker, key, deployment, fixture or deadline leaves the home unassigned. Wrong-broker renewal, reused nonce and the target proof passed to the lease interface leave the successful renewal deadline and audit intact. |
| `test_expired_owner_cannot_renew_or_survive_reassignment`, `test_clock_regression_holds_until_operator_fences`, `test_rotation_and_retirement_invalidate_old_keys_across_reopen` | Expiry prevents renewal and moves active route state to quarantine. The simulated clock regression denies ownership and failover during uncertainty. A reopened home rejects the old key and stale generation after rotation and refuses reuse after retirement. |
| `test_target_rejects_bad_intents_and_approval_without_consuming_anything`, `test_fenced_broker_and_previous_review_cannot_lease_after_failover` | Missing, forged and mismatched proofs, forged approval, missing evidence binding, a legacy writer on the enrolled database, and a stale reviewed plan leave the expected target fences and audit intact. A valid exact approval commits. A reopened writer rejects a consumed command. |
| `test_expiry_before_commit_rolls_back_effect_and_command_receipt`, `test_transfer_barrier_serializes_with_the_actual_target_mutation`, `test_required_profile_denies_unenrolled_replacement_database` | Expiry after staging rolls back the effect and both audits. An in-flight target write commits before the fence, and no old write commits after it. An empty replacement database in the required profile denies the write and serves quarantine. |
| `test_phase4d_ownership_with_real_evidence_and_target_readback` | The healthy run uses real signed Evidence and confirms three restricted replicas. The fault run transfers ownership after canary confirmation. All nine replica/route pairs serve quarantine at fences `1, 0, 0` before controller recovery. Old and replacement holder intents using the old approval commit no peer writes. The locally observed recovery reaches `safe_hold` at fences `2, 1, 1`. |
| `test_live_independent_jetstream_leases_cannot_override_home` | Two independent NATS servers each accept and renew a JetStream KV lease for the same deployment. The shared home refuses broker B during A's assignment. After an explicit fence, both transport leases still renew. The target rejects A's previously approved command and records only B's new approval at generation 3. |

The live-enabled branch suite passed **157 tests** on 2026-11-19 with one inherited Starlette deprecation warning. It includes 137 inherited tests and 20 T3 cases. The unit tests provision ephemeral instance keys and inspect read-only SQLite state. The integrated HTTP cases use the existing signed Evidence workers and Rapid, with a mock journal transport and a stub for the broker lease. The live broker case uses real JetStream and passes provisioned identity context directly to the home.

An interface check on a disposable copy of integration `9af6e43` combined T3 with the then-current T4 journal snapshot and T5 status code later committed as `852a0f8`. It used T4's `EvidenceGate` and T3's `VerifiedLab` and passed 260 tests with the two optional Docker scenarios skipped. This check exercised the shared hooks and the T5 suite. The combined Evidence status guard remains T6 integration work.

## Interface handoff for T4 and T5

The following interfaces reflect the T4 journal and T5 status code in their development checkouts. T4 and T5 acknowledgements are pending.

- **T4 — Witnessed journal.** Keep T4's `EvidenceGate.prepare(controller, lease_ms)` with the verified Mesh checkpoint commitment and deadline. T3's `VerifiedLab.prepare` adds the ownership commitment and caps that plan at the current lease deadline before review. Retain T4's `JournalClient.authorize` context around the target transaction. For authenticated replay, bind the verified checkpoint and replay receipt to the exact returned `Assignment`. Revalidate ownership as part of the authority-bearing cursor commit. Broker ACK follows the durable decision.
- **T5 — Evidence status.** Use `RelyingStatus.evaluate` and require `StatusAssessment.outcome == "reproduced"`. Include `StatusAssessment.binding_sha256` in the appraiser's `evidence_binding` alongside the existing local evidence and Mesh checkpoint material. Include the conservative monotonic conversion of `StatusAssessment.valid_until` in the stage deadline. T3 separately binds `ownership_binding` and the signed intent to the resulting exact plan. Recheck an exact, current Evidence commitment under the local writer's authorization guard. Restrictive local recovery stays available after either source loses authority.
- **Transport and writer integration.** Supply `OwnershipHome.accept(proof, peer_principal=..., broker=...)` with the verified workload peer and broker identifier from trusted configuration. Validate the home peer. Close old sessions on fence or expiry and isolate ACK state by generation, or verify closure before reusing a physical consumer. T6 needs the authenticated broker mapping, expiry and old-ACK rejection evidence. Separate databases need durable barrier receipts from the entire enrolled writer inventory, including any authority-bearing audit or cursor writer.

## T6 integration instructions

1. From the sibling `phase4d` integration checkout, run `git fetch ../phase4d-t3-identity refs/heads/feat/phase4d-t3-identity` and `git cherry-pick FETCH_HEAD`. Use T4's `EvidenceGate.prepare` and T3's `VerifiedLab.prepare` if both touch that hook. Review the frozen signing, Evidence, ACK, exact-approval and observer contracts and rerun the three commands above.
2. For the disposable profile, initialize an unused fixture path with `TargetStore(path, LocalOperator()).create()`. Through the trusted local operator process, call `store.ownership.enroll(agent_id, exact_principal, public_key, (broker_a, broker_b))`. Use the Rapid audit UUID for `agent_id`. Pin the same home and fixture path in both local contenders. Retire older fixture writers before cutover and use the guarded binary for recovery.
3. Read `home.candidate(broker)`, call `lease_proof("claim", candidate, instance_key)` in the local holder, and pass the proof and authenticated adapter context to `home.accept`. Wrap the result and key in `IdentitySession`. Open `VerifiedLab(gate, path, identity=session)`, run `prepare`, and submit the reviewed digest through the existing local operator path. Exercise expired and explicit transfers, attempt the prior proof, and read back targets and both audits. Handle an uncertain commit by rereading the home and its receipts before retrying.
4. Before a shared deployment, require live SPIRE/mTLS, TLS-to-broker ACL and session-expiry tests, signed journal and Evidence status, all-writer fencing and restore evidence. During a distributed transfer, persist a preparing state, stop renewals, install each writer's floor under its mutation lock, and activate the successor only after the complete pinned inventory acknowledges. A missing writer leaves the transfer incomplete. Keep enrollment, ownership and target-write privileges restricted to the operator and trusted services.

## Remaining security limitations

- The lab trusts adapter-provided identities. Live SPIRE attestation, mTLS channel binding, credential renewal and revocation, NATS ACLs, broker session/ACK fencing, and authenticated journal cursors remain integration gates.
- The ownership home and all fixture writers are colocated in one SQLite transaction domain. Independent writable copies can diverge. Multi-host arbitration, durable primary failover and per-writer barrier acknowledgement require a separate tested implementation. Copying or restoring an old database requires an external generation anchor and reconciliation before reopening authority.
- An older binary lacks the guard for an enrolled database. The branch's current compatibility path checks the durable marker. Isolation must exclude older writers once the guarded profile is installed.
- Local expiry uses the shared host's monotonic and UTC clocks. Verified boot continuity, reliable time across reboot and suspend, bounded commit and response latency, and external recovery points are deployment requirements. A process can pause after a pre-commit check. The fixture independently checks serving authority and closes active routes on expiry.
- The OS and service isolation must protect instance keys, trusted adapter context, approval and database access. Clone or compromise of both workload and instance credentials within one assignment can impersonate that holder. Compromise of the local writer or database administrator falls outside the lab evidence.
- The existing journal can still omit events, and the integrated test's synthetic Evidence shares administrative control. No independent status, organizational independence or coverage outside the compiled fixture is established by the identity tests.
