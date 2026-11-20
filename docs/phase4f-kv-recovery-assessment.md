# Phase 4F-B withdrawal recovery assessment

Source is clean `feat/phase4f-recovery-astra` at `3298273c285d2f6819df7016eb35c83819dd8335`, parent `3bfd2abea430bc8036105ce85adfdc78706d367d`. VAL-D froze acceptance at `5c5d94f9c3b9ca99c29301bc743767233599ab4f` before this review. Relevant identity, runtime, recovery, audit, ownership, target-store and Trust-status source bytes are identical to instrumented failing source `613efe36e56609bfe4c62740b2ecdee3ae0aeec4`. Original raw failures and the collided branch remain untouched. No lease, wire, trust, ACK, cursor or protected-write behavior changed here.

## Exact-pin measurement

One fresh disposable one-host trial used one enrolled dry-run agent, two valid scoped withdrawals, a pre-intake SIGKILL, broker restart and six pending ordinary outbox rows. Its raw result embeds source pin `3298273c285d2f6819df7016eb35c83819dd8335`.

| Withdrawal | Submit to durable SQLite audit | Restart request to audit | Submit to confirmed ACK |
| --- | ---: | ---: | ---: |
| Independent revoker | **30,610.679 ms** | 30,548.660 ms | 30,612.772 ms |
| Mixed publisher sequence | **30,598.738 ms** | 30,553.422 ms | 30,600.936 ms |

Broker start returned at 197.705 ms. The successor made 30 busy KV claims, acquired the broker-scoped lease 30,499.251 ms after restart request, received critical wire at 30,543.382 ms and audited the first denial at 30,548.660 ms. Controller and child use one host's monotonic `perf_counter_ns`; remote clock subtraction is not used. The independent stage scorer reports one passing diagnostic and **one failed five-second trial**. This observes dry-run SQLite, not independently confirmed target protection or native T4/T5 inclusion.

VAL-D's minimum is 3 agents × 2 withdrawals × 3 repeats × 4 fault arms = **72 targeted pairs**, plus **18 healthy control pairs**. This trial gives failed timing for 2 pairs, but neither pair is a full-oracle result because this dry-run path has no native T4/T5 or target transaction proof. **Full-oracle evaluable: 0/72; missing: 72/72; healthy controls at this exact pin: 0/18.** The 72-pair matrix is currently not executable on this source. The two timing misses independently keep the inherited 5,000 ms submit-to-denial gate failed. Prior retained owner/independent single-agent runs measured six additional 30,589–30,710 ms crash denials and two 1,759.519/1,767.656 ms alive controls; they do not fill the new denominator. No fleet p50/p95/p99, CPU/RSS, physical protection or multi-host claim follows.

Focused local Trust, ownership, native writer and withdrawal regressions: **40 passed, 1 skipped**, zero failed/errors. The skip was the optional two-broker live case; it ran separately with two disposable loopback brokers and passed **1/1**, with 17 other ownership cases deselected. These verify existing local invariants only. Full regression was not run.

## Proposed cross-component contract, not adopted

Unsupported versions fail closed. Native T4/T5 and local policy remain authoritative. These are field-level interface proposals for architecture and VAL-D review, not permission to edit shared contracts or run an early owner takeover.

| Proposed record | Required input fields | Output and commit rule |
| --- | --- | --- |
| `VerifiedWithdrawalStatus.v1` (independent T4/T5 reader) | Canonical withdrawal event ID and signed-body digest; issuer key/grant and revocation scope; target finding UUID/digest and exact Evidence bundle digest; witness admission receipt and covered checkpoint, withdrawal floor and continuity pin; current T5 status operators, contradiction/revocation result and audience; challenge nonce and earliest expiry. | Return `withdrawn`, `unknown` or `conflict`, a proof digest and bounded validity interval. Only the reviewed issuer/scope and independently authenticated witnessed inclusion can label `withdrawn`; missing or conflicting status denies new positive authority but cannot be misreported as an accepted withdrawal. A signature or Mesh receipt alone is insufficient. Current Mesh revocation and native Evidence-bundle withdrawal have no reviewed exact mapping. |
| `TargetDenialCommit.v1` (operator-enrolled target) | Proof digest and exact status result; local policy/target inventory ID; immutable plan/finding/Evidence digests; current target ID/mode/fence; owner-generation floor; prior denial ID and earliest deadline. | Under the same target SQLite transaction and lock as protected writes, commit restrictive mode, monotonically increased fence and reason-linked audit ID. Return new fence and durable commit ID. A verified withdrawal-specific denial is distinct from an unknown-status quarantine. Never create a positive capability, consume approval, expand peers or reopen a route. Existing `store.quarantine()` lacks a transport event/proof binding. |
| `DeliveryEpoch.v1` (critical transport and per-agent audit) | Enrolled workload principal and deployment UUID; authenticated broker identity; target-home generation and consumer epoch; withdrawal ID/digest, stream/sequence, proof digest and target/audit commit IDs; previous generation-bound cursor. | Permit CAS cursor advance and `ack_sync` only after exact durable denial and current generation proof. Broker ACK is telemetry. Use generation-isolated durable consumers or an equivalent independently tested barrier so a late old-session ACK cannot move the successor's floor. Rebuild from signed journal and durable local denial ledger after lost ACK; retain one logical decision. Current stable-UUID consumer and `reconcile()` cursor lack target-generation binding. |
| `OwnerTransferBarrier.v1` (target home and all protected writers) | Operator-controlled authenticated fence request; old/new broker and principal; old/new durable generations; complete enrolled writer roster; target IDs and current fences; last accepted T4/T5 cut; per-writer and per-ACK/cursor deny-barrier receipts. | Advance target generation before successor authority; each writer rejects old signed commands inside its transaction. Permit successor positive writes only when every enrolled writer and ACK/cursor lane proves the new floor and a fresh exact local approval and T4/T5 cut are checked at commit. Missing receipt leaves positive authority closed. A dead PID or expired broker KV lease cannot supply this proof. `OwnershipHome.fence()` is only the local generation primitive today. |

**Adversarial old owner:** pause or partition it, let a successor begin transfer, then resume it with a validly signed old command and old JetStream ACK token. Every protected target must reject the command by durable generation/fence; the old ACK must affect only an isolated old consumer, never the successor's cursor or replay obligation. **Malicious coordinator:** omit or reorder a withdrawal, replay an old positive status or forge an HTTP receipt. Independent T4/T5 continuity and status must block new positive authority; an unverified coordinator message may trigger only a separately labeled local uncertainty hold under local policy, never a withdrawal-specific proof or a cursor advance. Test restored target/cursor snapshots and incomplete witness views with the same rule.

The issuer-to-Evidence mapping, target-owned deny-only commit, generation-specific consumer retention and all-lane barrier require shared-contract review by the native T4/T5/target owners. Within this branch's identity and critical-transport ownership, no safe implementation can bridge those missing fields. Shortening the 30-second TTL, deleting a KV key, or calling Mesh `evaluate_revocation()` before claim would bypass the frozen proof. **No recovery code was changed.**

## Reproduction, raw results and decision

Run from this worktree with cached images and an authorized localhost Docker socket:

```sh
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase4e_withdrawal_recovery_check.py . --authorize-local-lab --kill-agent --priority --output /tmp/phase4f-baseline-sigkill.json
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase_next_4f_stage_audit.py --output /tmp/phase4f-baseline-stage-score.json /tmp/phase4f-baseline-sigkill.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q tests/phase4e/test_withdrawal_status.py tests/phase4d/test_ownership.py tests/phase4d/test_native_enforcement.py tests/test_phase4e_withdrawal.py
AEGIS_PHASE4D_T3_LIVE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q tests/phase4d/test_ownership.py -k live_independent_jetstream_leases_cannot_override_home
```

Committed raw files are under `benchmarks/phase4f-kv-recovery/`: `baseline-sigkill.json` SHA-256 `8cc699a8d7a478f0ed789cef40ac84a402526349636ce833e393833b51eda95f`; `baseline-stage-score.json` `ad7446b28151f4436d04ac4f90ede04e737a15380067dbbacd66d40948ec0a1e`; `focused-safety.xml` `8a8eba17bd5349b0194a4f00faea93eb342156b11fb3f2882dbd9f78fcdd0ac9`; `two-broker-fence.xml` `1602a95b70ed880b4e52328708e0106eb34387e3c772b50d7d1156286e80f0ae`.

After architecture and VAL-D review of a versioned contract, a successor must run all **72 targeted pairs and 18 healthy controls** on one exact integrated pin, recording every miss, skip, censored pair and unavailable stage. Require zero stale-owner protected writes, zero positive action on unknown status, one logical denial, monotonic target fences and safe rollback. Physical multi-host ownership, independent witness custody and external rollback anchors remain separate open gates.

**Decision: NO-GO** for five-second withdrawal recovery, native 4F release and distributed autonomous enforcement. The measured wait is real, and a safely reviewed protocol to remove it is absent. Passing local fencing tests cannot substitute for the missing cross-component proof.
