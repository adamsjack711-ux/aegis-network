# Phase 4E integration plan

## Baseline and reconstruction

The approved clean common reference is `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f` on `integration/phase4d`. Phase 4E lives in `.worktrees/phase4e` on `integration/phase4e`. Master is an unrelated, dirty checkout at `14440ee226c58aa6e8e06517ab1601b2d672798c`. All existing work was preserved. The final 4D commit's parent `f26f69d5b41284ab675bad4368387be76410e544` has the same implementation and tests. The clean Phase 4E start independently passed all **272** of those tests, with three live test flags enabled, zero failures or skips and one inherited deprecation warning.

The parent checkout retains T6's independent `docs/phase4d-validation.md`, `docs/phase4d-reproduction.md` and `benchmarks/phase4d-t6/SHA256SUMS`. All retained checksums verified. Neither detached T6 revision was present in the main object database before review. Running the retained reconstruction script with `--guarded` in a private temporary clone recreated both exact revisions and trees:

| Reconstructed input | Result and disposition |
| --- | --- |
| `4ae320783b11918e44b1ea83a574d5a27e904d9e`, tree `1a46d4ab4bdbb6b23202b639dbfaa681873dc4d7` | T6 performance control, joining published Phase 4 inputs with its own status-file choices. Lacks the full native writer composition. |
| `a380c8f4a53c9d2e0e5c9437a5a9a6801e2eae38`, tree `cb929f14a246be6acb02493ec69bcb76efada3d6` | Detached guarded T6 composition. Its final delta changes `src/aegis/phase3c.py` and adds `tests/phase4d/test_joint_trust.py`. It is both implementation and validation, on a different lineage than the lead integration. Its stubbed broker ACK and injected transports remain scoped validation evidence. A fresh run of its ten joint scenarios passed in 4.42 seconds. The separate historical full T6 run reported 273 passed and a failed distributed gate. The patch was not applied to the 4E baseline. |

## Ownership and integration order

| Order | Canonical isolated worktree | Interface to review before integration |
| ---: | --- | --- |
| 1 | `.worktrees/phase4e-withdrawal` · `feat/phase4e-withdrawal` | A owns critical ingress, outbox and replay/recovery behavior. Review legacy ordering, authorization of the new path and protected queue resource separation. |
| 2 | `.worktrees/phase4e-identity` · `feat/phase4e-identity` | B owns authenticated workload and broker identity and writer generation barriers. Review the target and session contracts and interrupted transfer. |
| 3 | `.worktrees/phase4e-trust` · `feat/phase4e-trust` | C owns independent Mesh witnesses and Evidence status continuity. Review proof semantics and the independently retained floor before binding anything to the writer. |
| 4 | `.worktrees/phase4e-adversarial` · `test/phase4e-adversarial` | D owns the independent cases and verdict. Freeze acceptance before seeing candidate results. Record unsupported and failed cases. |

The additional A, B and C worktrees are independent review lanes for these canonical implementations. Original feature branches and worktree histories remain intact. Send each implementer and D the approved pin, scope and contract-review criteria. Only the integration lead imports approved exact commits. A shared hot path or contract change requires a written disposition. Run focused cross-component regressions after each sequential import, then issue the exact candidate to D for independent verification.

## Acceptance ledger

| Gate | Intake state | Exit evidence |
| --- | --- | --- |
| 1 · 4C-01, -02 and -04 under a declared distributed fault model | Open | Independent D verdict on all three using the authenticated multi-host candidate and known failure bounds. |
| 2 · Withdrawal delivery and denial under competing findings | Failed at 4D | Reserved service for valid critical traffic, bounded normal progress, sustained mixed load and auditable ingress/replay under broker restart and process death. |
| 3 · Deny new writes with unknown status | Passed in 4D fixture only | Repeat with live authority endpoints and fault injection. Independent absence of peer writes and retained quarantine. |
| 4 · Stale owners and competing writers | Shared fixture home only | Authenticate real broker contexts, close stale sessions, reject stale generation at every target and stop partial barriers. |
| 5 · Restored snapshots retain denials | Synthetic anchors only | Restore behind anchored witness/owner state, including key rotation and a long-offline agent, with no stale reactivation. |
| 6 · Administrative and credential separation | Unproven | Independent operator custody and storage/failure domains with evidence; isolate revoker, witness, verifier, status, coordinator and local approver capabilities. |
| 7 · Authenticated multi-host test | Blocked at intake | Obtain explicitly designated authorized lab peers with pinned identities and independent restore domains. Local Docker and loopback have one physical fault domain. |
| 8 · Phase 4B misses disposition | Four recorded | Retain failed sample, identify scope and cause allowed by evidence, retain fresh reruns and ensure fail-closed behavior. Historical root cause needs contemporaneous request logs that do not exist. |
| 9 · Full integrated and adversarial suites | 272 baseline pass | Run all opt-in live flags and new cases on the exact sequential integration pin, plus D's separately owned test result. |
| 10 · Performance and resource cost | 4D local only | Publish repeated paired reports on the declared topology and separate detection, denial, restart and ACK denominators. |

## Test and release procedure

1. Run the 4D baseline suite with all three local live flags. Compare durable rows separately from broker acknowledgements and always include eventual denominator and budget misses.
2. For each intake, verify the declared base and hash, changed code and tests, retained source branch and limits. Review outside the author's tree and import only the compatible delta. Keep legacy clients and scoped restrictions unchanged. When a dependency is missing, record the feature as a lab artifact or hold it out of integration.
3. Run one untouched healthy control and independent fault probes for a withdrawn or contradictory bundle, missing critical proof pages, replayed status, revoked session, unconfirmed writer barrier, stale restored cut and outage during expansion. Record expected denied attempts as part of the denominator. Keep protected writes disabled beyond the disposable fixture.
4. Use predetermined, repeated benchmark pairs per topology. Pin host and failure-domain placement, service versions, data hashes, credential roots, queue limits and clock bounds. Report p50/p95/p99, tail spread, censored observations, CPU, RSS, capacities, backlog ages and complete observation denominators. For clocks across hosts, use driver-monotonic upper bounds for end-to-end cut-to-readback and per-host monotonic stage timings. Never subtract raw monotonic readings from different hosts. [4D paired controls](phase4d-benchmarks.md)
5. A Phase 5 engineering handoff may proceed for isolated lab adapters and shadow appraisal while any gate fails. The exact candidate requires a new independent pass before distributed writes. Keep a tested rollback plan that preserves quarantine and historical denials.

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 AEGIS_PHASE4A_LIVE=1 \
  AEGIS_PHASE4D_LIVE=1 AEGIS_PHASE4D_T3_LIVE=1 \
  python -m pytest -q -p no:cacheprovider
```

## Sequential intake record

| Step | Approved source input | Integrated checkpoint and focused result |
| --- | --- | --- |
| A | `6e8bedccb184f3b4268670c93bc22310234c4f5e` and evidence/crash regression `4c6f674c1915ee255222f02c38c2e2c010421b1f` | `1adea06fc5b1a86b802008bfe55b7753f4abf755`. 35 focused withdrawal, exact fixture, hardened Mesh and slice tests passed. |
| B | `cb7986d1abb7491e73f5ce53bb01778ba7159d94` and durable interruption fix `11ecb948de82ef094f4fc48261786ff7600d64de` | `16e71ed1ccaf96209054fa3e5ddd03dd6e24b273`. 39 cross-regressions passed, including 13 authenticated loopback identity cases and inherited two-broker identity. Imported as a separate lab namespace. Evidence-only source tip `330294e1326ab30fb1ade096b089d5c175d957cd` retained after review. |
| C | `f1692340b03521d44877b6ba4a2799db66a4576d` | `4918dadacc8dedd96d1c4b506e5f746040a01941`. 47 cross-regressions passed across Trust, unmodified native writer authority, Evidence and withdrawals. Shadow and isolated capability only. |
| D | `61909cc085389a1987a7b835517270160a896ab2`, `39e72afc9e4e915ff56e44b3e8c77cc4e509409a`, `e22ab356aea4f4a6ba01bf59fee44da33c685c01` | `508322e441c772a4d5b93396d6856fc9bf36f0ba`. Independent defensive harness and retained baseline failures. The native tests need the default fixture mode. The two-stream live oracle uses the priority environment separately. |

C's only overlapping intake was the status log. Preserve all source handoffs. No C status endpoint is wired to the existing writer. No B broker adapter can grant native consumer or target authority. The D challenge against the shared writer covers the existing exact T4/T5 fixture gates plus A's early denial integration. Independent D checks of B and C exercise their separate lab boundaries. A single combined authenticated native writer with B and C active remains untested. [Reviewed interfaces](phase4e-contract-review.md) · [Independent assessment](phase4e-adversarial.md)

## Candidate test profiles

Use the default Mesh profile for the general and guarded-fixture suite. Run the explicit two-stream test separately so stubs built for the legacy profile retain their intended controls. The separate legacy-stream withdrawal test intentionally fails the original priority requirement on the baseline. Its four corrected runs remain archived and are outside the current pass denominator.

```sh
export PYTHONPATH=src:tests/phase4d:scripts:. PYTHONDONTWRITEBYTECODE=1
export AEGIS_PHASE4A_LIVE=1 AEGIS_PHASE4D_LIVE=1 AEGIS_PHASE4D_T3_LIVE=1
export AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_TOPOLOGY=loopback

AEGIS_PHASE4E_PRIORITY=0 python -m pytest -q -ra -p no:cacheprovider \
  --ignore=tests/phase4e/test_withdrawal_delivery.py
AEGIS_PHASE4E_PRIORITY=1 python -m pytest -q -ra -p no:cacheprovider \
  tests/phase4e/test_withdrawal_delivery.py::test_W01_W02_critical_lane_progress_while_ordinary_stream_is_full
```

The B container backend is separate from this full loopback-oriented run. The scoped bench and adversarial reports state the tested topology and pin for each observation. No combined authoritative native deployment was provisioned. [Identity topology](phase4e-identity.md) · [Independent run conditions](phase4e-adversarial.md)

## Targeted follow-up order

1. Retain the original C single-witness reproduction. The strict shadow profile must require direct authenticated denial-lane freshness, preserve receipt bytes and native authority, and deny positive appraisal when a designated witness cannot be accounted for. Test one accepted denial and an untrusted denial attempt separately. No shared writer promotion is in scope.
2. Review A's adapter contract for transport separation and permanent versus unavailable denial states. Any generation-scoped transport revision remains behind an explicit lab contract. Broker and replay metadata cannot serve as verified inclusion or Evidence status.
3. Review B's exact protected-marker binding at the transaction. Keep the native T4/T5 writer and existing safety latch. Before live use, require proven fences and known denials at every enrolled writer and at the authoritative consumer/cursor boundary.
4. Give D the exact local candidate and every failed or superseded pin. Verify the three inherited Docker faults explicitly and retain matched healthy and fault controls. Repeat the crash, rollback and partial outage matrix while keeping the no-production and no-multi-host scope. Independent administration, enrolled physical hosts and stronger rollback anchors remain deployment prerequisites.

## Verified local validation and release posture

The full local suite at source and harness pin `508322e441c772a4d5b93396d6856fc9bf36f0ba` passed **314 tests in 169.17 s** with no failures or skips and one inherited Starlette/httpx warning. The separate opt-in independent priority oracle passed in 6.19 s. The defensively failing legacy-stream priority reproduction remains separate from the accepted candidate tests.

The three inherited Docker checks were rerun explicitly on `213e3dd1400708cea686b175b9a16ff279b1f421`: actual agent-process distribution and broker fault recovery, witnessed archive reconciliation after replacing a broker, and independent JetStream leases against one owner home. **3 passed, zero failed or skipped** in 48.99 s. The three flags exercise local Docker with cached images. They close the outstanding local execution checks from the C integration review. They do not establish independent physical hosts, actual custody or deployed rollback anchors. [Exact Docker fault results](../benchmarks/phase4e/docker-fault-results.json)

D independently passed 15 native writer and supporting cases on `4918dadacc8dedd96d1c4b506e5f746040a01941`, retaining independent route and audit readback. D also reproduced C's fresh positive after one authorized witness admission on that combined source and on the original C branch. The sealed quorum path, native mandatory-two T5 path and the isolated B latch passed their narrower checks. A mid-failure observed durable denial is not an authorization, and an unavailable observation is not a confirmed safe state. [C compatibility result](phase4e-trust-integration-review.md) · [Independent validation](phase4e-adversarial.md)

## Targeted implementation intake

A's adapter contract and isolated proof regression `4af51b486efa24b98b74f85537cc92293ce0f770` were imported at `c1e5702`. No runtime adapter is installed. The canonical round-trip test independently checks that a valid different withdrawal cannot borrow a receipt by reusing the same event ID, fewer than three native votes cannot certify a history leaf, and a valid receipt remains distinct from proven inclusion.

C's shadow-only v2 `f7053de6f059535e631cbca9544cd2ee57b2ed48` was imported at `86d2454`. Its strict policy requires all authenticated withdrawal lanes to be fresh and gives a verified scoped withdrawal precedence over a positive checkpoint. Native T4/T5 and the shared writer files are unchanged. No legacy C positive is carried into the protected writer. D has the exact original pin and the strict shadow pin for the independent comparison.

D's initial integrated evidence and adversarial harness are pinned at `ba21b5c8aa8635b695feefcb2d557d57c29c9e2a`, `dfa70c2151f06c5a1c4ba9c4c743a7d85fa803cc` and `1e378a5ce58b8f4176eb84072daa68c40ab96333`. All three Docker faults passed separately for D at `4918dad` and for the lead at `213e3dd`. The independent pre-observation trial `e64bd4d639d9dfd25646650c6a988c7ab0e57718` remains a failed release test for ownership loss. Its Evidence-loss control is a narrower pass.

The source and test tree at `691e1b01d28542ffe4946b35149b5ac4a06573ec` passed **325 tests in 189.30 s** with all inherited live flags and the legacy fixture mode. No failures, skips, or new warnings were reported. The explicit priority, pre-intake/post-audit crash and agent-only partition controls passed **3/3** at `5ca31b1258be06923467bfcd30f7b41c6df498f9`, with the intentionally failing legacy comparison deselected. The focused native writer and independent receipt proof cases passed **16/16** at that pin.

The two D shadow-v2 checks independently passed and were rerun successfully on `a884e8d517417a519b31aed4cd237b5615d2ee59` after import. D retained a fresh original-path failure and the repaired result, including lost fourth view, unrelated and unauthorized inputs, replay, and stale store restore. A separate post-I/O expiry finding remains in D's report. Its affected source is shadow only. [Independent v2 and freshness findings](phase4e-adversarial.md)

B's proactive marker watchdog at `79cd10a72aac169047f63fe137988ce881304f25` was imported at `bc078a8b244a43aa2b9571835f864996afd553c2`. Thirty-three identity and native trust cross-regressions passed at that stage. D independently exercised the unobserved target hold, anchor recovery, stale snapshot and expiry. The native pre-observation failure stays in the gate ledger.

The targeted implementation candidate after the B deadline follow-up is `7a87d47`. The earlier D-review pin `9276d5eea08bcc59deea1fea4c420ab9a2ab0402` remains a separately verified control. It combines the proposed A proof adapter contract, the explicit local B Evidence-bound SQLite writer and C's strict shadow policy with final-I/O freshness checks. The exact contract decisions and import hashes appear in ADR-06 through ADR-10. Native T4/T5 stays authoritative. There is no shared-writer activation, generation-bound native ACK/cursor implementation, or dedicated transport-to-Trust runtime. [Contract review](phase4e-contract-review.md) · [Isolated writer](phase4e-b-evidence-writer-fixture.md)

For the next gated composition, first demonstrate verified transport proof discovery and generation-bound broker acknowledgements and replay cursors, then validate the native writer's exact appraisal, local approval and all-target barrier with controlled late status and ownership changes. Keep native T4/T5 authoritative while comparing C in shadow. Give D one exact candidate and retain each narrower control and failure. Require independent authenticated physical hosts, custody and restore anchors before a distributed enforcement decision.

## Candidate readiness

| Acceptance gate | Measured disposition |
| --- | --- |
| 4C-01 · Fresh withdrawal coverage | Partial. Native witnessed scope tests passed. C reproduced the single-recipient omission and fixed it for its own strict shadow profile under the honest responding witness assumption. Independent cross-domain complete intake is unproven. |
| 4C-02 · Cross-broker ownership | Partial. The B marker lab validates a two-target barrier and rejects a former signed owner. Native broker ACK/cursor generation fencing and complete independent writer barriers are unproven. |
| 4C-04 · Independent Evidence status | Partial. Native two-operator withdrawals, conflicts and missing status passed local tests. The B marker fixture exercises an exact approved native cut. Independent authority custody and distributed cut-to-commit visibility are unproven. |
| Withdrawal priority and all-agent reporting | Priority passed locally with a full ordinary stream. **Five-second gate OPEN.** The independent pre-intake SIGKILL denial took 30.479 s. Those dry-run transport tests did not measure the target hold. |
| Unknown authority and recovery | Partial. D passed native fixture status-loss, stale-cut, local approval, owner and restrictive rollback cases. B's proactive marker hold passed without observation traffic. The original native ownership-loss durable quarantine ordering failure remains open. |
| Restore and independent authorities | Partial for local retained anchors. Common control of lab custody, clock and physical storage prevents claims about separately administered restore and rollback domains. |
| Authenticated physical multi-host run | Blocked. No authorized host inventory, enrollment and credential references were verified. Local loopback and container tests fulfilled the current authorization. |
| Phase 4B four inconclusive assessments | Disposition documented. The original fail-closed availability and provenance discrepancies remain attributed only to the retained oracle outcomes. Three reruns matched all 1,000 each. |
| Performance and overhead | Local paired priority and shadow costs measured. Matched combined end-to-end protection and resource benchmarks and physical multi-host recovery remain open. |
| Phase 5 readiness | GO for local lab and shadow engineering. NO-GO for shared C authority, distributed autonomous enforcement or production. |

The broad integration run completed **346/346 passed**, zero failures or skips, in **291.64 s** with all three inherited live flags and priority off. It began before the last additive B deadline commit was imported, so it is a test-window result. The final integrated pin `7a87d47c43c3a768bb5d5143c606c7f1c6a59c7c` passed 18/18 focused B writer and C expiry tests in 174.38 s, with zero failures or skips. D independently passed 7 B marker seam cases and 15 native writer cases at the prior exact pin. A repeat broad suite on the final pin is tracked separately. The run used the existing Python 3.15 environment although the project targets Python 3.12+. Its JUnit configuration emitted record-property warnings without changing assertions.
