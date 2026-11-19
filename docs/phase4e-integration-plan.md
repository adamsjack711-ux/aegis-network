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
