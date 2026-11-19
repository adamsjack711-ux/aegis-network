# Phase 4C adversarial resilience review

**Disposition: retain isolated-lab use.** The reviewed baseline is `7744ebd7f80e6f2aabb253d5cc3ec9972c86cffd`. The new checks verify several local fail-closed paths. Journal completeness, cross-broker identity, and independently administered Evidence status remain deployment gates.

The work lives on `test/phase4c-adversarial` in `.worktrees/phase4c-adversarial`. It adds defensive tests and proposed threat-model changes. The candidate implementation and inherited assertions are untouched.

## Review basis

- The Phase 2C hardening and release-candidate records establish the signed-event contract, audit-before-acknowledgement, broker-scoped leases, and replay from PostgreSQL. The risk register records the original completeness, identity, and key-history limits. The release-candidate report was read from `integration/phase2-release-candidate` at `455b39a`. [Hardening report](phase2c-hardening.md) · [Integration review](phase2c-integration.md) · [Risk register](phase2c-risk-register.md)
- The Phase 3C integration report is the basis for the Evidence-to-Mitigation path, the short freshness bound, and the earlier Compose results. The Phase 3D suite in the baseline matches the suite on `test/phase3d-validation` at `1fca385`. Its 44 toy checks exercise the observation oracle and its three dry-run checks exercise Rapid and replay. [Phase 3C report](phase3c-integration.md) · [Phase 3D report](phase3d-validation.md) · [Phase 3D tests](../tests/phase3d)
- Phase 4C runs the candidate's Evidence, Mesh replay, Rapid, and Mitigation gates using ephemeral signing keys and temporary SQLite files. Evidence runs the existing synthetic verifier workers. An in-process HTTP transport supplies a conventional journal or a service-unavailable response. A stub represents a current broker lease. The fixture proxies bind to loopback and forward to disposable Unix sockets. The separate observer reads HTTP status, body, target identity, and fence on all nine fixed replica/route pairs. Separate read-only SQLite connections inspect durable state. [Phase 4C tests](../tests/phase4c/test_defensive_boundaries.py)

## Results and coverage

| Area | Observed in Phase 4C | Inherited tests rerun and remaining limits |
| --- | --- | --- |
| Intelligence sources | A wrong signing key, a credential lacking the finding role, an expired credential, and a revoked credential each produced the expected Rapid rejection. No authenticated finding or fixture action was committed, and all nine routes stayed at their baseline fence. | The wire-tampering, signed-conflict, and malformed and corrupted material tests passed. Authenticity of submissions still depends on independent corroboration. [Wire tests](../tests/phase3d/test_dry_run.py) · [Evidence tests](../tests/test_phase3a_evidence.py) |
| Coordinator and replay | Journal unavailability before plan preparation and again after exact review denied activation with an empty fixture audit. An ordinary scoped, signed withdrawal delivered through replay after the canary prevented both peer writes. The cursor and exact tombstone committed, and direct HTTP readback verified quarantine on all nine routes. | Out-of-order findings, duplicate delivery, detectable gaps, and malformed broker deliveries passed the inherited controls. A reachable journal has no independent completeness witness. [Mesh tests](../tests/test_phase2c_hardening.py) · [Dry-run tests](../tests/phase3d/test_dry_run.py) |
| Agent identity | Exercised separate local audit binding in the inherited suite. The Phase 4C integrated cases assume a current broker lease. | Broker double coverage checks lease collision and loss of ownership. The prior Phase 3C Compose run exercised same-broker collision and reconnect. Cross-broker identity and prolonged reconnect through credential rotation remain open. [Hardening tests](../tests/test_phase2c_hardening.py) · [Prior integration](phase3c-integration.md#tests-and-fault-observations) |
| Verification | A legitimately signed bundle with a matching claim and positive quorum in `lab-green` was denied by the `lab-blue` entry point before a fixture was created. | Forged verifier records, corrupted cached bytes, conflicting observations, and withdrawal during a worker run passed the inherited tests. The local ledgers and verifier enrollment remain under one administrative trust domain. [Evidence tests](../tests/test_phase3a_evidence.py) · [Integrated tests](../tests/test_phase3c_pipeline.py) |
| Mitigation | A review digest for an earlier plan could not activate a replacement. Under journal unavailability, the active lease expired and all nine routes closed before the controller wrote quarantine. Recovery advanced all three fences, and the old approval stayed unusable after journal reconnect and fixture restart. | Existing tests cover missing observations, wrong fences, failed canaries, and recovery after crashes. Full protection is measured on the three enrolled replicas and three known routes. Quarantine also closes the benign routes. [Mitigation tests](../tests/test_phase3b_containment.py) |

During the new withdrawal check, the only restriction was on the canary. The durable event order was `leased`, `restricted`, `canary_verified`, `quarantined`, `safe_hold`. Recovery fences for canary, replica A, and replica B were `2, 1, 1`. During the expiry check, all three marker routes initially returned 403 while all six benign routes returned 200. After expiry, all nine routes returned the quarantine response at fence 1 before durable recovery and at fence 2 after recovery and restart.

## Findings

Severity describes the consequence if the baseline were used beyond the disposable lab. These are source-confirmed limits of the reviewed design. The verification results above cover the defensive paths exercised locally. The source links and symbols below are the review artifacts for each finding.

### 4C-01 · High · Journal completeness has no independent trust source

The coordinator provides the replay events and head. Rapid validates individual envelopes and rejects detectable replay inconsistencies. The response carries no independently authenticated coverage or freshness proof. A deployment can therefore remain unaware of a withdrawal absent from its view. Phase 3C uses that same view when refreshing Mitigation authority. This carries forward R-02. Review `replay_events`, `events_after`, `reconcile`, and `MeshIntake.fresh` at the pinned baseline. [API](../src/aegis/api.py) · [Repository](../src/aegis/postgres.py) · [Replay](../src/aegis/recovery.py) · [Integrated gate](../src/aegis/phase3c.py)

**Proposed gate** — Require authenticated replay clients and independently witnessed, signed checkpoints with append-only consistency and completeness proofs. Bind the accepted checkpoint and its validity to the write decision. Treat unverifiable or non-current checkpoint state as unavailable and retain existing denials.

### 4C-02 · High · Broker-local leases cannot establish deployment-wide identity

The canonical UUID and compare-and-swap lease establish active identity within a broker KV namespace. The reviewed Compose profile supplies no broker credentials or per-agent ACLs. There is no authoritative enrollment or durable fencing generation shared by every broker and writer. A deployment-wide audit or authorization cannot rely on the UUID alone for exclusive identity. This carries forward R-01. Review `IdentityLease`, the SQLite audit owner check, `EvidenceGate.binding_context`, and the broker service definition. [Lease](../src/aegis/identity.py) · [Audit owner](../src/aegis/storage.py) · [Plan binding](../src/aegis/phase3c.py) · [Compose](../compose.yaml)

**Proposed gate** — Bind the deployment identifier to an enrolled credential and enforce broker ACLs. Issue a monotonic generation from a trusted authority. Bind the generation to journal delivery, local approval, and actuator checks. Treat conflicting ownership during failover as unavailable until reconciled.

### 4C-03 · Medium · Historical withdrawal replay depends on current revoker trust

A signed historical withdrawal can outlive its envelope expiry for replay, subject to current local revoker authorization. An offline deployment that missed the withdrawal can therefore halt replay after the revoker's grant expires or is revoked. Local tombstones already committed are retained. The unresolved distinction is between planned key retirement and compromise, which can require different treatment of historical signatures. This carries forward R-04. Review `LocalAgent.evaluate_revocation`, `TrustStore.authorize_revocation`, and the replay stop condition. [Rapid evaluation](../src/aegis/core.py) · [Publisher trust](../src/aegis/trust.py) · [Replay](../src/aegis/recovery.py)

**Proposed gate** — Define signed, versioned historical trust with explicit retirement and compromise semantics. Preserve validated tombstones through backup and restore. Require a long-offline agent to refresh checkpoints and trust history before becoming eligible. Keep the current fail-closed stop until this contract is verified.

### 4C-04 · High · Evidence enrollment and withdrawal share an administrative boundary

Portable attestations are verified by a relying ledger, and the write transaction reappraises both the collector and relying ledgers. The lab enrolls the verifier organizations and instantiates both ledgers on the same host. Different enrolled keys and organization identifiers establish distinct signatures but give no assurance of separate administrative control or independently witnessed withdrawal state. A common trust or status failure can undermine the corroboration used to authorize a plan. Review `create_lab`, `Evidence._assessment`, and `EvidenceGate.authorize`. [Synthetic enrollment](../src/aegis/evidence/synthetic.py) · [Evidence appraisal](../src/aegis/evidence/service.py) · [Integrated writer](../src/aegis/phase3c.py)

**Proposed gate** — Separate verifier and revoker administration from intake, require relying-party verification of signed monotonic status, and retain contested-scope and withdrawal decisions across restart and failover. Bind approved plans to the Evidence status checkpoint in addition to attestation digests.

### 4C-05 · Medium · Protection and recovery coverage is scoped to a compiled fixture

The integrated runner's controller and observer share a lab host. The registered route and replica set defines both the write set and observation coverage. The independent readback can verify marker suppression on that fixture, including in safe hold. It provides no topology or reachability evidence for a wider fleet. Review `TARGETS` and `PATHS`, `HttpObserver.observe`, and `TargetStore.record_recovery`. [Topology](../src/aegis/mitigation/policy.py) · [Observer](../src/aegis/mitigation/observer.py) · [Recovery](../src/aegis/mitigation/store.py)

**Proposed gate** — Establish authoritative, versioned route and replica inventory. Require independently administered observations covering the complete inventory at current fences. Assign missing or stale telemetry an explicit inconclusive outcome. Preserve quarantine until restrictive behavior is observed across the required coverage.

### 4C-06 · Medium · HTTP admission lacks a declared pre-parse resource budget

The reviewed coordinator provides field-level schema constraints and a downstream broker message-size limit. Its API and Compose configuration declare no pre-parse HTTP body ceiling or per-client admission budget. Evidence and withdrawal processing share the coordinator, so intake resource pressure can affect timely recovery and status. No load measurement was made for this finding. Review `submit`, `revoke`, and `ensure_streams`. [API](../src/aegis/api.py) · [Compose](../compose.yaml) · [Baseline threat model](../threat-model.md)

**Proposed gate** — Enforce bounded request bytes, parsing time and concurrency at ingress. Reserve capacity for authenticated revocation and recovery traffic. Verify rejection before persistence or dispatch and measure withdrawal progress at the configured operating limit.

## Repeat and hand off

Use the branch checkout, Python 3.12 or later, the project's test dependencies, and a local environment that permits binding disposable Unix sockets and loopback ports.

```sh
PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/phase4c
PYTHONPATH=src python -m pytest -q -p no:cacheprovider
```

On 2026-11-19, the baseline passed 129 tests with one Starlette deprecation warning. The first sandboxed run could not bind fixture sockets. Its 19 failures and setup errors cleared when local sockets were allowed. The first Phase 4C run found a missing fixture signing argument. The test setup was corrected while preserving the expected security outcomes. The final run passed all 137 tests, including eight Phase 4C checks, with the same warning. [Retained test results](../tests/phase4c/results.json)

Integration review should start with 4C-01, 4C-02, and 4C-04. The proposed contracts in the threat model identify the trust inputs and acceptance evidence for each deployment gate. The Phase 4C handoff is a separate branch for review. [Threat-model proposals](../threat-model.md#proposed-phase-4c-trust-boundaries)
