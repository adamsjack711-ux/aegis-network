# Phase 3D independent validation

Phase 3D ran on `test/phase3d-validation`, based on the committed Phase 2C candidate `65ebb3ab14d4a57651919b17106bcb01fec9a4a0`. The suite uses deterministic synthetic records, a toy service in memory, temporary SQLite databases, an in-process message double, and HTTP mock transport. It opens no service connections and performs no deployment or control action.

## Run

From the validation checkout, use a Python environment with the project's test dependencies.

```sh
PYTHONPATH=src python -m pytest -q tests/phase3d
PYTHONPATH=src python -m pytest -q
```

On 2026-11-19, Python 3.15.2 and pytest 9.2.0 ran **47 Phase 3D tests** and **85 tests in the full suite**. All passed. The full suite reported one Starlette test-client deprecation warning.

## What the tests observe

- The synthetic suite executes scripted writes against two in-memory replicas with two routes each. Its oracle checks independently collected marker counts, benign-request counts, observed fences, and the chronological write and probe log. Three of three benign requests must succeed on each observed path. Missing telemetry or a fence mismatch makes otherwise clean observations inconclusive. [Synthetic suite](../tests/phase3d/test_synthetic.py)
- The fixtures pin the evidence hash, enrolled verifier organizations, topology, identities, trust generations, and lease. The scenario table gives the inputs and expected dispositions. The affected baseline emits the inert marker, the restricted control suppresses it while serving benign requests, and separate controls establish how service loss and observer loss appear. Scripts can perform an unsafe write so the oracle can verify that its effects are detected. [Fixture truth](../tests/phase3d/fixtures/world.json), [scenario table](../tests/phase3d/fixtures/scenarios.json)
- The dry-run tests sign literal wire inputs with fixture-owned Ed25519 keys and independent JSON encoding. They read authenticated audit rows, rejections, the owner binding, the replay cursor, and the scoped withdrawal from separate read-only SQLite connections. The acknowledgment double reads that state at the point the consumer attempts to acknowledge. The restart test additionally checks that the effective decision denies the withdrawn finding while the historical row stays available. [Dry-run suite](../tests/phase3d/test_dry_run.py), [wire inputs](../tests/phase3d/fixtures/dry_run.json)

## Coverage and required outcomes

| Risk | Independent check | Where exercised |
| --- | --- | --- |
| Forged or contradictory evidence | Recompute the object digest and verify signed attestation bytes with pinned keys. Require two enrolled organizations excluding the submitter. A credible same-scope contradiction blocks eligibility even with two positives. Other-scope and inconclusive records have separate controls. | Toy evidence fixtures. Phase 2C wire tampering and a signed same-ID conflict cannot alter the durable finding or consume its sequence. |
| Stale revocation and trust state | Deny on expired, regressed, or incomplete status. A withdrawal learned during rollout blocks later writes or invalidates confirmation. | Toy status timeline. Phase 2C replay preserves the exact publisher, artifact ID, and digest tombstone across restart, a regressed journal head, and revocation of the old revoker key. |
| Incorrect inventory assumptions | Require exact build, configuration, and route coverage, and recheck live inventory generation at each write. | Toy inventory assertions. Phase 2C records different per-agent decisions for exact and different installed versions of the same package. |
| Incomplete protection across routes | Compare every observed replica and route against the frozen topology. A reachable marker fails protection. A missing or old-fence reading makes coverage inconclusive. | Toy route and observer fixtures. |
| Unsafe rollback and expired leases | Reject writes at lease expiry and invalidate confirmation at that boundary. Capture even transient writes that reopen an affected route. Require fresh marker readback over all paths for a verified safe hold. | Toy clock, chronological write log, and fallback probes. |
| Agent identity and replay confusion | Check capability agent, replica, fence, and prior consumption. A duplicate delivery after a lost acknowledgment must leave one committed row for each independent agent. | Toy capability fixtures. Phase 2C owner binding and acknowledgment-time SQLite readback across restart. |
| Partial rollout and service disruption | Require a passing canary observation before peer writes. Require marker suppression and healthy benign traffic on every path before claiming protection. | Toy rollout, bypass, and service-loss fixtures. |

## Interpretation and integration

The 44 synthetic checks qualify the fixture and oracle against scripted outcomes. The three Phase 2C checks exercise committed dry-run code. The candidate has no Phase 3 evidence, status-witness, or fixture-control implementation wired to this suite. Phase 3 implementation acceptance remains pending.

For candidate validation, preserve the fixture inputs and expected outcomes. Replace scripted writes with calls to the candidate's authorized synthetic interfaces. Capture the effective eligibility decision, committed writes, probe readings, and recovery transitions at their respective boundaries. Compare each with the frozen expectation and use the fixture observer and write log to verify effects. Run the affected, restricted, service-loss, and observer-loss controls before interpreting a rollout. Keep the candidate's own success messages out of the observer inputs. A synthetic safe hold establishes marker suppression within these fixtures. It may deliberately interrupt benign service and carries no claim of full protection.
