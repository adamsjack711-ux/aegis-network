# Phase 4D release readiness

## Decision

The isolated branch `integration/phase4d` integrates the witnessed native Trust profile for an explicitly approved disposable lab fixture. Distributed mitigation is disabled. The three Phase 4C High findings have independently rerun scoped dispositions and remain release blockers for distributed writes. Existing Phase 2 dry-run and Phase 3C fixture behavior remain supported experimental paths. Phase 5 engineering can use the branch for closed-lab deployment adapters and independent validation. Promotion to a distributed enforcement pilot requires a new reviewed candidate. [Security dispositions](phase4d-security-review.md) · [Benchmark scope](phase4d-benchmarks.md)

## Acceptance checklist

| Gate | Result | Release evidence still needed |
| --- | --- | --- |
| Pinned Phase 3C, 4A, 4B, 4C and Trust provenance. Original histories and frozen wire contracts retained. | Pass | Review any versioned shared contract changes before enabling a new path. |
| Native Evidence, Mesh, Rapid, independent protection observer and lab mitigation continue to operate. | Pass for legacy and witnessed disposable fixtures | Qualify real actor placement and run the same probes under actual network failure. |
| All three High findings have independently rerun defensive cases and an explicit disposition. | Pass for disposition. Open for live closure. | Repeat at real authenticated interfaces with separately controlled principals and durable stores. |
| Untrusted coordinator cannot override history coverage or Evidence status. | Demonstrated at the native fixture, after quorum admission and the covered cutoff and with pinned independent status roles. | Exercise actual mTLS and role custody, denial receipt transport, end-to-end rotation and failure of the restore domain. |
| Cross-broker ownership and target fencing validated. | Live loopback contenders and fixture-local durable generations pass. | Exercise authenticated failover and session/ACK fencing, independent restore and a barrier across all separately writable targets. |
| Offline and reconnect behavior explicitly fail closed. | Native tests lose the status path, deny peer mutation and reject resuming an old approval after status recovers. | Live denied renewal through cutoff, long isolation across rotation, older target and witness snapshots and reconnect to the current authority cut. |
| Complete regression and adversarial suite. | 272 passed, zero failures or skips. | Repeat the combined adversarial campaign with independently administered network endpoints. |
| Trust, protection, verification CPU and operational overhead. | Scoped local measures available. | Replicated coordinator and witness outage, concurrent agents on the authoritative trust path, delivery from independent withdrawal receipt and real network-to-denial latency. |
| Risks and limits recorded, writes remain local. | Pass | Monitor open risks below. |

## Test record

The first inherited live run passed **210** tests before the shadow and native workstreams were integrated. The final tested code and test tree at `f26f69d5b41284ab675bad4368387be76410e544` passed **272 tests in 76.97 s** with all three live modes enabled, zero failures or skips, and one inherited Starlette/httpx deprecation warning. It includes the strengthened T4 restore assertions, T3 broker contention, 4C adversarial cases and independent protection readback. Reproduction uses disposable Docker and Unix/loopback sockets. The ordinary runtime remains dry-run and the lab writer requires explicit local approval.

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 AEGIS_PHASE4A_LIVE=1 \
  AEGIS_PHASE4D_LIVE=1 AEGIS_PHASE4D_T3_LIVE=1 \
  python -m pytest -q -p no:cacheprovider
```

## Handoff order

1. Test real identity enrollment through two independently administered broker contexts. Fence the prior generation at every existing writer before granting a replacement, including after storage restore.
2. Run independent admission, archive, and status services outside coordinator control. Test receipt and checkpoint continuity, stale status, lost signers, certificate rotation and exact binding to the same local plan and expiry.
3. Repeat T6 against the deployed lab topology with independent SQLite and HTTP readback. Record every attempted, denied, committed, confirmed and restrictive-recovery outcome.
4. Re-run paired throughput, latency and cost trials on authoritative Trust with declared denominators and pinned host, transport and resource limits. Include burst and witness failure, recording operational and availability costs.

[Integration dependency plan](phase4d-trust-integration.md) · [Risk register](phase4-risk-register.md)
