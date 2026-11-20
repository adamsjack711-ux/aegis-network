# Phase 4E-C withdrawal status v2

`withdrawal-v2` is an opt-in shadow profile. It preserves the existing 3-of-4 checkpoint threshold and adds a signed withdrawal view from each of the four enrolled witnesses before either the publisher or relying reader can return a positive result. The native shared writer remains on its existing T4/T5 path. The reproduced `checkpoint-v1` behavior and its evidence at `f169234` remain the historical control. [Integration finding and baseline evidence](phase4e-trust-integration-review.md)

Independent validation found a post-I/O expiry race at the original pin and measured the separate shadow fix at `8042097bbcd2a0f30d146d5057a6c846ee3ac746`. The full results preserve the original failure and the remaining integration gates. [Independent withdrawal validation](phase4e-withdrawal-independent-validation.md)

## Protocol and denial precedence

| Concern | Behavior |
| --- | --- |
| Version and migration | Set `status_profile` to `withdrawal-v2` in the shadow policy. Its context has a new version domain. Missing configuration selects `checkpoint-v1` and retains its existing context and API. The experiment starts with newly provisioned disposable stores. Importing history or changing a deployed trust context requires a separate reviewed migration that preserves denials and protected floors. |
| Direct admission | A witness authenticates the native revoker role, key, cohort, target scope and signed original before anchoring its admission and issuing a receipt vote. A single authenticated vote is a deny input for that exact record. Three matching votes are still required to certify a log leaf. An unmerged withdrawal remains separate from a witnessed inclusion proof. |
| Checkpoint coverage | A signed proposer head still needs three fresh matching coverage votes plus replay and continuity verification. A fourth witness may return a fresh withdrawal view even if it has no checkpoint. Loss of an ordinary checkpoint vote and loss of a required withdrawal view have different availability implications. |
| Fresh withdrawal views | Each reader requests a view from every pinned witness at `POST /v2/withdrawals` using a separate operation credential. The witness signs the exact status challenge, enrolled operator identity and ordered receipt digests in the new signature domain. Each receipt binds the original record bytes, policy context and admission epoch to an enrolled witness key. Invalid, missing, replayed or expired views hold the read. The same nonce, scope and deadline bound the two appraisal passes. |
| Deny precedence | A valid partial receipt can suppress positive status before quorum or inclusion. Native Mesh withdrawals match the exact publisher, artifact UUID and finding-body digest. Native Evidence withdrawals match the enrolled bundle, attestation or verifier-key scope and run through the same historical appraisal and independent verifier threshold. An unrelated valid receipt does not deny a different exact scope. Neither a witness's boolean flag nor an unverified record is retained as a denial. |
| Durable retention | A publisher and relying reader each append verified original records and receipt votes to a separate local denial ledger with its own anchor namespace. A valid record is retained even if another withdrawal lane is unavailable. Retraction or omission cannot erase an already retained record. A stale ledger, unavailable anchor or exhausted retention fails closed. Status tokens check both checkpoint and withdrawal anchors before use. Recovery of a mismatched store requires replay or restoration of the exact anchored data. |
| Existing authority | No new enforcement binding is added. The 3-second lab challenge and the existing signed-cut deadline bound the shadow decision. The native shared writer keeps its one-second refresh budget and mandatory-two native Evidence semantics. The original canary safety and approval rules continue to apply there. |

The four-view rule protects positive results when a single **honest** witness has already accepted an authorized withdrawal by the time it samples its view. A sole Byzantine recipient can conceal its own unreported receipt, and a withdrawal that arrives after sampling can race a result inside its short deadline. The experiment provides no proof about an unpublished withdrawal. A witness can hold availability by going offline. A single receipt authenticates the witness's assertion about the admission epoch. Historical grants are checked against that epoch. An actor controlling a retired revoker key and a dishonest witness could create a conservative false denial by backdating it. Independent historical timestamping or adjudication is an additional gate for cross-custody promotion.

All observations use separate processes, stores and disposable credentials on one host. The shared fixture controller and SQLite anchor remain in the same administrative boundary. The existing release **NO-GO** remains in force for shared-writer activation and distributed enforcement. Multi-host and independently administered trust and restore testing remain required.

## Regression and reproduction

The focused regression reproduces the historical false positive, then returns `revoked` in v2 after only one valid receipt while the other three witnesses still corroborate the same checkpoint. It exercises a healthy three-vote checkpoint with all withdrawal endpoints reachable, denial when the fourth endpoint is unavailable, an unrelated scope, a forged native revocation under a valid witness signature, a substituted receipt signer, a replayed challenge response, retention during an outage, and denial after restart and stale store restore.

```sh
cd .worktrees/phase4e-trust
PYTHONPATH=src:. python -m pytest -q -p no:cacheprovider tests/phase4e/test_withdrawal_status.py
PYTHONPATH=src:. python scripts/benchmark_phase4e_withdrawal_status.py \
  --sizes 4 128 --repeats 12 --output benchmarks/phase4e-withdrawal-status-v2.json
```

The completed suite passed **283 tests**, including all 14 cases under `tests/phase4e`. Three Docker opt-ins were skipped in this run. The suite reported the inherited Starlette/httpx deprecation warning.

## Availability and latency

The benchmark alternates the order of the two profiles by history size and uses 12 warmed reads per arm on disposable Unix sockets. A one-witness outage is tested separately from the single-receipt scenario. The checkpoint has three available signers in the outage arm. The healthy samples have no retained withdrawals. The single-receipt response is one measurement per arm and excludes intake. The experiment does not estimate distributed availability or performance at the retention bound. [Raw observations and source fingerprints](../benchmarks/phase4e-withdrawal-status-v2.json)

| Records | Profile | Healthy full appraisal p95 | Publisher response p95 | Positive with one withdrawal lane offline | One receipt to refreshed result |
| ---: | --- | ---: | ---: | ---: | --- |
| 4 | `checkpoint-v1` | 52.83 ms | 26.07 ms | 12/12 | 36.26 ms, reproduced |
| 4 | `withdrawal-v2` | 61.52 ms | 30.13 ms | 0/12 | 60.59 ms, revoked |
| 128 | `checkpoint-v1` | 464.24 ms | 234.78 ms | 12/12 | 448.22 ms, reproduced |
| 128 | `withdrawal-v2` | 548.05 ms | 309.29 ms | 0/12 | 468.15 ms, revoked |

Both profiles returned positive results in all 12 healthy reads at each size. V2 held every one-lane outage, with 9.53 ms and 7.35 ms p95 latencies at 4 and 128 records. The run used Python 3.15.2 on one arm64 macOS 27.0.1 host. These small-sample nearest-rank p95 timings include each participant's independent appraisal.
