# Phase 3C integration

## Pre-change conflict register

Recorded before modifying source. The worktree starts from Phase 2 RC `ffe5c322b144ab3fb40d2ee29b1486b917d339f1`. Reviewed the Phase 2 contracts, threat model, hardening and RC handoffs, Phase 3 design proposals, and the three feature handoffs.

| Input | Ancestry and conflict | Integration choice |
| --- | --- | --- |
| Evidence `b2628f2d0a59d0eed1352e8d3f0ef7055909efe2` | Bespoke Evidence signature domain and opaque claim digest. Its parent `14440ee` predates hardened Mesh. | Import additive files. Bind the evidence claim to the exact Phase 2 finding payload excluding its circular evidence reference. Reappraise signed records locally. |
| Mitigation `83cacbd8f9eac9dc4a5eef558cb613fe1a46a498` | Also based on `14440ee`. Its standalone plan starts from local fixture state and has no Evidence or Rapid binding. | Keep the existing disposable adapter. Add a typed, hash-bound integrated plan to the local approval path and guard target transactions. |
| Validation `1fca3858165c67d491f35b15c7009fef6d940d1c` | Common ancestor with the RC is `65ebb3a`. Its scripted oracle validates synthetic scenarios and hardened dry-run audit behavior. | Preserve the independent fixtures and existing assertions. Add live candidate checks using HTTP observations and durable audit readback. |
| Phase 2 RC | Phase 2 signed payloads, scoped revocations, UUID durable leases, journal and ack rules are distinct from the new contracts. | Leave the existing wire contracts and default dry-run entry points in place. Use the standard Mesh path and commit-before-`ack_sync()` handler. |
| Signature-reason regression | The Evidence and Mitigation handoffs report a text mismatch on `14440ee`. The pinned RC test already asserts `INVALID_SIGNATURE`, no watermark advance, and acceptance of a later valid lower sequence. | Preserve the RC assertion and verify it in the combined suite. Keep signature rejection and separate expiry reasoning. |

Evidence and effectiveness have different authority. The former qualifies a finding about one exact inert fixture. The latter observes actual HTTP behavior after an approved local transaction. Only local review can issue a capability. A local status feed and the existing Mesh journal are available in the lab. Neither constitutes independent proof that a compromised coordinator disclosed every withdrawal.

## Integrated path

1. The publisher verifies the exact registered route-toggle manifest and four SHA-256-pinned materials through isolated verifier workers. Two pinned organizations must produce signed corroboration. The publisher signs only the exact enrolled synthetic finding after verification.
2. The signed v1 finding points to the signed manifest by a single `urn:aegis:evidence:<digest>` reference. No agent follows the URI. The lab supplies the matching portable package through a locally configured in-process channel. The manifest binds all signed finding payload fields other than the evidence field. The signed finding in turn binds the exact manifest digest. The Mesh-safe template identifier `restrict-fixture-route.v1` maps to the compiled lab template `restrict-fixture-route/v1`. This preserves the Phase 2 template identifier grammar.
3. The original HTTP, PostgreSQL journal and outbox, JetStream stream, UUID lease, and `ack_sync()` path distribute and audit the finding. Each receiving deployment checks its pinned publisher keys and local inventory independently. Enrollment initializes separate SQLite files. The test runner waits for the broker-confirmed agent decision before offering a plan.
4. A second Evidence ledger imports and verifies each qualifying attestation with its own pinned public trust. The action plan binds the finding ID and digest, agent UUID, bundle digest and sorted attestation digests through an evidence binding in the plan digest. The adapter journals the binding and its component identifiers alongside the lease. Only an exact digest approved through the local entry point mints the process-local approval and per-target capabilities.
5. Before each target transition, the integrated local gate refreshes the Phase 2 journal, validates broker lease ownership, and rechecks Rapid's current effective decision. A one-second monotonic freshness budget limits reliance on that check. The guarded SQLite write reappraises the local and collector evidence ledgers and coordinates with signed evidence status updates on the trusted local host. It requires the same current attestations and checks freshness again before commit. An expired plan cannot outlive the relevant signing and evidence lifetimes.
6. The adapter verifies the three fixture replicas and exact fences, applies the canary and checks its HTTP behavior before peer writes. The independent HTTP reader confirms the restricted marker route and the two benign routes on every replica at the current generation. Protection is recorded after a complete successful observation. Status or health loss, an interrupted rollout, expiry, or operator stop after leasing quarantines the fixture. A separate HTTP check must observe quarantine before `safe_hold`. A quarantined fixture intentionally denies benign traffic as well.

The Phase 2 entry point remains dry-run. The legacy ungated Phase 3B operator CLI now points to the integrated entry point. The low-level Phase 3B adapter remains available to its isolated component tests. Protection runs only against the compiled synthetic inventory and local Unix socket upstreams. The executable contains no production adapter or remote action endpoint.

## Reproduce

From `.worktrees/phase3c`, install the project's test dependencies into a local Python environment. Use a disposable Compose project with the three loopback ports in `compose.hardening.yaml`. Use a different project and free loopback ports if another lab occupies them. The fault harness expects project `aegis_phase3c`. Store test audit databases under a private temporary directory.

```sh
export PYTHONPATH=src
export AEGIS_DB_PASSWORD=local-phase2c
python -m pytest -q -p no:cacheprovider
python -m compileall -q src scripts tests
python scripts/setup_lab.py
docker compose -p aegis_phase3c -f compose.yaml -f compose.hardening.yaml config -q
docker compose -p aegis_phase3c -f compose.yaml -f compose.hardening.yaml up -d --build coordinator
python scripts/phase3c_lab.py --agents 3 --directory /tmp/aegis-3c-interactive --hold-ms 500
python scripts/phase3c_lab.py --agents 3 10 100 --eligible 2 --repeats 10 --scripted-approval \
  --directory /tmp/aegis-3c-bench --output benchmarks/phase3c-pipeline.json
python scripts/phase3c_faults.py --directory /tmp/aegis-3c-faults --output benchmarks/phase3c-faults.json
docker compose -p aegis_phase3c -f compose.yaml -f compose.hardening.yaml up -d --build agent agent_b
python scripts/phase2c_live.py --project aegis_phase3c --override compose.hardening.yaml \
  --integration-only --extended-faults
python scripts/benchmark_phase3a_evidence.py --deployments 3 10 100 --scenarios cold distinct \
  --repetitions 5 --output benchmarks/phase3c-verification-cpu.json
docker compose -p aegis_phase3c -f compose.yaml -f compose.hardening.yaml down
```

For a clean live regression rerun, start with fresh named lab volumes. The Phase 2 regression deliberately purges the lab findings stream. Its controlled faults affect only this lab project. Keep experiment cohorts and keys private and disposable.

## Acceptance checklist

- [x] Pinned Phase 2 RC retained, three additive feature commits imported, and incompatibilities recorded before code changes.
- [x] Digest-pinned synthetic intake, isolated signed verifier observations, cache reuse, and per-deployment signature and scope appraisal.
- [x] Withheld approval, invalid attestation or issuer, contradiction, expiry, withdrawal, stale plan, and stale inventory or fence deny the corresponding write.
- [x] Broker-confirmed per-agent finding decisions and exact inventory denials with durable SQLite audit. Phase 2 signed formats, journal, outbox, identity and acknowledgment source unchanged.
- [x] Evidence-bound local plan, bounded active lease, fenced canary and peer writes, actual HTTP effectiveness and health checks, and independently observed restrictive recovery.
- [x] Original Phase 3D tests retained and passed. Their scripted toy assertions qualify the oracle and are distinct from the candidate's new live HTTP tests and Compose runs.
- [x] Signature-reason regression covered by the RC's stable `INVALID_SIGNATURE` assertion. The test verifies a rejected high sequence cannot poison local ordering.
- [ ] Multi-host availability, witnessed status completeness, and administratively independent observers remain outside this lab proof.

## Local benchmark results

Implementation under test is `1cb5cd60467ad6885f8aa1350197f576c06ae0ed`. The host was macOS 27.0.1 arm64 and Python 3.15.2. PostgreSQL 16 and NATS 2.10 ran in local Docker Compose. The host ran the pipeline driver, disposable fixture servers and separate verifier subprocesses. Each synthetic agent had its own UUID lease, durable subscriber and SQLite audit. They shared one host event loop and NATS connection. Two logical deployments per episode were enrolled for actual local control, each with three independently probed replica endpoints. The remaining agents were intentionally ineligible and exercised exact-inventory denial. Each scale ran ten episodes with a 3,000 ms lease.

Timing starts immediately after independent verification and the publisher's finding signature are complete, before submitting the finding to Mesh. It ends after the adapter commits successful all-replica HTTP observation. The driver records all spans against the same monotonic host clock. Submission to receipt includes HTTP, outbox, NATS and local scheduling. It does not isolate network transit. The stage timing for audit includes lease check, local validation and SQLite commit. The table uses linear-interpolated percentiles of individual observations. Stage percentiles overlap and should not be added.

| Agents | Broker-confirmed deliveries | Eligible confirmed | Verified to protection p50 / p95 / p99 (ms) | Verified to receipt p50 / p95 / p99 (ms) | Verified quarantine p95 (ms) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 30/30 | 20/20 | 463.931 / 512.200 / 515.834 | 18.210 / 32.687 / 32.797 | 46.707 |
| 10 | 100/100 | 20/20 | 484.155 / 532.374 / 534.589 | 18.778 / 19.869 / 19.919 | 45.705 |
| 100 | 1,000/1,000 | 20/20 | 565.701 / 602.859 / 604.969 | 21.968 / 41.031 / 41.493 | 44.225 |

| Agents | Verification and signing p95 (ms) | HTTP submission p95 (ms) | Rapid audit p95 (ms) | Broker ack p95 (ms) | Preflight / canary / expansion / effectiveness p95 (ms) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 72.783 | 20.320 | 4.977 | 3.205 | 70.496 / 130.035 / 37.354 / 67.245 |
| 10 | 72.263 | 12.692 | 10.243 | 8.894 | 65.992 / 69.412 / 41.017 / 67.744 |
| 100 | 74.412 | 13.508 | 69.987 | 67.822 | 66.164 / 70.075 / 35.500 / 63.874 |

All 1,070 ineligible deliveries were denied and triggered no fixture writes. The 60 eligible rollouts committed their plan and all-replica confirmation and reached verified quarantine on operator stop. After confirmation the repeated independent observations saw zero marker escapes in 360 marker probes and zero unexpected failures in 720 benign probes. Quarantine intentionally returns 503 on all paths. The benchmark did not test sustained benign load or every eligible agent executing concurrently. The p95 was under 30 s at all measured scales with scripted approval and 20 protected deployments per scale. One interactive smoke invocation with exact digest entry took 7,817.449 ms including the local approval wait. Human approval p95 and statistical confidence for the 30-second gate remain unmeasured. [Raw pipeline runs](../benchmarks/phase3c-pipeline.json)

### Verification CPU

The paired CPU benchmark uses the same two-verifier policy for shared and repeated arms. It charges the parent and child processes for verification, cache and per-deployment signature appraisal. It excludes Mesh publication and rollout because those stages are the same in both arms and were measured separately above. The shared cold workload uses three exact reusable keys, one per inert fixture family. Five pairs were run per scale and scenario with opposite arm order across repetitions. CPU times are median aggregate core-seconds. The ratio is the median of paired ratios.

| Deployments | Workload | Worker attempts repeated / shared | CPU repeated / shared (s) | Paired reduction |
| ---: | --- | ---: | ---: | ---: |
| 3 | Cold, three keys | 6 / 6 | 0.1950 / 0.1961 | 1.00× |
| 3 | All distinct | 6 / 6 | 0.1945 / 0.1973 | 0.99× |
| 10 | Cold, three keys | 20 / 6 | 0.6497 / 0.2211 | 2.94× |
| 10 | All distinct | 20 / 20 | 0.6547 / 0.6439 | 1.02× |
| 100 | Cold, three keys | 200 / 6 | 6.0851 / 0.5525 | 11.15× |
| 100 | All distinct | 200 / 200 | 6.1917 / 6.1617 | 1.01× |

At 100 deployments on the cold reusable workload, every pair reached 10× (observed range 10.9479–11.5824×). Both arms matched expected outcomes on the frozen corpus. Five local pairs support an observed result for this reuse-heavy workload. They do not establish a lower confidence bound or savings across arbitrary evidence mixes. [Raw verification CPU runs](../benchmarks/phase3c-verification-cpu.json)

## Tests and fault observations

On 2026-11-19, **129 tests passed**, with one third-party Starlette TestClient deprecation warning. This includes the 47 Phase 3D checks, the combined RC, Evidence, and Mitigation suites, and four integrated tests. The integrated tests reject claim rebinding, forged or unenrolled attestation signers, exact-plan mismatch and stale status. They also verify that a signed contradictory observation blocks a cached positive plan, and that an Evidence withdrawal after the canary prevents peer writes while the independent HTTP observer verifies safe hold. The imported Phase 3B tests run live local proxies and cover failed canary, stale fences, proxy and store loss, and fixture write crashes around the commit boundary.

During a verified rollout's post-confirmation interval a live scoped Mesh withdrawal reached the effective local denial through journal reconciliation. From injection to independently verified quarantine took **117.530 ms**. A separate broker-stop run reached independently verified quarantine in **1,304.709 ms**, including the Docker stop call and bounded Mesh refresh deadline. Neither case emitted a marker in its 18 post-recovery observations. On the first fault attempt, reconnect exposed a timed-out lease refresh applied with a newer broker revision. The integrated runner now checks ownership before deleting its disposable consumer and leaves an unmatched lease to expire. The rerun passed. [Raw Phase 3C faults](../benchmarks/phase3c-faults.json)

The original two-container Phase 2 regression also passed against the final build. It exercised duplicate delivery, UUID lease collision, scoped and stale event denial, findings-stream purge and journal replay, malformed and oversized messages, slow consumer recovery, and agent and coordinator crashes. The 40-event backlog reached 80/80 decisions in 2.163 s, the agent network partition recovered in 0.511 s, and the agent SIGKILL recovered in 30.554 s including lease expiry. Phase 2 tests record dry-run results. [Raw Mesh regression](../benchmarks/phase3c-mesh-regression.jsonl)

Compilation, Compose configuration parsing, and staged diff checks passed. Final live-regression image ID prefixes were `83ab0c0715d5` for the coordinator, `1d5b02d3a994` for PostgreSQL, and `b83efabe3e7d` for NATS. The Phase 3C Compose containers and network were removed after testing. Named volumes remained for audit inspection.

## Unresolved risks

- Mesh replay relies on the existing coordinator journal. A malicious coordinator can withhold a valid event or withdrawal while presenting internally consistent signed items. The short freshness bound handles an unavailable source and detected errors. Authenticated clients, an independently witnessed completeness proof, and multi-host failover remain open.
- Portable Evidence exchange and the corroboration status source run inside the trusted local driver. The worker keys simulate two enrolled organizations. The effectiveness reader probes HTTP independently of the write transaction but shares the lab host and process. Adversarial control of that host, its local SQLite files, or independent operator enrollment remains untested.
- The initial baseline exposes an inert marker, and replicas awaiting canary promotion retain baseline behavior only inside the disposable lab. Observations cover declared routes and fences. Quarantine protects at the cost of service disruption. A restored snapshot or bypass outside the compiled fixture topology is outside this evidence.
- Root trust and signed historical key rotation, broker ACLs and cross-broker identity, overload quotas, protected audit backup and recovery, and verification under sustained fault load remain open. Exact hashes and on-disk records aid audit correlation. They do not make a trusted local ledger tamper resistant.
