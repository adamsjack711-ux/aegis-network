# Phase 4 integration plan

## Baseline and worktree readiness

On 2026-11-19 the Phase 3C worktree and all three Phase 4 worktrees were clean at `7744ebd7f80e6f2aabb253d5cc3ec9972c86cffd`. This includes implementation `1cb5cd60467ad6885f8aa1350197f576c06ae0ed` and the Phase 3C handoff. The pinned full suite passed **129 tests** on Python 3.15.2 with one Starlette/httpx deprecation warning. Compilation, Compose configuration parsing and an isolated live fanout and control rerun passed. Original branches and working changes were preserved. The three existing Phase 4 worktrees are approved as development bases within the ownership below. This approval does not adopt a new interface or release any code. [Phase 3C baseline](phase3c-integration.md) · [Frozen contracts](phase4-contract-review.md)

## Ownership and boundaries

| Workstream and worktree | Owns | Handoff and boundary |
| --- | --- | --- |
| **4A distributed systems** · `.worktrees/phase4a-distributed` · `feat/phase4a-distributed` | Mesh topology and transport, independent durable consumers, broker identity isolation, leases, retry and recovery measurements, distribution instrumentation | Submit a pinned topology and runbook, per-agent audit and acknowledgment traces, and loss/recovery matrix. 4A may deploy disposable processes and configure isolation. Changes to signed bytes, effective local policy, target writes, and the observer need cross-surface review. |
| **4B Evidence** · `.worktrees/phase4b-evidence` · `feat/phase4b-evidence` | Evidence package portability and compatibility criteria, worker enrollment interface, cache and single-flight, verification CPU measurement | Provide exact-scope and compatible-environment vectors, a negative portability matrix, signed intake and invalidation evidence, and paired raw costs. Local reappraisal and authority remain at Rapid. New schemas and broader reuse rules go through contract review. |
| **4C adversarial resilience** · `.worktrees/phase4c-adversarial` · `test/phase4c-adversarial` | Independent threat cases, test oracles and fault schedules, compromised participant simulations, status completeness and trust recommendations | Provide independently derived expected outcomes, before/after evidence, source revisions, severity, and disposition for each finding. Fixes touching 4A or 4B implementation are reviewed with those owners. 4C does not assert safety from candidate self-reports. |
| **Integration lead** · this architecture worktree | Contract freeze, decisions, risk review, sequencing, evidence ledger for gates, and go/no-go | Verify all pinned candidates and review the handoffs before creating a separate integration candidate. Preserve local Rapid authority and approval. Coordinate the fixture adapter and final observer behavior across workstreams. |

Independent agents have separate processes, deployment identities, credentials, pinned trust and persistent local storage. Separate fault domains also require independently controllable network links and deployment instances. Use at least three separate lab VMs or hosts for the first independent topology. Record shared hypervisors, host-level failure domains, enrollment authorities and control services. A multi-host claim requires distinct physical hosts. Label co-located processes and logical consumers separately when scaling. Organizational independence of verifier signers is a separate claim and requires its own enrollment evidence.

## Integration order

1. **Record intake.** Each workstream supplies branch and exact commit, ancestry from the agreed baseline, worktree status, approved proposal IDs, source diff, environment manifest, tests and raw results, and unresolved risks. Review branches read-only. Create a separate integration candidate from the pinned baseline after intake. Use an explicit reviewed commit list.
2. **Integrate 4A.** Establish the independently operated topology without changing published contracts. Verify broker ownership, isolated credentials and volumes, acknowledgment ordering, duplicate/resend behavior, and failover and replay. Compare with the pinned same-protocol single-host control. Full topology measurements must retain the number of eligible deployments and all fault denominators. Unwitnessed status can be measured in a dry-run lane.
3. **Integrate 4B.** Add the reviewed Evidence package and cache behavior on top of the verified 4A candidate. Use a compatibility matrix before reuse counts toward correctness. Run the original verification comparison and the new portable-environment workload. Verify that cache hits still check trust, current status, and local inventory. Re-run the 4A acceptance cases after integration.
4. **Integrate 4C.** Preserve independent validation fixtures and their expected outcomes. Target the exact 4A+4B build. Verify known blockers first, then the full trust and fault matrix with independent readback. Any approved fixes to shared surfaces go through the contract review and rerun steps 2 and 3 where affected. Pin the final candidate only after checks against its exact source and build identity.
5. **Record the decision.** Complete the checklist below and publish a local candidate using the reviewed revision and raw records. Unresolved critical safety or authority failures block a Phase 4 protection release. A narrower dry-run result can still be recorded with its scope and blockers.

## Benchmark protocol

- **Comparability.** First rerun the original 3/10/100 single-host Phase 3C workload. Preserve ten episodes, 3,000 ms lease, the same two eligible three-replica fixtures per episode, and scripted local approval. Pin source, resolved dependency and image identities, deployment map, trust configuration, fixture and oracle digests, CPU limits, journal state and reset procedure. Then run the proposed distributed topology with a matched baseline and show what changed. Report producer, worker, agent and observer locations and administrative control explicitly.
- **Statistics and clocks.** Preregister workloads, eligibility, fault schedule, warm-up treatment, deadlines and success criteria. Use at least five independent, reset repetitions per comparison arm with paired workload seeds and counterbalanced order. Block or resample by episode, host or run to account for correlated agent deliveries. Report per-trial results and confidence intervals alongside p50/p95/p99. If the sample cannot distinguish the target from noise or its uncertainty crosses the threshold, record the result as inconclusive. Use one monotonic clock per span where possible. Use a single observation harness or calibrated clocks for cross-host intervals and report uncertainty. At a deadline use the conservative timestamp bound.
- **Latency and protection.** Primary end-to-end time starts after a finding is verified and signed, before Mesh submission, and ends at durable confirmation from independent all-scope marker and health checks. Report verification, publish, receipt, local audit/ack, approval wait, preflight, canary, promotion, confirmation and recovery stages. Measure human and scripted approval separately. The protection denominator is all deployments declared eligible before scheduled submission. Count disconnected, unobserved, timed-out and rolled-back cases as non-completions for the protection deadline. Publish a successful-only percentile separately. Use the existing p95 ≤30 s research target and keep decision latency distinct from protection.
- **Verification cost and correctness.** Use matched repeated and shared arms with equal verifier quorum, artifact corpus, hardware limits and expected outcome criteria. Run cold and warm caches, exact reuse, supported and unsupported compatibility, cohort isolation, and a changed or withdrawn workload. Include warm-up, cache, attestation appraisal and retries in aggregate parent and child CPU seconds. Publish total CPU and CPU per correct eligible appraisal plus memory, transfer, and consumer-side cost. Charge orchestration differences explicitly. Evaluate the historical ≥10× threshold on a predeclared three-key cold workload. Also report all-distinct and mixed workloads so the reuse fraction is visible.
- **Coverage and fault behavior.** For delivery, denominator is all intended event-agent pairs. Count covered only after both durable local decision and broker-confirmed acknowledgment. Report duplicate rows and redeliveries separately. For protection and recovery report eligible, approved, confirmed, safely held, unresolved and ineligible deployments. For service disruption report failed benign requests over scheduled benign probes and time to restored benign service separately from verified quarantine. For safety report unauthorized write attempts, unauthorized committed transitions, and marker observations over scheduled protected or held probes. Unknown or missing observations count as unknown and block confirmation. Preserve negative runs.
- **Mutual validation.** Test normal and fault conditions in paired workloads. Record time from withdrawal or status loss to last possible authorized write and to verified safe hold. Distinguish propagation, detection and observed recovery. Reproduce key cases from a second clean environment using the same scope and documented commands. A faster run with weaker local or observer checks fails comparability.

## Original Phase 3 benchmarks and fresh controls

The existing results establish a single-host control. The fresh run used the same pinned source, Mac arm64, Python 3.15.2, Docker Compose 5.5.1, 10 episodes per scale, two eligible fixture deployments each, and a fresh isolated Compose journal on different loopback ports. All 1,130 event-agent pairs in each run were acknowledged and all 60 eligible deployments confirmed. Each series observed 0/360 post-confirmation marker escapes and 0/720 unexpected benign probe failures. The difference between runs is baseline variability. There was no Phase 4 candidate in either run.

| Agents | Eligible / confirmed per series | Phase 3C protection p50 / p95 / p99 (ms) | Fresh Phase 3C control p50 / p95 / p99 (ms) | Original → fresh receipt p95 (ms) |
| ---: | ---: | ---: | ---: | ---: |
| 3 | 20 / 20 | 463.931 / 512.200 / 515.834 | 324.282 / 342.762 / 345.291 | 32.687 → 40.314 |
| 10 | 20 / 20 | 484.155 / 532.374 / 534.589 | 365.200 / 378.015 / 380.190 | 19.869 → 21.056 |
| 100 | 20 / 20 | 565.701 / 602.859 / 604.969 | 472.736 / 486.503 / 486.972 | 41.031 → 24.408 |

Phase 3A's isolated verification results and Phase 3B's standalone route restriction timings are attribution controls. Phase 3C measures the full signed-delivery-to-protection path. Its scripted run does not establish a human approval p95 or independent multi-host operation. [Original Phase 3C pipeline](../benchmarks/phase3c-pipeline.json) · [Fresh pinned pipeline](../benchmarks/phase4-baseline-pipeline.json) · [Phase 3A](phase3a-evidence.md) · [Phase 3B](phase3b-containment.md)

The fresh verification control repeated five matched pairs at 100 logical deployments per workload. Both arms met their expected outcome on every declared case. Ratios are medians of paired repeated/shared CPU, with observed ranges rather than confidence intervals.

| 100-deployment workload | Repeated / shared worker attempts | Original median CPU ratio | Fresh median CPU ratio and range | Fresh median parent + child CPU, repeated / shared |
| --- | ---: | ---: | ---: | ---: |
| Cold, three exact keys | 200 / 6 | 11.1485× | 11.1647× (11.1117–11.2830×) | 6.4349 / 0.5757 s |
| All distinct | 200 / 200 | 1.0053× | 1.0073× (0.9914–1.0081×) | 6.4482 / 6.4012 s |

This reproduces the observed reuse-dependent CPU result for the Phase 3C workload. It excludes Mesh and mitigation CPU and leaves portable-environment reuse unmeasured. [Original verification records](../benchmarks/phase3c-verification-cpu.json) · [Fresh verification records](../benchmarks/phase4-baseline-verification-cpu.json)

### Reproduce the fresh control

From the architecture worktree at the pinned baseline, use the repository's Python environment and disposable Compose configuration. The override avoids the Phase 3C and Phase 4 developer ports.

Docker client and server were 29.8.0 and 29.5.2. The fresh Compose image ID prefixes were `67898a5e53a2` for the coordinator, `1d5b02d3a994` for PostgreSQL, and `b83efabe3e7d` for NATS. The verification JSON retains environment and source digests. The fresh control's Compose containers and network were removed afterward. Its local volumes were retained.

```sh
export PYTHONPATH=src AEGIS_DB_PASSWORD=phase4-baseline-local
cat > /tmp/aegis-phase4-baseline.compose.yaml <<'YAML'
services:
  nats:
    ports: ["127.0.0.1:14224:4222"]
  coordinator:
    ports: !override ["127.0.0.1:18084:8000"]
YAML
python -m pytest -q -p no:cacheprovider
python scripts/setup_lab.py
docker compose -p aegis_phase4_baseline -f compose.yaml \
  -f /tmp/aegis-phase4-baseline.compose.yaml up -d --build coordinator
python scripts/phase3c_lab.py --agents 3 10 100 --eligible 2 --repeats 10 \
  --broker-port 14224 --coordinator-port 18084 --scripted-approval \
  --directory /tmp/aegis-phase4-baseline-audit --output benchmarks/phase4-baseline-pipeline.json
python scripts/benchmark_phase3a_evidence.py --deployments 100 --scenarios cold distinct \
  --repetitions 5 --output benchmarks/phase4-baseline-verification-cpu.json
docker compose -p aegis_phase4_baseline -f compose.yaml \
  -f /tmp/aegis-phase4-baseline.compose.yaml down
```

### Release checklist

- [x] Pinned Phase 3C ancestry, clean worktrees, frozen contracts, and fresh baseline regression confirmed.
- [x] Original benchmark denominators checked and single-host protection and verification CPU controls reproduced.
- [x] Independent baseline security review recorded the replay-completeness blocker and its matched control.
- [ ] 4A, 4B and 4C submit exact reviewed revisions, environment manifests, and approved interface diffs.
- [ ] Separate candidate passes 4A transport and ownership gates, 4B portability and cache gates, then 4C integrated adversarial gates.
- [ ] Full regression and cross-component tests pass against the same candidate revision. Include legacy payloads, audit migration, role separation, stale status, unauthorized action, missing observation and restrictive recovery.
- [ ] Critical benchmarks reproduce with the stated topology, repeated trials, eligibility and coverage, confidence intervals, and raw outcomes.
- [ ] Every critical security blocker is resolved for the claimed operating scope with independent evidence. Document remaining risks, exclusions and their effect on scope.
- [ ] Record approval for the exact local release commit and summarize demonstrated findings and untested hypotheses.

**Readiness:** Development bases and the contract freeze are ready. Phase 4 integration intake is pending. The longest remaining dependency is evidence that a deployment cannot be misled into authorizing writes when a participant withholds status. Phase 4 release remains blocked until the new candidates and evidence satisfy the gates. [Risk register](phase4-risk-register.md)
