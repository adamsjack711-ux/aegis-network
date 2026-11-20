# Phase 4E performance and topology report

## Authentication and host scope

The user authorized disposable localhost or container fixtures and throwaway test signing material. No external hosts, real credentials, or production infrastructure are in scope. An authenticated physical multi-host run requires the authorized peer inventory, identity enrollment and credential references to be supplied and verified first. No such run was attempted. A local Docker VM, separate container, process, or Unix socket remains on one physical host and does not establish independent administration or physical failure isolation.

The local baselines used the existing Python 3.15 macOS arm64 environment and disposable loopback PostgreSQL and JetStream. Raw traces pin the build, runtime and Docker image IDs. Each locally measured interval uses one host monotonic clock. Test workloads use synthetic findings and dry-run decisions unless explicitly named a disposable protection fixture.

## Withdrawal and recovery controls

The independent A controls used the clean 4D pin with 24 unrelated ordinary findings, two mixed-role findings and two scoped withdrawals queued during broker outage. Both controls confirmed **28/28** queued events and **2/2** final exact denials. Each fault ran once.

| Controlled baseline fault | Ordinary findings ahead of independent withdrawal | Restart request to durable denial | Restart request to confirmed ACK |
| --- | ---: | ---: | ---: |
| Restart broker | 24/24 | 1.660 s | 1.661 s |
| Restart broker and SIGKILL agent | 24/24 | 29.590 s | 29.644 s |

The crash arm took 29.705 s from withdrawal submission to ACK, exceeding the historical five-second reporting threshold. These tests did not measure a protected route or writer deadline. The recovery duration includes renewed broker ownership. A live ACK can arrive after the actuator has lost authority, so it remains a separate metric. [A controls and reproduction](phase4e-withdrawal-recovery-validation.md)

## Historical timing references

The pinned lead 4D fixture measured p95 **185.949 ms** with Trust and **137.772 ms** on its preprovisioned legacy control, with 12/12 confirmations per arm. The one-host 4D 10-process broker comparison confirmed 810/810 decisions per arm. Its fault run recovered 310/310 logical decisions and recorded one late withdrawal. Those observations remain separate from Phase 4E experiments. The original Phase 3C p95 target was a verified-finding-to-confirmation span with scripted local approval. The lead 4D paired fixture starts after provisioning and data readiness. [Phase 4D methods and denominators](phase4d-benchmarks.md)

The historical 4B compatibility run and current oracle reruns are prior/current correctness controls with different runtimes and observed worker attempts. Their wall-time differences are observational. [Phase 4B discrepancy disposition](phase4e-risk-register.md#phase-4b-strict-discrepancy-disposition)

## Required multi-host results

Repeat matched runs with independent broker, home, target and witness hosts, a designated observer, explicitly scoped lab identities and protected continuity anchors. Before sending traffic, pin code and configuration revisions, image digests, endpoint and failure-domain placement, clock uncertainty, arrival rates, queue capacity and trial order. Confirm the healthy control on the same candidate and reset state between pairs.

Report eligible fixtures, exact durable denials, confirmed ACKs, rejection counts, verified safe holds, backlog age, and write and marker escape counts as distinct denominators. Report stage and end-to-end p50/p95/p99, maximum tested withdrawal-to-safe-state time, disconnect-to-fence time, process-owner recovery and actual CPU/RSS, including tails, resource rejections and failed or censored trials. Use a driver-monotonic send-to-independent-readback bound for intervals spanning hosts. A p95 global bound cannot be obtained by adding host-local stage percentiles. [Integration procedure](phase4e-integration-plan.md)

## Phase 4E local candidate observations

A recorded five controlled 1,000-finding broker-restart pairs, with two coordinator processes and one deliberately slow worker per arm. The opt-in priority lane acknowledged the withdrawal first in **5/5**. The legacy arm acknowledged it after all 1,000 findings in **5/5**. Every finding eventually drained. The repeated comparison used a candidate development tree, before the final lab fault and regression passes. Exact-pinned independent priority cases separately verified the ordering improvement.

| Measured p95 | Legacy | Priority |
| --- | ---: | ---: |
| Intake to independently observed durable denial | 4.956 s | 2.675 s |
| Intake to confirmed broker ACK | 13.874 s | 2.669 s |
| Ordinary backlog drain | 13.267 s | 13.629 s |
| Worker CPU | 3.442 s | 3.942 s |
| Two coordinators combined CPU | 12.750 s | 14.604 s |
| Worker peak RSS | 63.21 MiB | 63.37 MiB |

Independent observer polling and broker ACK use different observation points, so report p95 can lag the ACK even though the database commit preceded the ACK. In the final worker-link and capacity fault, the priority ACK was **1.910 s** and independent durable denial **1.923 s** from intake, with the ordinary row still unsent. Two exact-pinned independent runs on the earlier A implementation observed denial during a held ordinary backlog **1.770 s** and **1.743 s** after requesting broker restart. The before-intake SIGKILL case still took **30.383 s** to report denial. In the after-commit SIGKILL case, the independent observer reported in **55 ms** and broker ACK followed at **30.476 s**. Those individual cases leave the all-agent five-second reporting objective unmet.

The retained final 12 independent route observations with ACK unavailable measured **50.983 / 56.492 / 58.401 ms** p50/p95/p99 from direct agent receipt to quarantine evidence. Each trial checked all nine paths twice. This bypassed broker and coordinator transit. The A source handoff contains an earlier fixture timing; the values here use the final retained raw report. [A method and controls](phase4e-withdrawal.md) · [Matched transport trials](../benchmarks/phase4e/mesh-live.json) · [Partition run](../benchmarks/phase4e/partition.json) · [Final fixture sample](../benchmarks/phase4e/fixture.json)

C measured warm p95 full appraisal of **47.00 / 150.44 / 491.03 ms** at 4/32/128 records, 12 trials per size. Separate publisher lookup was **24.26 / 76.97 / 246.86 ms**. Fresh status passed 12/12 at each size with three available witnesses and denied 12/12 at each size with two. Aggregate warm service RSS at 128 records was **777 MiB** across nine local processes, with shared pages potentially counted multiple times. These separately measured status observations have no native actuator or cross-host timing. [Trust method](phase4e-trust.md#measurements) · [Raw Trust samples](../benchmarks/phase4e-trust.json)

B measured p95 **104.83 ms** for ownership transfer, **31.37 ms** for its two-writer barrier and **13.64 ms** for a new session in the disposable authenticated lab. Its one controlled Docker disconnect and reattach completed retired-broker denial, both durable writer fences and one fresh approved successor write in **3.315 s**. There were zero stale writes. Distinct containers and per-service credential directories exercised actual mTLS and separate writer transactions. They shared the host, VM and temporary lab CA. This is no measurement of native JetStream generation-bound acknowledgements or distributed protection. [Identity method](phase4e-identity.md) · [Raw identity results](../benchmarks/phase4e-identity.json)

A's extra matched run retained the same first-to-ACK ordering effect and reported the priority withdrawal at **2.396 s**, with the legacy worker again acknowledging all 1,000 findings first. The fresh before-intake SIGKILL denial report took **30.366 s**. The after-audit observer reported in **55 ms** while the ACK took **30.467 s**. Independent D pre-intake runs against A and the integrated source observed **30.434 / 30.479 s** before durable denial readback, respectively. D's integrated agent-only broker partition had no audit or ACK during the isolated interval. After rejoin the external observer saw the durable denial in **1.964 s** and the confirmed broker ACK in **1.968 s**. These are local fault observations and do not certify a protected route or an all-agent service bound. [A repeat traces](../benchmarks/phase4e/safety-boundary-review-live.json)

## Withdrawal-v2 shadow cost

For C's paired local shadow comparison at `f7053de6f059535e631cbca9544cd2ee57b2ed48`, 12 warm appraisals per profile used separate private Unix-socket services. Verified checkpoint coverage stays at 3 of 4. V2 also waits for four nonce-bound withdrawal views.

| Records | Original p95 full appraisal | V2 p95 full appraisal | V2 minus original | Positive with one withdrawal endpoint offline |
| ---: | ---: | ---: | ---: | --- |
| 4 | 52.83 ms | 61.52 ms | +8.69 ms | Original 12/12, v2 0/12 |
| 128 | 464.24 ms | 548.05 ms | +83.81 ms | Original 12/12, v2 0/12 |

With one signed scoped withdrawal receipt held outside the checkpoint, the original profile returned a positive result in both sample sizes and v2 returned revoked. From a new challenge, the single measured v2 responses took 60.59 ms at four records and 468.15 ms at 128 records. These samples are local shadow appraisal observations rather than native enforcement latency. The old failure stays in the record. [Strict shadow methodology](phase4e-withdrawal-status-v2.md) · [Raw v1/v2 comparison](../benchmarks/phase4e-withdrawal-status-v2.json)

A separate final-fix oracle from the C author measured healthy p95 **71.56 / 540.31 ms** at four and 128 records. It observed **0/48 false denials** on expected-positive samples, **24/24 holds** with one withdrawal lane unavailable, and **24/24 pre-inclusion denials** after a matching receipt. D independently passed all six focused expiry regressions and 15 separate timing checks at the fixed source, including exclusivity and backward-clock handling. The new healthy timings come from a separate run and do not establish the cost of the expiry fix itself. [Separate oracle and raw results](phase4e-withdrawal-independent-validation.md) · [D's timing checks](phase4e-adversarial.md)

## Isolated proactive writer costs

B's proactive-watchdog input `79cd10a72aac169047f63fe137988ce881304f25` recorded 18 local trials across two marker writers. Both durable commits preceded the first serving observation. The pre-specified faults were eight anchor losses, four assignment expirations and six orderly retirements. Driver-observed p95 time to both commits was **53.974 ms**, **30.018 ms** and **15.150 ms**, respectively. These sample sizes make p95 a near-tail observation. The fault triggers differ and do not support ranking equivalent designs. D independently repeated the untouched-through-loss observation. The prior native pre-observation failure remains open. Twelve focused B writer tests passed on the author’s exact amended B pin. The final integrated pin passed 18/18 focused B writer and C expiry tests in 174.38 s, including the two shorter deadline regressions. No matched latency or CPU comparison isolates the incremental cost of the final C expiry checks or the B Evidence-bound commit hook. No integrated finding-to-protection or physical multi-host latency result is claimed. [Raw watchdog timings](../benchmarks/phase4e-watchdog.json) · [B commit-hook controls](phase4e-b-evidence-writer-fixture.md)
