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
