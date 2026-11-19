# Phase 4D benchmarks

## Scope and method

Three sequential paired runs compare the pinned Phase 4A control `bc1b52f66494c0f49ca085eb494bf534212cfba0` with the integrated legacy path `8edcfa5077f45faa0cb98bcc2f357476c8508ed3`. Run order was control/candidate, candidate/control, control/candidate. Each run used a fresh loopback PostgreSQL and JetStream environment, 10 agent processes, two coordinator processes, five steady and 20 burst findings, and two withdrawals. Each arm also ran two separate local protection fixtures per trial. Raw reports pin the OS, CPU count, dependencies, container image IDs and harness hashes. The host was macOS arm64, 10 logical CPUs, Python 3.15.2. This is a one-host experiment. Trust runs in a separate synthetic lane, so the paired runs measure compatibility and prior delivery behavior. [Raw paired runs](../benchmarks/phase4d/)

Driver, coordinator and local agents share a host monotonic clock. The harness measures submit to first durable audit and submit to broker-confirmed ACK for each logical event/agent pair. It also records request, lease, local audit and ACK round-trip stages. Protection takes each fixture's verified-finding timestamp through independent healthy marker and benign route readback. CPU and peak RSS are process measurements at exit. Broker CPU, storage, pending and memory are sampled. Timing precision exceeds the number of significant digits supported by the protection sample sizes.

## Paired live delivery and local protection

Each cell is the median across the three per-run percentile estimates, written as p50 / p95 / p99 in milliseconds. Counts are per arm across all three repetitions. Protection has two observations per repetition, so its tails describe the observations rather than a fleet tail estimate.

| Outcome | Observations per arm | Phase 4A control | Integrated candidate |
| --- | ---: | ---: | ---: |
| Steady finding to audit | 150 | 34.963 / 39.823 / 40.003 | 35.137 / 39.388 / 39.945 |
| Burst finding to audit | 600 | 139.227 / 200.848 / 214.326 | 148.197 / 214.750 / 218.981 |
| Withdrawal to audit | 60 | 33.678 / 34.189 / 34.208 | 35.069 / 36.290 / 36.332 |
| Burst finding to confirmed ACK | 600 | 141.064 / 202.767 / 215.756 | 150.018 / 216.515 / 220.639 |
| Verified finding to confirmed local protection | 6 | 361.324 / 366.025 / 366.231 | 369.699 / 382.973 / 384.153 |

Each arm delivered **810/810** expected decisions and broker acknowledgements, with no duplicate logical decisions, missed withdrawals or incorrect readback decisions. Both protected **6/6** eligible lab rollouts with no marker escapes. Median burst throughput was **604.35** control and **546.14** candidate confirmed decisions/s (ranges 570.60–684.46 and 360.60–597.83). Burst audit p95 ranged from 173.455 to 218.861 ms in control and 197.470 to 344.135 ms in candidate. The run-to-run spread and the unchanged delivery harness preclude attributing that difference to any Trust mechanism. Median total agent CPU was **3.556 / 3.660 s** control/candidate. Median per-run typical agent peak RSS was **61.61 / 62.16 MiB**, and combined coordinator CPU **1.382 / 1.416 s**. Each trial had zero outstanding pending deliveries at burst drain.

The historical Phase 3C fixture recorded protection p95 of **512.200 / 532.374 / 602.859 ms** with 3/10/100 logical agents and **20/20** eligible rollouts per scale. This topology and number of rollouts differ from the current fixture. Historical Phase 4A ran up to 300 processes on one host in two successful 8,100-decision runs, with burst decision p95 4.23–5.57 s. Phase 4D reran the 10-process control. There is no fleet throughput or protection latency result with authoritative Trust. [Phase 3C results](../benchmarks/phase3c-pipeline.json) · [Phase 4A results](phase4a-distributed.md)

## Controlled delivery faults

One candidate trial with a single coordinator and 10 agents used the historical Phase 4A fault profile and separate protection observations. It observed **310/310** durable logical decisions, **309/309** expected broker ACKs and zero duplicate logical decisions. One expected journal-only repair had no broker ACK. Ten repeat broker acknowledgements had no additional logical decision. The deliberately killed holder exceeded the 5 s withdrawal report budget and regained a claim in **30.304 s**, with confirmed ACK at **30.415 s**. Restarting the broker gave **2.227 s** from restart probe to all ACKs. Journal repair took **281 ms** after resume. Capacity-backpressure audit p95 was **933 ms**. Protection confirmation was **5/5**, with p50/p95/p99 **381.177 / 428.977 / 436.099 ms** and zero marker escapes. Phase 4A's historical fault trial had the same coverage, one reporting-budget crossing, and protection p95 **381.70 ms**. This candidate run provides no witness outage latency or replicated coordinator failover measurement. [Raw candidate fault run](../benchmarks/phase4d/candidate-faults.json.gz)

## Trust overhead in the synthetic lane

Full-prefix prototype, one process, fixed 3-of-4 signer cohort, local stores and synthetic signed records. Each size used 20 observed runs after three warmups. Rows time coverage, status appraisal, reconciliation and the local synthetic target commit together. CPU is process CPU over the 20 observations. RSS is cumulative process peak. Distribution latency, independent operator custody and real writer checks are outside these figures. With 20 observations, p99 is close to the maximum.

| History records | p50 / p95 / p99 (ms) | Total CPU (s) | Process peak RSS (MiB) |
| ---: | ---: | ---: | ---: |
| 3 | 24.478 / 25.533 / 25.696 | 0.483 | 54.73 |
| 32 | 155.540 / 157.711 / 157.922 | 3.089 | 55.66 |
| 128 | 581.491 / 590.675 / 593.724 | 11.604 | 58.02 |

At 128 records coverage p95 was **350.697 ms**, status **115.370 ms**, reconciliation **120.832 ms**, and commit **3.712 ms**. The original prototype p95 was **25.019 / 154.959 / 581.551 ms** at these sizes. In 20 modeled withdrawal trials, durable admission was **5.060 / 5.243 / 5.389 ms** p50/p95/p99. Reconciliation and write denial after local receipt were **35.278 / 36.439 / 36.846 ms**, with **20/20** denials. The driver advances the seal using a synthetic clock. This is local receipt-to-denial time, excluding the real seal window, wire delivery, witness recovery and scheduler contention. Witness loss/coverage and stale reconnection were exercised as functional cases. [Raw Trust observations](../benchmarks/phase4d/trust-local.json)

## Exact Evidence CPU control

Five paired cold trials per workload, 100 decisions per arm in each pair, using the existing two-verifier synthetic worker and alternating arm order. The three-key corpus used 200 verifier worker attempts independently and six with reuse per pair. Median repeated/shared CPU ratio was **10.9334×** (10.7460–11.4024×). With 100 distinct keys both arms needed 200 worker attempts and the ratio was **1.0033×** (0.9954–1.0206×). Outcomes matched for each workload. These compare with Phase 3C's **11.1485×** and **1.0053×** on the corresponding workloads. Phase 4B exact sharing reported **17.19×** for clustered and **3.49×** for heterogeneous 1,000-deployment workloads, with different corpus and worker/ledger accounting. Independent live status, witness CPU, and broker transport are outside the exact Evidence ratio. [Raw Phase 4D CPU pairs](../benchmarks/phase4d/evidence-exact.json) · [Phase 3C raw CPU pairs](../benchmarks/phase3c-verification-cpu.json) · [Phase 4B report](phase4b-evidence-portability.md)

## Reproduction

Use the pinned checkouts, installed project test dependencies, local Docker, and a private temporary directory with a fresh workspace per invocation. Run the first command on each arm three times in the paired order above. Run the second command once on the integrated legacy pin. The artifact filenames identify the arm and run. The last two commands use this integration branch's benchmark source. All commands are for disposable loopback fixtures.

```sh
PYTHONPATH=src python scripts/phase4a_bench.py --authorize-local-lab --agents 10 \
  --coordinators 2 --steady 5 --burst 5 --protection 2 --directory /tmp/aegis-4d-lab \
  --output /tmp/replace-with-arm-and-run.json.gz
PYTHONPATH=src python scripts/phase4a_bench.py --authorize-local-lab --agents 10 \
  --coordinators 1 --steady 5 --burst 5 --faults --protection 5 --directory /tmp/aegis-4d-lab \
  --output /tmp/candidate-faults.json.gz
PYTHONPATH=src python tests/trust_lab/benchmark.py --events 3 32 128 --repeats 20 \
  --warmup 3 --withdrawal-samples 20 > /tmp/trust-local.json
PYTHONPATH=src python scripts/benchmark_phase3a_evidence.py --deployments 100 \
  --scenarios cold distinct --repetitions 5 --output /tmp/evidence-exact.json
```

## Native Evidence status prototype

The T5 handoff reports 100 warmed samples per size under the same local worker, two status stores and one relying-party process. The report uses nearest-rank p95. The p99 values below use linear interpolation on its raw samples. Neither path includes distribution or target effects.

| Warm assessment | p50 / p95 / p99 (ms) |
| --- | ---: |
| Legacy, three records | 0.807 / 0.952 / 1.018 |
| Independent, three records | 2.68 / 3.21 / 3.442 |
| Independent, 32 records | 10.31 / 10.74 / 11.349 |
| Independent, 128 records | 35.37 / 36.37 / 36.928 |
| Independent, 256 records | 67.36 / 70.84 / 88.484 |

The 20 paired cold trials measured p95 **69.05 ms** for legacy two-worker verification and **75.57 ms** for two workers plus independent status. Over 20 fault trials, first witness intake through divergent denial was **3.481 ms p95**. From second witness intake to corroborated revoked status it was **4.972 ms p95**. Warm records include distinct role keys, but transport, actual custody separation and writer scheduling are outside these measurements. [T5 report and reproduction](phase4d-t5-evidence-status.md#measurements) · [Raw T5 observations](../benchmarks/phase4d-t5-evidence.json)

## Paired native Trust fixture overhead

Twelve alternating, fresh pairs run the same finding scope, material pins and three-replica fixture with legacy approval and with the combined Trust gate. Each fixture has fresh IDs and role keys. Each arm uses preprovisioned authorities and an independently confirmed fixed route restriction. Timing starts before plan preparation and ends after confirmation. It includes journal and Evidence rechecks, approvals, target writes and probes. It excludes initial verifier execution, provisioning, finding distribution and waiting for the synthetic seal. The legacy side uses mocked replay and the Trust side uses in-process witness and status stores. Both use actual loopback HTTP for effectiveness. These are different clocks and denominators from the 10-agent delivery report above.

| Interval | Legacy p50 / p95 / p99 (ms) | Combined Trust p50 / p95 / p99 (ms) |
| --- | ---: | ---: |
| Plan request to confirmation | 133.178 / 137.772 / 139.342 | 180.829 / 185.949 / 186.704 |
| Preparation | 2.201 / 3.548 / 4.352 | 12.630 / 14.112 / 14.226 |
| Preflight | 45.733 / 47.708 / 47.775 | 50.792 / 53.606 / 54.346 |
| Canary | 35.999 / 37.310 / 37.648 | 48.242 / 50.398 / 50.912 |
| Expansion | 7.184 / 7.687 / 7.715 | 18.882 / 20.889 / 21.815 |
| Effectiveness observation and commit | 41.692 / 44.767 / 45.699 | 49.900 / 53.876 / 54.329 |
| Process CPU during timed interval | 67.848 / 71.196 / 71.238 | 118.316 / 122.174 / 122.613 |

Both arms confirmed **12/12**. Candidate p95 was **48.177 ms** slower over the prepared local interval. The driver and both arms shared one process with **96 MiB** cumulative peak RSS, so there is no per-arm memory delta. All timings are empirical isolated-fixture observations with small samples. The Phase 3C end-to-end target and Phase 4A fleet tail remain separate workloads. [Raw native fixture pairs](../benchmarks/phase4d/native-composed.json)

```sh
PYTHONPATH=src python tests/phase4d/benchmark_native.py --pairs 12 > /tmp/native-composed.json
```

## Native witnessed history

T4's three paired trials per size compare the same native signed events in SQLite and in-process archives against the Phase 4A replay harness with HTTP mocked. At **100 / 1,000 / 5,000** total records, witnessed initial replay medians were **79.8 / 757.7 / 3,863.8 ms** and witnessed verified-cache restart **91.8 / 893.8 / 4,512.7 ms**. Legacy initial replay medians were **78.7 / 766.5 / 5,141.0 ms**. At 5,000 total records, the initial 4,000-record catch-up exceeded the one-second protected refresh budget. Witnessed app payload was **10.43 MiB** versus **3.29 MiB** legacy. The results exclude waiting for epoch closure, network costs and deployment resource saturation. Three trials support medians and raw observations. [T4 methodology and reproduction](phase4d-journal-integrity.md#measurements-and-repeatability) · [Raw journal trials](../benchmarks/phase4d-journal.json)
