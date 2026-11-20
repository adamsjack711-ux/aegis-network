# Phase 4F-B: retained KV lease recovery measurements

Worktree `.worktrees/phase4f-kv-recovery`, baseline `3bfd2abea430bc8036105ce85adfdc78706d367d`. The ownership/fencing proposal was committed separately at `bb1db07cf5460ce71c5a1653d89166efc33caa36` for Main Astra review. Product lease, ownership, target, ACK/cursor, and native T4/T5 behavior was not changed. Original Phase 4E/4F failing tests and traces remain unchanged.

## Trial roster and scoring rule

Each invocation created fresh Docker volumes, PostgreSQL and NATS state, keys, one enrolled dry-run agent, one independent revoker withdrawal and one mixed publisher-sequence withdrawal. Twenty-four ordinary findings plus the mixed publisher's earlier and later findings were queued while NATS was down. The replacement worker used the same stable agent UUID and audit path after pre-intake SIGKILL. All five crash trials restored broker connectivity, and all ten agent-withdrawal pairs were eligible; zero were censored or omitted. The agent-alive broker-restart run is a separate healthy control. The ordinary stream was held at capacity until both critical withdrawals were ACKed and exact SQLite denials existed; then its backlog drained. The eligible denominator is **1 agent × 2 withdrawals × 5 fresh crash trials = 10 pairs**.

The five-second origin is signed withdrawal HTTP submission start. In the first three trials, the worker's durable SQLite commit report alone is already later than five seconds; final independent read-only SQLite state confirms both exact denials, so a later read-only observation cannot make them pass. The two later trials also poll the SQLite file through an independent read-only connection every approximately 25 ms. Those first-present times are conservative upper observations of the committed denial. Broker ACKs and cursors are reported separately and never score a pass. The scorer returns exit 1 for the failed crash gate.

| Trial | Enrolled eligible agent | Withdrawal ID / type | Submit → worker durable commit ms | Submit → read-only denial upper ms | Submit → broker ACK ms | Gate |
| --- | --- | --- | ---: | ---: | ---: | --- |
| S1 | `9512efcf-e02b-42dc-bfad-d0a5937c621d` | `767bfc00-5ced-4cb4-88b9-6f9cee5e859d` independent | 29,662.350 | final readback only | 29,664.139 | FAIL |
| S1 | `9512efcf-e02b-42dc-bfad-d0a5937c621d` | `26e4e69e-b075-44ac-84b1-1bf0f779379a` mixed sequence | 29,649.319 | final readback only | 29,650.799 | FAIL |
| S2 | `33fcc52e-f4fe-45ac-a76f-4b17e631edb6` | `12329a3c-b54f-4ea2-bcc9-c339076f5d41` independent | 29,615.833 | final readback only | 29,617.567 | FAIL |
| S2 | `33fcc52e-f4fe-45ac-a76f-4b17e631edb6` | `ec437c08-6d61-45d4-a7dc-efb7c5973344` mixed sequence | 29,602.089 | final readback only | 29,605.751 | FAIL |
| S3 | `1f062a18-69f8-4455-86d2-c366dce73f52` | `28855728-c272-4f6e-9046-be9fa174b6cc` independent | 29,647.879 | final readback only | 29,649.386 | FAIL |
| S3 | `1f062a18-69f8-4455-86d2-c366dce73f52` | `ef36a012-3087-4e6d-a85f-ede78e13c31a` mixed sequence | 29,633.551 | final readback only | 29,634.945 | FAIL |
| S4 | `bd36d46d-0f23-40b2-98af-1f7ce701ba8b` | `bb6b1702-9bfd-4ded-bd66-e2f17603b384` independent | 29,610.243 | 29,629.508 | 29,611.813 | FAIL |
| S4 | `bd36d46d-0f23-40b2-98af-1f7ce701ba8b` | `f3573e16-ceea-49db-a3d0-04ed28d04085` mixed sequence | 29,596.914 | 29,612.191 | 29,598.268 | FAIL |
| S5 | `789f5772-01be-4a92-87f0-441dc0b2eea0` | `b60bb094-2318-4f1d-af71-bca4dffc8546` independent | 30,623.497 | 30,634.960 | 30,624.946 | FAIL |
| S5 | `789f5772-01be-4a92-87f0-441dc0b2eea0` | `b5c66172-ae6a-4d97-ba14-4b8d1d8b2dae` mixed sequence | 30,611.753 | 30,619.245 | 30,613.063 | FAIL |
| Alive control | `dbb783aa-90ed-4756-9078-51551e16c917` | `913f2cb1-ea3e-489c-93d8-e303966cfeb3` independent | 1,372.105 | 1,388.955 | 1,382.812 | PASS |
| Alive control | `dbb783aa-90ed-4756-9078-51551e16c917` | `827c3984-3fd6-435c-a889-0f8c62723071` mixed sequence | 1,358.783 | 1,372.962 | 1,389.312 | PASS |

Every crash trial failed, including each required withdrawal type. The all-agent maximum observed read-only upper bound in the timed crash runs was 30,634.960 ms. These are one-agent samples; no fleet percentile or multi-host conclusion follows.

## Distinct event timing in the fully instrumented S5 fault

All relative numbers below use the controller and child processes' `perf_counter_ns` on the same physical host, with broker-restart request at 0 ms. They must not be subtracted from remote or container wall clocks. The two signed withdrawals began HTTP submission at −63.072 and −47.357 ms. PostgreSQL journal positions 28 and 29 and their outbox rows were present before the HTTP 202 responses at −47.778 and −27.847 ms; those responses bound durable Mesh intake, but are not independent T4/T5 witness receipts. The broker stream later recorded critical sequences 1 and 2 with UTC publication timestamps `2026-11-20T04:51:48.095811+00:00` and `2026-11-20T04:51:48.121973+00:00`. These wall timestamps are retained as publication evidence, not mixed into the monotonic latency calculation.

The controller observed SIGKILL reaping 3.916 ms after signaling, before restart request. NATS `start` returned at 189.609 ms. The replacement connected at 398.277 ms but saw 30 busy KV create attempts against the retained lease, revision 7. It acquired revision 8 at 30,506.148 ms. Critical wire receipt followed at 30,557.631 ms. The worker reported committed exact local denials at 30,560.462 and 30,564.396 ms. Its confirmed broker ACKs followed at 30,561.874 and 30,565.706 ms. The critical journal replay cursor committed 0→28 at 30,569.603 ms and 28→29 at 30,571.837 ms; this cursor is a separate local progress record, not the denial or a witness receipt. Independent read-only polling last saw both denials absent at 30,545.748 ms and first saw both present at 30,571.888 ms. Worker reporting therefore precedes read-only observation, while ACK can precede replay-cursor advancement. The final read-only state contains both exact tombstones; all 28 queued logical envelopes eventually received broker ACKs, and 26 ordinary rows remained pending when the two critical ACKs were checked.

The dominant 30-second span is between replacement broker connection and retained KV claim success. Broker restart, critical receipt, local commit, ACK, and cursor progression are individually far shorter in this run. This corroborates the retained 30.6-second root-cause diagnosis: SIGKILL leaves a 30-second FILE KV identity lease, and `agent_runtime.run()` gates both critical wire and replay on its expiry. The lease delay is measured; safe early transfer is not established.

## Regression and limits

The new scorer tests require exact final denial and a timed independent readback for a passing pair; an ACK or a worker report alone cannot pass. The focused unit regression completed **27 passed, 1 existing opt-in skip**, including the new oracle tests and existing Phase 4E withdrawal, Phase 2C lease/replay and Phase 4A delivery checks. The retained live C05 lost-ACK/after-audit death and agent partition/rejoin controls completed **2 passed, 2 deselected** in 47.71 s. The initial sandbox unit run had two socket permission failures in existing loopback/Unix socket tests; the authorized rerun passed. The disposable broker stop produced the expected NATS `UnexpectedEOF` log in each trial. The original failing fixtures and tests were neither removed nor rewritten.

These trials exercise a one-host dry-run Mesh audit, not an independently administered T4/T5 witness or physical protected target. Native target-side durable denial, route state, external custody, multi-host split brain, CPU/RSS under recovery and positive-write safety are **unobserved**, and broker ACK does not fill those gaps. No ownership/fencing contract implementation, lease shortening, forced KV deletion, preclaim write, native promotion, merge or real enforcement was performed. Main Astra review of [the contract proposal](phase4f-ownership-fencing-proposal.md) is required before any such change. The five-second withdrawal recovery gate remains **FAILED / NO-GO**.

## Raw artifacts and reproduction

Raw trials: `benchmarks/phase4f-kv-recovery-sigkill-{1,2,3}.json`, `benchmarks/phase4f-kv-recovery-instrumented-sigkill.json`, `benchmarks/phase4f-kv-recovery-cursor-sigkill.json`, `benchmarks/phase4f-kv-recovery-alive-control.json`. Per-pair score: `benchmarks/phase4f-kv-recovery-score.json`; live C05 JUnit: `benchmarks/phase4f-kv-recovery-c05.xml`; SHA-256 manifest: `benchmarks/phase4f-kv-recovery-sha256.json`. Each raw JSON includes the exact source HEAD, instrumentation hashes, Docker image IDs, event IDs, broker order, journal/outbox order and worker stage trace. Reproduce from this worktree with cached local Docker images and authorized local socket access:

```sh
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase4e_withdrawal_recovery_check.py . --authorize-local-lab --kill-agent --priority --ordinary-count 24 --output /tmp/phase4f-kv-recovery.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q tests/test_phase4f_kv_recovery_oracle.py tests/test_phase4e_withdrawal.py tests/test_phase2c_hardening.py tests/test_phase4a_distributed.py
```
