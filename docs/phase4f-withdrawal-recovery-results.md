# Phase 4F pre-intake withdrawal recovery diagnosis

This is an isolated, one-host disposable Docker diagnosis on instrumentation commit `613efe36e56609bfe4c62740b2ecdee3ae0aeec4`. The retained independent source pin is `51e5601cdb5f1330828063518d62c342ba8721da`; its two original 30.610/30.710-second traces and the validator's freeze at `2eb2ca27be986f3b55e3f85c2067ae6672d213a5` remain unchanged. No enforcement or authority change was attempted. Native T4/T5 remains authoritative, and distributed enforcement stays disabled.

## Measured stages

The controller and dry-run worker run on the same host and record `perf_counter_ns` samples. Controller milestones and worker stages are comparable only inside this local trial. The diagnostic reports each worker process start, NATS connection, KV claim attempt/busy/success, critical replay/subscription/receipt, SQLite audit and confirmed ACK. It does not subtract remote-host clocks. The existing benchmark records the worker's committed audit time; independent read-only SQLite readback confirms the denial after the run. It does not establish a physical target hold or a separate T4/T5 witness acceptance timestamp.

| Fresh trial | Independent withdrawal submit to durable audit | Restart request to durable audit | Broker start return | KV busy / attempts | KV claim success from restart | First critical wire receipt from restart |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SIGKILL + broker restart 1 | 30,616.800 ms | 30,554.514 ms | 196.228 ms | 30 / 31 | 30,503.600 ms | 30,551.384 ms |
| SIGKILL + broker restart 2 | 30,604.164 ms | 30,539.239 ms | 186.787 ms | 30 / 31 | 30,487.082 ms | 30,535.923 ms |
| SIGKILL + broker restart 3 | 30,613.554 ms | 30,553.404 ms | 186.589 ms | 30 / 31 | 30,498.277 ms | 30,550.186 ms |
| Broker restart, agent alive control | 1,759.519 ms | 1,699.135 ms | 171.996 ms | 0 / 0 | existing lease | 1,700.774 ms |

The one-factor comparison holds the broker restart and queued ordinary workload constant and changes agent SIGKILL. In each killed trial the replacement connected by about 0.39 seconds, then 30 KV `create()` attempts returned busy. The first successful claim was at about 30.5 seconds; the critical receipt and durable denial followed roughly 50 ms later. The alive control reached denial in 1.76 seconds. This localizes the dominant delay to waiting for the retained 30-second FILE KV lease to expire after SIGKILL. It does not establish a safe way to shorten that lease or bypass ownership. The broker's `UnexpectedEOF` during intentional stop was observed in each run; each trial otherwise exited zero and passed its ordering, audit, outbox-isolation and ACK assertions.

The frozen closure denominator is **one enrolled dry-run agent × two admitted withdrawals × three fresh SIGKILL trials = six targeted agent-withdrawal pairs**. Every pair eventually had one durable denial and confirmed ACK; all six exceeded 5,000 ms from submission. The withdrawals were durably committed in the coordinator journal before the broker restart request, so the approximately 30.5-second restart-to-denial interval is also a conservative lower bound on acceptance-to-denial even though an independent T4 witness timestamp was not measured. The five-second all-agent reporting gate remains **OPEN / FAILED**. The healthy broker-restart control does not cancel the failed crash cases. p50/p95/p99 across three independent-withdrawal submit-to-audit measurements are 30,613.554 / 30,616.475 / 30,616.735 ms by linear interpolation; these describe this tiny sample, not fleet performance. Physical protection latency, CPU/RSS and multi-host coverage were not measured by this diagnostic.

## Negative controls and authority decision

Focused tests on the diagnostic commit: `22 passed, 1 skipped` in `tests/test_phase4e_withdrawal.py`, `tests/test_phase2c_hardening.py` and `tests/test_phase4a_distributed.py`. The skip is the existing optional live test. Existing disposable live C05 lost-ACK/after-audit death and agent partition/rejoin controls: `2 passed, 2 deselected` in 47.79 seconds; see the retained JUnit. The first unprivileged test attempt reported two socket permission failures; the same suite passed when authorized local loopback sockets were available. No full regression, physical multi-host or protected-writer validation was run on this branch.

`LocalAgent.evaluate_revocation()` checks publisher trust, signature, scope, replay and local SQLite denial, but that dry-run Mesh path does not establish native T4/T5 withdrawal inclusion/status or a target-side owner-generation transaction. A preclaim call could write the audit while the old session's lease remains active, and this repository lacks a reviewed, complete cross-broker ACK/cursor and target fencing barrier for such a takeover. Therefore this branch does **not** add preclaim intake, decrease the lease TTL, force-delete a KV key, or grant write authority from a Mesh ACK, journal cursor or signed claim alone. A future deny-only preclaim design would need an independently authenticated T4/T5 cut, explicit denial precedence, durable same-target hold semantics, local approval and a reviewed rule for a concurrent incumbent. It must remain separate from positive write authority and defer ACK/cursor until the owner generation is proven current. The original five-second failure remains a release blocker.

## Raw evidence and reproduction

- `benchmarks/phase4f-withdrawal-recovery/sigkill-restart-1.json` SHA-256 `fbb13cb3fef546f6e6a31bbdd4b1df436face6a56cb866bc867442c0bcce3894`
- `benchmarks/phase4f-withdrawal-recovery/sigkill-restart-2.json` SHA-256 `172c1effa3935cece06a082829b73c5ffa26d1249ed77bb03d5d5a82594f6487`
- `benchmarks/phase4f-withdrawal-recovery/sigkill-restart-3.json` SHA-256 `7b169af7589df3171d4a5236847964bff97e47dfd9f8fc654a13e46ba09fae1b`
- `benchmarks/phase4f-withdrawal-recovery/broker-restart-no-kill.json` SHA-256 `db348df0d224c56c0e1fb060fd4067b5e1592ed260b735c60953ffd43e873ad5`
- `benchmarks/phase4f-withdrawal-recovery/c05-live.xml` SHA-256 `c455c8df5516e365e19d40980180480d45e4f81c12cac74d6aa198abac0f898a`

From this worktree with already cached Docker images and an authorized local Docker socket:

```sh
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase4e_withdrawal_recovery_check.py . --authorize-local-lab --kill-agent --priority --output /tmp/aegis-4f-sigkill.json
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase4e_withdrawal_recovery_check.py . --authorize-local-lab --priority --output /tmp/aegis-4f-alive.json
PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q tests/test_phase4e_withdrawal.py tests/test_phase2c_hardening.py tests/test_phase4a_distributed.py
AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_PRIORITY=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q tests/phase4e/test_withdrawal_delivery.py -k C05
```

Next reviewed contract decision: establish whether an independently verified, deny-only withdrawal can be committed before broker lease transfer while a concurrent incumbent remains fenced from positive target writes. Until proven with native T4/T5 and exact protected-writer tests, retain the current 30-second owner wait, preserve restrictive local quarantine, and keep Phase 4F native release and distributed enforcement **NO-GO**.
