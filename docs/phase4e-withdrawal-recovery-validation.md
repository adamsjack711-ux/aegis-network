# Phase 4E-A independent withdrawal recovery validation

## Scope and baseline

The original T6 trace queued a scoped withdrawal behind all four ordinary findings. This check independently repeats the control on reviewed Phase 4D commit `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f` with 24 ordinary findings, two additional findings from a publisher enrolled for both roles, and two scoped withdrawals. The synthetic fixtures use one physical host, one broker, one PostgreSQL database, one actual agent process and dry-run policy. The observer queries the local audit through a separate read-only SQLite connection. No fixture actuation is included.

First, both targets receive positive dry-run decisions and confirmed broker acknowledgements. While the broker is down, the PostgreSQL journal commits all 28 new envelopes. One withdrawal comes from an independent issuer. The other follows an earlier finding and precedes a later finding from the mixed-role issuer. After restart, the test checks every durable and broker record, same-publisher finding order, exact tombstones and preservation of each journal position. The SIGKILL arm restarts the same stable agent identity against the same audit. The raw records distinguish elapsed time to the first durable audit from elapsed time to confirmed broker acknowledgement.

| Legacy fault | Ordinary findings preceding the independent withdrawal | Queued events with confirmed ACK | Exact final denials | Restart request to independent withdrawal audit / ACK |
| --- | ---: | ---: | ---: | ---: |
| Broker restart | 24/24 | 28/28 | 2/2 | 1.660 / 1.661 s |
| Broker restart and agent SIGKILL | 24/24 | 28/28 | 2/2 | 29.590 / 29.644 s |

These are individual controlled runs, measured using the monotonic host clock. The crash run took 29.705 s from withdrawal submission to confirmed ACK, above the historical five-second reporting threshold. Both runs recovered the eventual scoped denial. They did not establish a bound on withdrawal propagation or prove a writer reached safe hold. [Restart control](../benchmarks/phase4e-withdrawal/baseline-restart.json) · [SIGKILL control](../benchmarks/phase4e-withdrawal/baseline-sigkill.json)

## Candidate acceptance oracle

The optional priority arm keeps the ordinary stream at its existing storage limit across the restart. It requires both critical acknowledgements and both exact durable denials before lifting that limit, while every queued normal finding is still unsent. After restoration, every ordinary finding must progress and preserve per-publisher order. For the mixed-role issuer the high-sequence early withdrawal may commit its scoped tombstone but may not drive the ordinary high-water mark ahead of the earlier finding. The final SQLite audit must show all normal findings as correctly authenticated with their expected dry-run decisions and no duplicates. The test measures transport latency and recovery and keeps shared broker, database and ownership outages outside the priority isolation claim.

## Reproduction

Run from this validation checkout with the project's Python dependencies, local Docker and cached PostgreSQL and NATS images. The supplied checkout chooses the build under test. Each invocation uses fresh disposable state and removes its loopback services. Use `--kill-agent` for the crash arm. Use `--priority` only on a checkout that implements the opt-in separate withdrawal stream.

```sh
python scripts/phase4e_withdrawal_recovery_check.py ../phase4d \
  --authorize-local-lab --ordinary-count 24 --output /tmp/phase4e-a-baseline.json
python scripts/phase4e_withdrawal_recovery_check.py ../phase4d \
  --authorize-local-lab --ordinary-count 24 --kill-agent --output /tmp/phase4e-a-sigkill.json
python scripts/phase4e_withdrawal_recovery_check.py ../phase4e-withdrawal \
  --authorize-local-lab --ordinary-count 24 --priority --output /tmp/phase4e-a-priority.json
```
