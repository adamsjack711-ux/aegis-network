# Aegis Trust acceptance tests

**Verified 2026-11-19.** The isolated prototype passed 35 unit and adversarial cases. The full run included those cases, 129 Phase 3C tests, and eight Phase 4C tests read from their original worktree. All 172 passed. The inherited Starlette `TestClient` deprecation warning remains. The broader run used only the inherited disposable loopback HTTP and Unix socket fixtures. [Prototype tests](../../tests/trust_lab/test_trust_lab.py) · [Phase 3C test baseline](../phase3c-integration.md#tests-and-fault-observations)

## Reproduce

From the Aegis Trust worktree, use a Python environment with the project's test dependencies. Run the inherited regression and Phase 4C suite in an isolated environment that permits local fixture sockets.

```sh
PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/trust_lab
PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m pytest -q -p no:cacheprovider ../phase4c-adversarial/tests/phase4c
PYTHONPATH=src python tests/trust_lab/benchmark.py --events 3 32 128 --repeats 20 --warmup 3
python -m compileall -q src/aegis/trust_lab tests/trust_lab
git diff --check
```

Each prototype case uses ephemeral Ed25519 keys, separate SQLite witness files, an independently retained SQLite anchor and a controlled clock. Assertions inspect durable target generation, fence, restrictions and audit. The split-view case reads both signed statements from anchor storage. The healthy cases require an actual target transaction, including a healthy write after reconnection and a renewal with a later lease deadline.

## Fault matrix

| Fault | Verified observable result |
| --- | --- |
| Coordinator withholds a quorum-receipted withdrawal | Old view remains eligible only during its signed window. After the cutoff, at most two signatures are available for the omitted view even with a colluder. A full cut applies the withdrawal and leaves the target fence unchanged. |
| Coordinator unavailable or archive omits an index | Three independent witnesses suffice for a complete prefix without coordinator input. A truncated archive under a valid seal fails, then the complete control commits. |
| Witness identity substitution, duplicate signer, or conflicting history | Unknown and duplicate keys fail. Two Byzantine signers produce a split outside the assumed bound. The evaluator shown both cuts preserves the signatures and holds across restart. An honest restarted witness retains pending obligations. Missing signer storage prevents signing. |
| Multiple brokers, stale generation, or target race | An unassigned broker and unenrolled contender fail. Concurrent admin transfers from one expected generation have one winner. A pre-approved old holder cannot commit and the winner can. Two local operations at the same target fence commit at most once. |
| Stale or forged local approval | A signature on the prior challenge and a publisher signature used as local approval both fail. An exact approval commits once and is audited. |
| Evidence expiry, contradiction, or withdrawal | Expired positives fail. The independently receipted withdrawal or eligible contradiction closes the gate even after the denial envelope expires. Two keys from the same organization or a submitter-linked vote cannot form a qualifying positive pair. |
| Evidence status unavailable, mis-scoped, stale, or contradictory | Missing or mismatched signed status blocks the operation. A valid signature on a contradictory status blocks already prepared writes for that exact cut. A healthy later cut can proceed after renewed appraisal and approval. |
| Retirement, compromise, or forged history | A missed withdrawal survives revoker retirement and is reapplied on reconnect. Backdated envelopes and unapproved delegation changes fail. A compromise cutoff leaves an uncertain historical negative on hold. |
| Partition and recovery | Disconnection invalidates a prepared renewal and leaves the existing restriction and lease unchanged. Missing endorsements, stale cuts, a substituted holder and replayed challenge responses hold. A fresh authenticated cut and local approval permit the control renewal. A stalled wall clock alone cannot extend the monotonic deadline. |
| Journal restore | Older snapshots, lost journal bytes, rolled-back ownership, a missing anchor and an interrupted cross-store write all hold. Matching restore still requires new authenticated reconciliation and approval. |

## Local benchmark

macOS 27.0.1 arm64, Python 3.15.2 and cryptography 46.0.7. Each point used 20 measured operations after three warmups in a temporary directory. The timed path includes opening the challenge, three serial witness archive appraisals, signing independent Evidence status, relying-party replay, scripted exact approval, and the target and anchor commits. Loading the initial archive and generating admissions were outside the timers. The clock was controlled and kept within one epoch. Percentiles describe whole individual operations and are independent of the stage percentiles. [Raw run](../../benchmarks/aegis-trust-local.json) · [Benchmark driver](../../tests/trust_lab/benchmark.py)

| Records in prefix | Median | p95 | Max |
| ---: | ---: | ---: | ---: |
| 3 | 24.276 ms | 25.019 ms | 25.360 ms |
| 32 | 153.293 ms | 154.959 ms | 155.109 ms |
| 128 | 577.484 ms | 581.551 ms | 582.519 ms |

Cross-host deadlines, clock error, receipt-to-application latency, human approval, production disk scheduling, and concurrency under load still require measurement. The full-prefix cost motivates bounded proofs and incremental replay before a pilot. The initial one-second simulated epoch establishes a test boundary, with no demonstrated service objective over a real network.
