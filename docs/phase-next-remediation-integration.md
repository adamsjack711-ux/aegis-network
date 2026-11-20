# Phase 4F / 5A / 5B isolated remediation integration

## Scope and exact pins

The clean common parent was `192feacf0c015c1fa37b075228b258d70e565d42`. This candidate is `integration/phase-next-remediation`; master, the original feature branches and all original failure evidence remain intact. The independent oracle was frozen **before** implementation review at `2eb2ca27be986f3b55e3f85c2067ae6672d213a5` and the exact-pin review is `adf5cbac14d634115593222e5555d57329c95293`. [Independent review](phase-next-remediation-candidate-review.md) · [Frozen failures](phase-next-remediation-validation-freeze.md).

| Intake | Independently reviewed source | Integration merge | Accepted scope |
| --- | --- | --- | --- |
| Phase 5A | `71a6f864456457769cfb3f844f0cd47aac3a9d95` | `189571e84cde7c6b800ba471a59bc9181008134c` | In-process, offline read-only fixture research. No authenticated reusable Evidence or model-to-finding adapter. |
| Phase 5B | `a9b0d0e1d45b64ce833343dbfa3dd9f034a20770` | `4bce000869976184c476303febaf05196ac24384` | Offline source-level observation tests. Installable Linux CLI alpha is not cleared. |
| Phase 4F | `2fa7321618fc5e7435b339ffa9368de258198d21` | `7a51695e3ba61514bbc89fe91c5383caad175a21` | Stage instrumentation and diagnostic evidence only. No lease, ownership, ACK/cursor or enforcement behavior change. |

The planning branch `8253cff2d5af646e3c6f30e993e5b628fd9b64b2` and independent validation branch `adf5cba` were imported after the three code intakes. No Git conflict arose. The independent 5B review accepted source-level offline observation but did not verify an installable wheel, so the integration lead withheld its `[project.scripts] aegis` entry point and adjusted the README claim in this candidate. The original 5B feature branch is unchanged. The source-level CLI remains runnable with `python -m aegis.cli` in the isolated development fixture. This scope adjustment is retested at the final pin. The final documentation commit is recorded by `git rev-parse HEAD` on this branch.

## Shared-contract and safety review

`src/aegis/artifact.py`, `src/aegis/core.py`, native T4/T5, the mitigation and protected-writer modules, and the frozen schema authority map have no product diff from `192feac`. SignedFinding 1.0 canonical bytes, exact `InventoryItem(purl, version)` matching, revocation/denial behavior and local policy authority remain unchanged. Phase 5A's private `phase5a-research-v2` result cannot be silently parsed as v1; the model hypothesis is segregated, all prose is unchecked, and the reportable F1 outcome is unknown/needs-evidence. Its unkeyed internal checksum is **not** source authentication. Phase 5B's private v2 output distinguishes signature origin, local-file claim time, exact package match and `independent_status=unknown`; default commands do not persist identity. Phase 4F callbacks record stages without granting preclaim authority or weakening the five-second gate.

Unresolved interface debt: the observation CLI imports the shared publisher-grant loader through `config.py`, which transitively imports dry-run `core.py` types. Independent Python-level guards found no writer, socket, process or privilege call, but the import boundary should be separated before wider CLI distribution. A serialized Phase 5A v2 record with a self-consistent forged unkeyed checksum can parse; cross-process reuse requires independent source reacquisition/revalidation and a separate trust state. Neither private format is an enforcement contract.

## Tests after each integration intake

Full local regression ran on each exact code merge with `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q -p no:cacheprovider`, using the repository virtual environment and authorized local socket fixtures. Original independent failures were retained, not relabeled. JUnit XML is checked in under `benchmarks/phase-next-remediation/`.

| Candidate code merge | Passed | Skipped | Failed/error | Wall time | Raw JUnit SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| After 5A, `189571e` | 344 | 37 | 0 | 134.01 s | `3b44d57db5a497b8fc73eb165d3706b0cf240cdc913e87b33bce58674ddd118c` |
| After 5B, `4bce000` | 353 | 37 | 0 | 130.29 s | `80d54398ee3912c61c467b720528ec658c460765269977eeaaa9046ca1a13af1` |
| After 4F, `7a51695` | 353 | 37 | 0 | 128.48 s | `60639b8fbc5e1d67ecd0d6b379178fca70733c5a2e37f534e6c1c7d637e48a90` |
| Final source-only CLI scope | 353 | 37 | 0 | 133.24 s | `4b35cf1206ef155e6ead9b8ed9f61be57df4d38dc559e4c4f6a3ea4293041426` |

The 37 skips are opt-in live cases in these local suite runs; they are not silently counted as passes. The final integration-only packaging adjustment was tested by the last full-suite row; the independent validator reviewed its narrow scope and found no new source-level authority crossing. The original specialist-branch wheel smoke scripts require the withheld console entry point and are **expected unavailable** in this integration candidate. They were not rerun as passing packaging tests. No production or physical multi-host test was attempted.

## Independent security and performance results

- **5A:** The original seven-case exception-only harness remains 6 pass/1 fail because it demands a thrown exception. Its frozen alternative disposition passes: the F1 invented affected-version/remote-execution point is raw unchecked hypothesis; reportable outcome is unknown. An intermediate v2 pin failed 2/10 reader-integrity challenges; the corrected exact pin passed 12/12 independent challenges and 19/19 owner focused tests. The independent holdout completed 11/12 cases: 9 correct, 2 conservative unknown disagreements, 1 Debian epoch inconclusive, zero false affected. The scripted development corpus remains 12/12 deterministic and 12/12 checked, with **zero demonstrated model advantage**. A real model and billing/compute cost were skipped.
- **5B:** Independent cached Debian source testing found 4/4 default commands with **zero writes** and the explicit-state control writing only `chosen/identity.json`; signed and negative-status challenges passed 11/11, and focused plus adjacent tests passed 28/28. A prior candidate `4ff82d5` failed the macOS explicit-state alias control and remains retained. The owner reports an offline wheel smoke; the independent `uv build --offline` could not complete because `hatchling` was absent from its local cache. Independent wheel install/uninstall, Ubuntu, syscall tracing and a revised-pin resource envelope are **incomplete**. The console entry point is withheld in this integration candidate pending that gate. No performance or packaging release claim follows.
- **4F:** Three owner and one independent fresh SIGKILL-plus-broker-restart trials measured first durable denial at **30,616.800 / 30,604.164 / 30,613.554 / 30,589.201 ms** from withdrawal submission. Two agent-alive broker-restart controls took **1,759.519 / 1,767.656 ms**. Six of six corrected independent stage/denial controls passed, while all four crash trials **failed** the inherited 5,000 ms gate. In the fresh crash trial, broker start returned at 175.931 ms and KV claim succeeded at 30,478.094 ms after 30 busy attempts; critical receipt and SQLite commit followed about 46 and 49 ms later. This localizes delay to the retained identity lease. The first validator stage score used wrong target IDs; both the mistaken score and corrected 6/6 score remain retained. Owner focused tests: 22 pass, 1 optional skip; two live C05 controls pass, two deselected. No safe early-takeover proof, physical target protection latency, CPU/RSS, or multi-host denominator was obtained. **No performance improvement is claimed.**

## Release decisions and next gates

**GO:** continue isolated in-process Phase 5A fixture research, offline Phase 5B source tests, and Phase 4F diagnostics on this candidate. **NO-GO:** authenticated reusable AI Evidence, installable Linux CLI alpha, native 4F release, the five-second all-agent withdrawal gate, distributed autonomous enforcement, production integration and master merge.

Next engineering priorities are (1) define and independently test a native T4/T5-backed deny-only withdrawal path or safely fenced ownership-transfer protocol without using broker ACK/cursor as authority, (2) obtain reproducible offline Linux wheel dependencies plus syscall/resource and Ubuntu evidence for 5B, and (3) give 5A cross-process records authenticated source acquisition or revalidation before publication. Keep the original failures as fixed regression inputs.
