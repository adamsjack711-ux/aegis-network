# VAL-1 independent findings and terminal handoff

Validation branch `test/phase-next-independent-validation`, starting source `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`, freeze commit `2890cf8a17805923a326a1fc5e02d481f9640b08`. The original 262 tracked evidence/oracle files matched their frozen SHA-256 and length manifest, **262/262**. No specialist branch, master, native enforcement setting or production target was modified. Raw VAL-1 outputs and the validator-owned harness are under `benchmarks/phase-next-independent-validation/` and `scripts/val1_*.py`; the new evidence manifest pins their bytes. All local tests used synthetic fixtures or cached, offline containers. A source branch and a separate integrated candidate are not interchangeable.

## Exact source and environment pins

| Scope | Exact clean commit at trial | Observation |
| --- | --- | --- |
| Integrated baseline | `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9` | Clean separate `integration/phase-next-r-astra` worktree before/after full suite. Its `pyproject.toml` has **no** `[project.scripts] aegis`; it is not an installable CLI release candidate. |
| 5B packaged alpha specialist | `1b30cf864b8559e02509c22ed8c5362a141da448` | Clean separate specialist worktree before/after offline build and source-focused suite. This branch diverges from the integrated source and is not intake. |
| 5A repaired research specialist | `ebcc30c9cfcee54c3e103b6fb8cfafb8b5d4e762` | Clean separate specialist worktree before/after independent challenge. No real model or authenticated advisory source. |
| 4F recovery proposal | `cf957b18f4cd4a61361122426c6c5ed3a99e5059` | Clean proposal worktree; HEAD changes documentation only. Retained live diagnostic source is `2fa7321618fc5e7435b339ffa9368de258198d21`. There is no new safe recovery implementation at this pin. |
| Linux fixture | `aegis_phase4_baseline-coordinator:latest` at `sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e` | Cached Debian 13 arm64, Python 3.12.16 with resident Pydantic/cryptography. Disposable UID 65534, read-only root, `--network none`, one CPU, 256 MiB cgroup, no new privileges. Resident dependencies are not a locked independently sourced wheelhouse. |

The cached `python:3.13-slim` image is Debian 13 arm64 at `sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`; it has Python 3.13.18 but no Pydantic. Cached `ubuntu:22.04` is `sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc` and has no Python executable. Neither has a cached syscall tracer. These are recorded prerequisites, not attempted installed-console trials.

## Findings register

| ID / severity | Independent observation and denominator | Release consequence |
| --- | --- | --- |
| VAL1-4F-01 / critical | Rescoring two retained one-host dry-run traces yielded one SIGKILL/broker-restart trial with **2/2** targeted denials at **30,589.201 and 30,576.431 ms**, and one healthy control with **2/2** at 1,767.656 and 1,753.683 ms. The crash trace has 30 busy KV claims. The inherited historical failure pairs and raw files remain preserved. No new 72 fault/18 control all-agent run, 1,000-backlog arm, native target readback or physical multi-host proof exists on the current proposal. | **NO-GO** five-second recovery and distributed enforcement. Diagnostic stage ordering passed 2/2, which does not change the deadline failure. |
| VAL1-5B-01 / high | The exact 5B specialist wheel and sdist built offline twice with `SOURCE_DATE_EPOCH=1735689600`; hashes matched pairwise. Its console entry point exists. A packaged non-root Debian/Python 3.12 run completed **9/9** trials: three each at 100, 10,000 and 100,000 rows. At 100,000 rows, each emitted 100,000 `purl` entries, 39,089,273 output bytes, exit 0, no cgroup OOM and no changes to the declared `/tmp` or dpkg tmpfs trees. Wall was 1,623.585–1,708.764 ms and CPU 1,540.299–1,626.679 ms. The child RSS **upper bound including setup children** was 90.184 MiB. Installation and uninstall exited 0 and removed the console. Initial container setup failures (non-writable dpkg tmpfs, non-executable `/tmp`) and an OOM in the validator's first buffered JSON reader remain raw; the streaming reader resolved the harness error. This is one platform cell of four; it does not prove byte-level JSON validity at 100,000 rows, only the counted entries and identical output hashes. | **NO-GO** installable alpha. Debian 3.13, Ubuntu 3.12/3.13, locked dependency provenance, full default-command matrix and attempted-syscall tracing remain skipped/inconclusive. No cross-cell inference. |
| VAL1-5B-02 / high | The 5B sdist contains **650 entries**, including **329 benchmark**, 95 docs and 52 test paths. Wheel has 71 entries and includes `aegis.agent_runtime`, `aegis.ownership` and the Evidence runner. The exact dependency metadata requires Pydantic and cryptography, but does not lock their versions/hashes. | Review artifact scope and privacy before distribution. This is packaging exposure, not proof of a default CLI authority call. The source import/effect boundary and syscall trace remain open. |
| VAL1-5A-01 / high | Independent V holdout on clean `ebcc30c` had **10/12 exact**, including one conservative `unknown` for a withdrawn case expected `unaffected`, one Debian epoch case inconclusive, and **zero false affected**. A separate visible 36-case fixture had 33/34 completed deterministic decisions correct, two inconclusive, zero false positives, 15 emitted source claims and **0 independently semantically adjudicated** claims. Exact source-byte tamper, arbitrary version quote, source-role/acquisition spoof and unrelated impact were rejected. SignedFinding/Evidence promotion was rejected; 12/12 revised claim-integrity controls passed. The original exception-only script still says **6/7** because it expects a throw instead of the frozen permissible `unknown/needs-evidence` result; it remains raw and is not relabeled. No real model, billed cost or model latency was measured. | **NO-GO** AI research release/accuracy or cost claim. Narrow **GO** for offline read-only fixture evaluation at the exact specialist pin, with zero authority promotion. |
| VAL1-DR-01 / high | The scoped Diagnostic Runner is `aegis.evidence.runner` with fixed `_worker.py` and `_portability_worker.py`. Independent direct worker probes passed **11/11** registered, unknown-operation, malformed, oversized and command-text controls, with no scratch files or stderr. The runner invokes a pinned Python file with list argv, isolated interpreter flags, empty environment and bounded fixture vocabulary. It runs as the caller's OS UID; its Python audit hook is **not** a kernel privilege or syscall boundary. The probe did not trace attempted syscalls or test a separate unprivileged execution identity. | Narrow **GO** for inert fixed fixtures in an authorized lab. **NO-GO** for a privileged/untrusted Diagnostic Runner release or privacy/command-boundary guarantee until an OS-separated, traced runtime and output redaction review pass. |
| VAL1-INT-01 / high | Full regression on clean integrated baseline: **373 passed, 37 skipped, 0 failed/errors** in 140.17 s. Skips include 30 credentialed identity fixtures, four withdrawal-delivery tests and three other opt-in live tests. Validator-focused baseline: 52/52; 5B specialist focused: 10/10. These suites do not combine 5B packaging, 5A repair and 4F recovery at one exact source commit. | **NO-GO** integrated release. No test result here authorizes master merge or distributed enforcement. |

## Independent oracle limits

The CLI's `purl` count and tree snapshot establish complete emitted entry counts and no observed changes in the declared writable mounts for the tested commands. They do not substitute for a parser-level identity comparison, an attempted-syscall trace, or the 12 default plus four opt-in command matrix in each platform cell. The 5B specialist's resident Debian runtime dependencies and Mac-hosted offline build are diagnostic provenance; they are not a fresh four-cell Linux wheelhouse proof. The 4F trace reads one agent's dry-run SQLite denial, not all enrolled agents or native protected target state. The 5A fixtures are scripted/local and cannot establish real-model accuracy, cost, source authenticity or citation truth in live advisories. The Diagnostic Runner challenge directly executed fixed workers; it did not grant or test an OS sandbox.

## Separate GO/NO-GO decisions

| Release scope | Decision |
| --- | --- |
| Linux observation CLI alpha | **NO-GO**; one Debian/Python 3.12 cell passed limited packaged resource/no-write checks, three platform cells and syscall/provenance gates open. |
| AI read-only research release | **NO-GO**; offline fixture evaluation only is permitted at the specialist pin. Real-model and independent source entailment gates open. |
| Five-second native/distributed recovery | **NO-GO**; retained deadline failure, no 72+18 full oracle or target proof on a successor implementation. |
| Diagnostic Runner release | **NO-GO** for privilege/privacy/command-boundary release; fixed inert lab fixture use only. |
| Distributed autonomous enforcement / production | **NO-GO**; physical multi-host identity, witness custody, rollback anchors and integrated exact-pin proof absent. |

## Exact reproduction commands

From `.worktrees/phase-next-independent-validation` with the pinned worktrees still clean, no external network, and cached Docker images:

```sh
python3 scripts/val1_independent.py verify-manifest --output /tmp/val1-manifest-check.json
python3 scripts/val1_independent.py runner-probe --output /tmp/val1-runner.json
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase_next_r_5a_independent.py --candidate ../phase-next-r-5a-astra --pin ebcc30c9cfcee54c3e103b6fb8cfafb8b5d4e762 --v-corpus fixtures/phase-next-ai-holdout-v1.json --output /tmp/val1-5a-independent.json
PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python scripts/phase_next_5a_claim_challenge.py --candidate-root ../phase-next-r-5a-astra --source-pin ebcc30c9cfcee54c3e103b6fb8cfafb8b5d4e762 --output /tmp/val1-5a-claim.json
python3 scripts/phase_next_4f_stage_audit.py --output /tmp/val1-4f-rescore.json benchmarks/phase-next-remediation/4f-sigkill-fault.json benchmarks/phase-next-remediation/4f-broker-control.json
SOURCE_DATE_EPOCH=1735689600 PYTHONDONTWRITEBYTECODE=1 UV_NO_PROGRESS=1 uv build --offline --cache-dir /private/tmp/aegis-phase5b-uv-cache --out-dir /tmp/val1-build-1 ../phase5b-alpha-stabilization
SOURCE_DATE_EPOCH=1735689600 PYTHONDONTWRITEBYTECODE=1 UV_NO_PROGRESS=1 uv build --offline --cache-dir /private/tmp/aegis-phase5b-uv-cache --out-dir /tmp/val1-build-2 ../phase5b-alpha-stabilization
```

The installed-console 100,000-row arm used this exact container shape; change `--rows` to `100` and `10000` for the other sizes, and use a fresh output name for each run. The first read-only root attempt failed because `/var/lib/dpkg` was root-only; the second because the virtual environment tmpfs was mounted without `exec`. Both remain preserved.

```sh
docker run --rm --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --memory 256m --cpus 1 --tmpfs /tmp:rw,exec,nosuid,mode=1777,size=128m --tmpfs /var/lib/dpkg:rw,nosuid,mode=1777,size=32m -v "$PWD/benchmarks/phase-next-independent-validation/wheels:/wheels:ro" -v "$PWD/scripts/val1_cli_linux.py:/probe.py:ro" --entrypoint python aegis_phase4_baseline-coordinator:latest /probe.py --wheel /wheels/aegis_network-0.1.0-py3-none-any.whl --rows 100000 --repetitions 3
```

The full regression ran from the separate clean `integration/phase-next-r-astra` worktree with `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -p no:cacheprovider -q --junitxml=/tmp/val1-full.xml` and authorized localhost fixture sockets. Original stdout/JUnit and all skip reasons are retained in this validation branch. Run `git status --porcelain` in each source worktree before and after every test. Do not replace a recorded failed artifact with a retry.

## Terminal handoff

Keep the frozen plan, validator harnesses, original and new SHA manifests, raw results and this findings register on this branch. Owners can take the explicit open gates into a new integrated candidate. Any future GO requires a new exact clean integrated pin, full negative matrix and independent rerun; the current baseline's 373 passing tests and a specialist's local win are insufficient. No merge to master or distributed enforcement enablement was performed.
