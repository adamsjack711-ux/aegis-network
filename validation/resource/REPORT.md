# Installed Linux alpha resource and privacy children

**Status:** local owner observation on exact candidate `fc4a17bc6f9f0c289a645c4fb7006c999ba90e99`; independent final-pin release appraisal pending. This lane ran the frozen **17 children per cell × four cells = 68** on the installed `aegis` console. It did not change product source or shared contracts.

## Input binding and isolation

Before any install, `run.py` checked `supply-prep/install-review.json` against independent archive review `ad830ada4bb13e45b9f192bc54c165281e8d9b50`, source `fc4a17b`, manifest SHA-256 `39653937e83dd3d53a4becf9009c9a87234dddd7cf07bfb263451ae5cfed3784`, and final provenance SHA-256 `076619b22cb864a405eb073828bc57f317772340c3e5f18f70d4c4cc2b19b49c`. The same script checked both prebuilt wheels at SHA-256 `28943894bfe543338a353a538fac3a26e9fd552df730e4cb83921953503727e5`. Every pip `--report` archive was checked against the reviewed wheelhouse manifest; no unpinned archive was accepted.

| Cell | Cached image ID | 512 MiB | Hard 256 MiB |
| --- | --- | ---: | ---: |
| Debian 13 / Python 3.12 | `sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e` | 14/14 | 3/3 |
| Debian 13 / Python 3.13 | `sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90` | 14/14 | 3/3 |
| Ubuntu 24.04 / Python 3.12 | `sha256:c955040430a4cd8bee1b84aa6a038d6cf0fca28644b7e71f3f17280a84f358ec` | 14/14 | 3/3 |
| Ubuntu 24.04 / Python 3.13 | `sha256:f28569db398ff4d8d9edbe4887411861566a6c5f573d40a9ae559785e0e2dc86` | 14/14 | 3/3 |

All images were inspected locally by ID before execution. Docker used `--pull=never --network=none --read-only --user=65534:65534 --cap-drop=ALL --security-opt=no-new-privileges --cpus=1 --memory=512m/256m --memory-swap=same --pids-limit=64`. `/tmp` was noexec; only the disposable installed venv had an executable tmpfs. Wheelhouse and fixture input were read-only. The explicit `/results` sink was writable for raw test evidence. The cgroup readback in every raw `summary.json` showed the requested `memory.max`, `memory.swap.max=0`, `cpu.max=100000 100000`, and `pids.max=64`; each child recorded `oom_kill` delta zero. No source checkout was mounted and no package index or image registry was used.

This resource harness used `PYTHONDONTWRITEBYTECODE=1` to avoid installer cache effects in the measured child process. Its tree comparison proves zero unrequested writes **under that controlled setting** on `/tmp` (excluding the fixed venv), `/var/lib/dpkg`, and `/dev/shm`, not default installed-console write behavior. The separate console/tracer lane owns default-interpreter attempted-effect appraisal. `--network=none` blocks connections; this resource lane did not independently classify syscall attempts.

## Frozen children and measured results

Per cell: three fresh child processes each at 100, 10,000, and 100,000 dpkg rows under 512 MiB; three exit-2 negatives (malformed local feed, oversized local feed, duplicate inventory); three fresh 100,000-row controls under a separate hard 256 MiB container; one slow reader; and one closed stdout consumer. All output came from the installed `/tmp/venv/bin/aegis`, never `PYTHONPATH` source execution. The host verifier independently rehashed retained compressed stdout and checked every package name, exact version, architecture, distribution PURL, and source by position.

| Measure | Observed |
| --- | ---: |
| Frozen children | 68 planned, 68 attempted, **68 passed**, 0 failed/skipped |
| Exact package identities rechecked from raw output | **2,921,200** |
| Ordinary + hard 100,000-row children | 24/24 complete, all exact |
| Hard-256 children | 12/12 complete, zero OOM |
| Maximum 100,000-row wall / child CPU | **2.229252 s / 1.54696 s** (limits 5 s each) |
| Maximum conservative `wait4` child RSS | **161.562 MiB** (limit 256 MiB) |
| Maximum 100,000-row JSON | **43,889,275 bytes** (limit 64 MiB) |
| Malformed/oversized/duplicate controls | 12/12 exit 2, unknown or incomplete, ≤2 s, ≤128 MiB, bounded output, no traceback |
| Slow reader | 4/4 complete and exact |
| Closed stdout | 4/4 bounded exit 2, no traceback; four separate correction trials measured **4,096 consumed bytes each** |

The `wait4` RSS statistic includes a conservative fork high-water effect from the Python harness. The first diagnostic ordering ran malformed controls after parsing the 100,000-row output; those three controls reported **151.961 MiB** and failed the frozen 128 MiB limit despite small inputs. The exact first raw run is retained under `results/debian-13-py312/first-run-512m/` at **11/14**, and a 14/14 diagnostic second run with the wrong negative strata is retained under `second-run-512m/`. The scored harness put the three frozen negative strata first, before large JSON parsing, preserving the original 128 MiB ceiling. Do not relabel either earlier result as a pass. The first corrected 14/14 rehearsal is also retained under `first-corrected-512m/`.

The first scored closed-stdout trials measured zero *output-file* bytes because the harness discarded the 4,096 bytes it read before closing the pipe. The repeated `512m-closed-correction/` arms retained those exact 4,096 bytes and their SHA-256, with all four passing. The original scored trials and results remain unchanged. No limit was relaxed.

## Raw evidence and reproduction

Run from this worktree after confirming the reviewed input supply:

```text
python3 validation/resource/run.py
python3 validation/resource/verify_results.py
```

The runner refuses to overwrite existing raw output. `results/overall.json` records every Docker command, cell, installed archive list, child outcome and measurement. `results/<cell>/<512m|256m>/` retains per-child JSON, compressed raw stdout, stderr, pip report and cgroup readback. `results/verification.json` records the second-pass raw SHA and identity checks. The closed correction and prior failed trials are retained in separately named directories. The validator should independently inspect exact harness files, cgroup behavior and the candidate installed artifact before treating this as release evidence.

**Release scope:** this passes the resource denominator locally. It does not prove default-interpreter zero attempted writes/network, grant custody, every 84-case console outcome, or production safety. CLI alpha release and distributed autonomous enforcement remain **NO-GO** pending independent full acceptance.
