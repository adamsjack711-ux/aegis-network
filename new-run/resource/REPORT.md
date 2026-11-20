# Installed Linux alpha bytecode-launcher resource matrix

**Scope:** frozen 68 installed-console resource/privacy children against source `fa8272b507a9b86168b4dd4d85e75a48d9b1699b`, wheel SHA-256 `d537263a4e15e56dd2ffc940b2ad99c3b4e78486d09b21e52fd69383eb64f50b`. This is a local owner run awaiting independent exact-pin review. No product runtime source or shared contract was edited in this validation worktree.

Main relayed independent START approval after smoke and two byte-identical offline builds. The runner verified both build reports' source pin, wheel hash and sdist hash (`8bf568725cc7f39b291a531b4cbd6018cef171e56a546e2bbb0e1d5f41e45ed2`) before install. It verified the wheel's installed script bytes invoke the venv interpreter with `-B -P`, the original reviewed supply binding to `fc4a17bc6f9f0c289a645c4fb7006c999ba90e99` and independent archive review `ad830ada4bb13e45b9f192bc54c165281e8d9b50`, manifest SHA-256 `39653937e83dd3d53a4becf9009c9a87234dddd7cf07bfb263451ae5cfed3784`, and provenance SHA-256 `076619b22cb864a405eb073828bc57f317772340c3e5f18f70d4c4cc2b19b49c`. Every `pip --report` archive digest was rechecked against the reviewed manifest. No package download or image pull occurred.

| Cell | Exact cached image ID | 512 MiB children | 256 MiB children |
| --- | --- | ---: | ---: |
| Debian 13 / Python 3.12 | `sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e` | 14/14 | 3/3 |
| Debian 13 / Python 3.13 | `sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90` | 14/14 | 3/3 |
| Ubuntu 24.04 / Python 3.12 | `sha256:c955040430a4cd8bee1b84aa6a038d6cf0fca28644b7e71f3f17280a84f358ec` | 14/14 | 3/3 |
| Ubuntu 24.04 / Python 3.13 | `sha256:f28569db398ff4d8d9edbe4887411861566a6c5f573d40a9ae559785e0e2dc86` | 14/14 | 3/3 |

The eight disposable containers ran as UID/GID 65534, `--pull=never --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --cpus=1`, with 512 or hard 256 MiB memory, swap disabled and 64 PID ceiling. Each container's cgroup readback matched its requested memory and CPU limit. `/tmp` was noexec; only the disposable venv mount was executable. Input wheelhouse and fixtures were read-only; `/results` was the explicit raw-output sink. No source checkout was mounted. Each test launched a fresh installed `/tmp/venv/bin/aegis` child. The harness removed `PYTHONPATH` and **did not set `PYTHONDONTWRITEBYTECODE`** for the CLI, so it exercised the new installed launcher's default `-B -P` behavior.

## Results

| Frozen measure | Exact result |
| --- | ---: |
| Planned / attempted / passed / failed / skipped | **68 / 68 / 68 / 0 / 0** |
| Independently rechecked package identities from retained gzip stdout | **2,921,200**, all exact |
| Ordinary + hard 100,000-row children | **24/24** complete and exact |
| Hard 256 MiB children | **12/12** complete, zero OOM |
| Maximum 100,000-row wall / child CPU | **2.488192 s / 1.677261 s**, both below 5 s |
| Maximum conservative `wait4` child RSS | **162.117 MiB**, below 256 MiB |
| Maximum 100,000-row JSON output | **43,889,275 bytes**, below 64 MiB |
| Malformed feed, oversized feed, duplicate inventory | **12/12** exit 2 with unknown/incomplete result, max **0.286092 s**, **48.305 MiB**, **408 bytes**, no traceback |
| Slow reader / closed stdout | **4/4** each; closed consumers each read exactly **4,096 bytes**, exited 2 without traceback |
| Cgroup OOM-kill deltas | **0** across all children |
| Writable-tree before/after equality | **68/68** for `/tmp` excluding fixed venv, `/var/lib/dpkg`, `/dev/shm` |

The host-side `verify_results.py` independently rehashed the retained compressed output, re-parsed all 68 child results, rechecked all 2,921,200 name/version/architecture/PURL/source tuples, and re-scored frozen exit, wall, CPU, RSS, output and cgroup limits. Its result is `results/verification.json` with **68/68 verified**. Each `results/<cell>/<512m|256m>/` directory retains Docker stdout/stderr, exact command, pip install report, cgroup readback, child JSON, raw compressed stdout and stderr. `results/overall.json` contains the 68-case denominator and all cell records. The runner refuses to overwrite raw evidence.

The earlier `fc4a17` matrix remains under `validation/resource/` at its own pin, including its original 11/14 diagnostic first run. The new maximum 100,000-row wall is 2.488192 s versus 2.229252 s in the prior matrix; these maxima from one fresh run per image are not a controlled performance comparison. The `wait4` RSS includes conservative pre-exec fork high-water from the Python harness. No limit was relaxed.

This resource lane proves before/after equality for the named writable trees under the installed default launcher. It does **not** independently classify attempted file/network syscalls or inspect every possible mount; the separate installed console/tracer review owns that gate. CLI alpha release remains subject to the complete console, custody and independent final-pin acceptance. Distributed autonomous enforcement remains **NO-GO**.
