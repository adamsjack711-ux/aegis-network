# ALPHA-3 CLI privacy and performance observation

Source: clean worktree created from `29455087922a728a41936d8c5c79ff9942e1e3df` on `feat/alpha-cli-privacy`. No product code or prior evidence was changed. This is a source-module observation of that exact pin, not an installed-wheel or integrated release test.

## Environment and method

Disposable local Docker image `aegis-alpha-cli-privacy:local` at `sha256:d41dcb753948f6fdcdf428eac083555c08efd6c823c1fe0c33329263127820e6`: Debian 13.7, Python 3.13.18, arm64, `strace` 6.13. The base image was cached and pinned; the test image build fetched Debian `strace`/`time` and Python packages from package repositories. This is **not** the frozen approved offline wheelhouse. Runtime containers had no network namespace access, a read-only root, UID/GID 1000, no added capabilities, no new privileges, one CPU and the stated hard memory limit. The trace runs used `seccomp=unconfined` so the unprivileged tracer could observe attempted syscalls. Source and dpkg fixtures were read-only mounts. A trace-only writable mount held the tracer's output; explicit-state cases alone received a writable `/state` mount.

The synthetic input is exactly 100,000 unique installed `packageNNNNNN` dpkg stanzas (also 100 and 10,000). For each JSON inventory output, an independent verifier compared **every** row's name, purl, version, architecture and source to its expected value, plus total count and completeness. Wall/CPU/RSS are GNU `time -v` measurements of the CLI process inside the container; wall p50/p95 uses nearest rank over three fresh runs, so p95 equals the slowest observed run. CPU is user plus system time. Compressed raw stdout and the input fixtures are retained under [benchmark evidence](../benchmarks/alpha-cli-privacy/); [resource results](../benchmarks/alpha-cli-privacy/resource-results.json) include every exit and digest.

| Rows / hard cap | Completed / attempted | Wall p50 / p95 / max | CPU p50 / p95 | Peak RSS max | Verified rows | Output bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 / 512 MiB | 3 / 3 | 0.11 / 0.12 / 0.12 s | 0.10 / 0.11 s | 35.49 MiB | 300 / 300 | 43,972 each |
| 10,000 / 512 MiB | 3 / 3 | 0.23 / 0.24 / 0.24 s | 0.21 / 0.21 s | 42.22 MiB | 30,000 / 30,000 | 4,379,274 each |
| 100,000 / 512 MiB | 3 / 3 | 1.69 / 1.71 / 1.71 s | 1.30 / 1.31 s | 105.88 MiB | 300,000 / 300,000 | 43,889,275 each |
| 100,000 / 256 MiB | 3 / 3 | 1.69 / 1.69 / 1.69 s | 1.30 / 1.30 s | 105.88 MiB | 300,000 / 300,000 | 43,889,275 each |

All twelve runs exited 0, with zero row discrepancies, zero censored runs and `oom_kill=0` before and after each run. The 100,000-row output is 41.86 MiB, below the frozen 64 MiB ceiling. Three additional malformed/truncated, duplicate and oversized-line inputs each exited 2 in 0.10 s, with zero accepted packages, bounded 403–412 byte output and peak RSS ≤35.49 MiB; [failure results](../benchmarks/alpha-cli-privacy/failure-results.json) retain all three exits and reasons. The source-focused suite passed 9/9.

## Attempted effects and conservative outcomes

[Raw syscall traces and CLI output](../benchmarks/alpha-cli-privacy/traces/) cover **12 default/failure invocations and four explicit-state invocations**. In the 12 defaults, `strace -ff -e trace=file,network,process` observed **0** `socket`/`connect`/send attempts, **0** writable opens or filesystem mutation attempts, **0** privilege/namespace attempts and only the expected initial Python `execve` per invocation. The read-only source/input tree did not change. These counts include invalid-signature, missing-trust, malformed-feed, expired and withdrawn paths. Tracing succeeded; it does not stand in for the unrun installed-console/platform matrix.

The first `--state-dir /state/chosen` invocation made exactly two successful mutations: `mkdirat(..., 0700)` and `openat(..., O_CREAT|O_EXCL, 0600)` for `identity.json`. The repeat returned the same UUIDv4 identity and made no successful mutation; `mkdirat` and `openat(O_CREAT|O_EXCL)` were attempted and returned `EEXIST`. Ancestor and final symlink paths exited 2 without any successful mutation; final-symlink `mkdirat` also returned `EEXIST`. The saved state-tree modes and identity-file hash are in [trace results](../benchmarks/alpha-cli-privacy/trace-results.json). The disposable state directory was removed after recording evidence.

The tampered signature and missing trust yielded exit 2 with `status=unknown` and `independent_status=unknown`. A valid signed exact package match had `software_match=matched` and `local_claim_status=current-in-supplied-file`, while `independent_status=unknown` and `overall_assessment=unknown` because no independently verifiable Evidence/T4/T5 status was supplied. Expired and withdrawn signed claims likewise retained `overall_assessment=unknown` and exited 2. This is conservative observation, not an authorization result.

## Denominators and acceptance boundary

The historical 100,000-row **3/3 OOM failure at a 256 MiB hard cap** remains in the baseline [frozen acceptance record](phase-next-r-acceptance-frozen.md) and [original evidence manifest](../benchmarks/phase-next-r-validation/original-evidence-manifest.json), which pins the prior raw SHA-256 `e160f03fb08bf078b7fd678a201567fc8f89b60d4775dd04febf68f79baa463d`. The new 3/3 result is from this source pin and test image; it does not erase the original failure or constitute a controlled comparison with that earlier candidate.

This lane completed 12/12 resource successes, 3/3 expected conservative failure outputs and 16/16 traced CLI invocations. It did **not** run the frozen Debian/Ubuntu × Python 3.12/3.13 installed-console matrix, offline wheel/sdist reproducibility, independent Ubuntu dependency resolution, all frozen JSON/human commands, slow/closed stdout consumer, or every writable-mount snapshot. Those denominators remain unattempted here. Therefore the **resource and sampled syscall observations pass at this source pin**, while **Linux CLI alpha acceptance remains unverified / NO-GO** under the full frozen gate.
