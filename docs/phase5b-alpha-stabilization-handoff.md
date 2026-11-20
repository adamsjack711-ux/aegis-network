# Phase 5B-R Linux CLI alpha stabilization handoff

## Decision

**ALPHA NO-GO.** The memory ceiling and tested Debian behavior pass, but the frozen gate also requires fresh Ubuntu and Python 3.13 installs, attempted-syscall evidence, and the full matrix on both distributions. Those remain incomplete. This branch is not merged into master.

The worktree starts at `d15a3a756b8066c5cb2d98665662220e52f4a7d6`. The observed prior wheel is the clean `876988ba30abed9c2954668d02b2c4c13f84e50f` owner candidate, SHA-256 `7f4701b30303f47e645374f6d0ee085e74e927bd06dfc26da533ae5bd60a8698`. The final stabilized wheel is `dist/aegis_network-0.1.0-py3-none-any.whl`, SHA-256 `7f972ed4ecebebdeacc2b207be0ba6297047b1be33a1820f6bed2020f455bd57`. Both are version 0.1.0, so installation must use an isolated fresh environment or `--force-reinstall`.

## Memory and output

Before editing, I ran the prior exact wheel with its unchanged `phase5b_alpha_rusage.py` harness inside the pinned Debian 13 arm64 image `sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e`. It used UID 1000, one CPU, a 512 MiB hard limit, read-only root, tmpfs `/tmp` and `/var/lib/dpkg`, no capabilities, no new privileges, no network, and direct installed console invocation. Three 100,000-row trials peaked at **297.824, 297.824, 297.820 MiB**. Raw data: `benchmarks/phase5b-stabilization/baseline-debian-512m.json`.

The snapshot hash now streams each package identity into SHA-256 instead of allocating an identity list and full JSON copy. Package records use slots. `inventory --json` writes one package object at a time after the complete snapshot has been validated, rather than allocating the full result list and serialization buffer. The legacy snapshot ID bytes are covered by a regression test. Duplicate installed identities still reject the entire inventory. No rows are truncated.

The final wheel ran the same resource harness under a **256 MiB hard limit**. All nine trials completed: 100, 10,000 and 100,000 rows, three fresh processes per size. At 100,000 rows, wall was **1502.287 / 1508.123 / 1510.891 ms**, CPU **1500.179 / 1498.763 / 1507.631 ms**, and peak RSS **89.496 / 89.500 / 89.492 MiB**. The final JSON output declared `package_count: 100000` and contained exactly 100,000 `purl` entries; it was 39,089,273 bytes. Raw data: `candidate-debian-256m.json` and `candidate-debian-output-count.txt`. The frozen ≤5 s wall/CPU and ≤256 MiB RSS gates pass on this Debian pin. The three samples do not establish a broad capacity guarantee.

## Package and compatibility

The wheel exposes `[console_scripts] aegis = aegis.cli:main` and declares `cryptography>=44,<47` and `pydantic>=2.10,<3` as direct dependencies. Lab server dependencies are in the optional `lab` extra. The CLI grant loader no longer imports lab policy code. The wheel still bundles other Aegis modules; normal CLI imports avoid the protected writer, but module packaging isolation is not proven. Hatchling remains the build backend. Two offline builds with fixed `SOURCE_DATE_EPOCH=1735689600` and the reviewed local cache produced the same SHA-256 above. The cache has integrity evidence in `docs/phase-next-alpha-5b-cache-supplement.md`; it is not independently authenticated upstream.

The direct installed-console Debian matrix passed **33/33**: 24 JSON/human default invocations from 12 logical cases, five additional signed negatives, and four explicit-state controls. Its tree snapshots found no changes on default calls under the measured writable mounts. Explicit identity creation was confined to the requested directory. The matrix confirms valid SignedFinding 1.0 signature handling, invalid signature rejection, withdrawal and expiry, exact version comparison, unsupported comparator unknown, and `independent_status=unknown` on a signed exact match. Fresh Debian install and uninstall passed. Raw matrix: `candidate-debian-matrix.json`.

| Environment | Fresh offline install | Direct CLI matrix | Resource gate | Limitation |
| --- | --- | --- | --- | --- |
| Debian 13 arm64, Python 3.12.16 | Pass using image-local dependencies and candidate wheel | 33/33 pass | 9/9; 100,000-row RSS ≤89.500 MiB | Runtime dependencies were preinstalled in this image, not resolved from an empty host |
| Ubuntu 24.04 arm64, Python 3.12.3 | **Blocked**: local cache has no Ubuntu-origin `cryptography` wheel | 0/33 attempted | 0/9 attempted | No Debian library mount was used |
| Debian arm64, Python 3.13.18 | **Blocked**: local cache has no Linux 3.13 `cryptography` wheel | 0/33 attempted | 0/9 attempted | Dependency-free inventory parser import succeeded only; full CLI unverified |

The Ubuntu and Python 3.13 install errors are retained as `ubuntu-fresh-install.*` and `python313-fresh-install.*`. An attempt to fetch the Ubuntu wheelhouse over the network was rejected by automatic approval review because the specified acceptance is offline. That operation was not performed. A reviewed, locally supplied wheelhouse is needed before these environments can be scored.

## Privacy, safety, and regression

The Debian matrix uses independent before/after path, mode, mtime, size and content-digest snapshots under `/tmp` and `/var/lib/dpkg`; the root filesystem was read-only. No default state was created. Container networking was disabled. The Python API guard passed at source pin `c69cd4c654f523043ff13b6a41733b9cb6108327` with no observed network, subprocess or privilege API calls; its raw result is `candidate-api-guard.json`. No `strace` binary or compiler was present in the cached Linux images, so attempted connect, exec, privilege and write syscalls are **not proven absent**. The Python API guard and source import review are supplementary controls, not a syscall trace. No privileged enforcement or command execution path is exposed by the CLI.

Focused Phase 5B, slice and rapid-policy tests passed **29/29**. The full suite first failed in the sandbox because Unix socket binding was denied. Repeating with local test permissions passed **359**, skipped **37**, and reported one dependency deprecation warning in **134.84 s**. Skips and the missing independent Linux gates prevent ALPHA GO.

## Reproduce and continue

```sh
export UV_CACHE_DIR=/path/to/reviewed-offline-build-cache
pin=$(git rev-parse HEAD)
bash scripts/build_phase5b_stabilized.sh "$pin" /tmp/aegis-build-one
bash scripts/build_phase5b_stabilized.sh "$pin" /tmp/aegis-build-two
sha256sum /tmp/aegis-build-{one,two}/*.whl
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts ../../.venv/bin/python -m pytest -q -p no:cacheprovider
```

Complete the missing Ubuntu and Python 3.13 offline dependency installs in fresh containers, rerun the full installed matrix and three resource trials at each size per distribution, and obtain syscall trace or a formally reviewed equivalent. Preserve any failed trial. Do not recommend ALPHA GO until the exact committed candidate passes every frozen independent gate.
