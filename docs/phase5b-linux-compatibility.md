# Phase 5B-1 offline Linux packaging acceptance

## Result

**Acceptance incomplete; alpha NO-GO.** The source at `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9` gained an installable `aegis` entry point, two direct CLI dependencies, and an isolated publisher-grant import. The newer CLI streaming serializer was not changed. Two offline builds from exact packaging commit `e75757c40c4ce1e327e93bb459974f823074432e` yielded the same wheel SHA-256, `37ca4c6d5b5cdea1e770fd29fe93236a1a521bf4cd7d3b1ef2be71b55a6810d1`. The built artifact is [committed in `dist`](../dist/aegis_network-0.1.0-py3-none-any.whl).

The reviewed, hash-pinned **Linux runtime dependency wheelhouse is unavailable**. No dependency was downloaded. Fresh isolated installs on all three available Linux/Python cells stopped at the missing `cryptography<47,>=44` wheel. Therefore Ubuntu execution, Python 3.13 execution, fresh dependency resolution, and their uninstall results remain unverified. The committed [wheelhouse review state](../benchmarks/phase5b-linux-compatibility/wheelhouse-review.json) is deliberately rejected by `scripts/verify_phase5b_wheelhouse.py`; it cannot be used as an acceptance manifest. A reviewer must supply original Linux wheel artifacts, exact SHA-256 values and provenance before the fresh matrix can pass.

## Environment and provenance

The build used `uv build --offline --wheel`, `SOURCE_DATE_EPOCH=1735689600`, and the locally supplied `/private/tmp/aegis-phase5b-uv-cache`. `pyproject.toml` pins Hatchling 1.33.0. Its extracted `RECORD` SHA-256 was `e3b5d3ab14063323c18d7edb898bc0975a3634c636394030766a44798f481df0`; the earlier cache integrity snapshot is in [the independent cache supplement](phase-next-alpha-5b-cache-supplement.md). This establishes local cache consistency, not independent upstream authentication. The Aegis wheel is `py3-none-any`, contains the console entry point, and declares `cryptography>=44,<47` and `pydantic>=2.10,<3`; lab server requirements are optional.

| Cached image (immutable ID) | OS / Python / architecture | Fresh dependency install | Installed CLI result |
| --- | --- | --- | --- |
| `67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e` | Debian 13.7 / 3.12.16 / arm64 | Fail: no cryptography wheel | Pass with image-preinstalled dependencies only: 33/33 matrix, install and uninstall |
| `706130e55f22d2c81e272e0bf987be194bbbca232ab554b440f3116e74b00b60` | Ubuntu 24.04.1 / 3.12.3 / arm64 | Fail: no cryptography wheel | Skipped: no fresh install |
| `e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90` | Debian 13.7 / 3.13.18 / arm64 | Fail: no cryptography wheel | Skipped: no fresh install |

The [environment JSON files](../benchmarks/phase5b-linux-compatibility/) record `/etc/os-release`, Python, architecture, UID, installed versions, paths and installed distribution `RECORD` hashes. The Debian image had cryptography 46.0.7, pydantic 2.14.4, cffi 2.1.1 and pydantic-core 2.50.5 already installed. A `RECORD` hash is **not** a wheel hash or provenance for a fresh install. Ubuntu and Python 3.13 images lacked these runtime libraries. The [acceptance manifest](../benchmarks/phase5b-linux-compatibility/acceptance-manifest.json) records image IDs, build inputs and gaps.

## Observed behavior

The Debian installed-wheel matrix used ordinary UID 1000, `--network none`, `--pull never`, read-only root, no capabilities, no new privileges, and disposable tmpfs mounts. It passed 24 JSON/human invocations across 12 default cases, five additional signed negatives, and four explicit-state controls: **33/33** on rerun. The original run is retained at `debian312-preinstalled-matrix.json`: 32/33 passed, with one harness assertion expecting the old phrase “possible exposure.” The current human text reports an exact match and explicitly says independent Evidence status is unknown; the assertion was corrected in the copied harness and the rerun passed. Default invocations changed no path, mode, size, mtime or content digest in the harness's `/tmp` and `/var/lib/dpkg` trees. The root filesystem was read-only. The signed-current JSON result had `publisher_authenticity=verified`, `software_match=matched`, `local_claim_status=current-in-supplied-file`, `independent_status=unknown` and `overall_assessment=unknown`. Invalid signature, expired, withdrawn, future, revoked grant, conflict, duplicate inventory, malformed input and unsupported range controls were exercised. Explicit identity stayed in the selected directory; symlink controls failed closed.

The Debian preinstalled-dependency smoke installed this wheel into a non-root venv, ran `--help`, real `dpkg` inventory and `doctor`, then uninstalled it; the generated `aegis` script was removed. That image already contains an older same-version Aegis distribution, so `--force-reinstall` was needed inside the venv. The three truly isolated venvs failed before CLI execution and uninstall. Logs and exit codes for all four probes are in [the raw evidence directory](../benchmarks/phase5b-linux-compatibility/). The source tests for CLI, streaming, signed finding, and rapid policy passed **37/37** on macOS Python 3.15.2, with one Starlette deprecation warning. No full Linux test suite or syscall trace was run in this work; attempted connect, exec, privilege and write syscalls remain unverified. No production host or credentials were used.

## Exact reproduction

Run from this worktree on a host with the same cached images. The local build cache is required and may need to be supplied through the approved dependency process. Commands use no index, networked container or image pull:

```sh
export UV_CACHE_DIR=/private/tmp/aegis-phase5b-uv-cache
pin=$(git rev-parse HEAD)
mkdir -p .phase5b-local-wheels .phase5b-build-two
bash scripts/build_phase5b_offline.sh "$pin" .phase5b-local-wheels
bash scripts/build_phase5b_offline.sh "$pin" .phase5b-build-two
shasum -a 256 .phase5b-local-wheels/*.whl .phase5b-build-two/*.whl
python3 scripts/verify_phase5b_wheelhouse.py .phase5b-local-wheels benchmarks/phase5b-linux-compatibility/wheelhouse-review.json
bash scripts/probe_phase5b_linux_install.sh debian312 .phase5b-local-wheels
bash scripts/probe_phase5b_linux_install.sh ubuntu312 .phase5b-local-wheels
bash scripts/probe_phase5b_linux_install.sh debian313 .phase5b-local-wheels
bash scripts/probe_phase5b_linux_install.sh debian312-preinstalled .phase5b-local-wheels
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../../.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_phase5b_cli.py tests/test_phase5b_streaming.py tests/test_slice.py tests/test_rapid_policy.py
```

The wheelhouse verification and first three probes are **expected to fail** with the currently available artifacts. For a reviewed wheelhouse, place the Aegis wheel and each compatible Linux dependency wheel in `.phase5b-local-wheels`, replace the incomplete manifest with reviewed filename/SHA-256/provenance/reviewer records, and run the verifier before the fresh probes. The verifier checks integrity and completeness of named distributions; the fresh pip installs check actual wheel tag and dependency compatibility in each image. The missing wheelhouse must come from an authorized offline supply path. Keep this branch separate from master and obtain independent acceptance before changing the alpha gate.
