# Phase 5B-A installable Linux CLI alpha

## Scope and compatibility

The approved baseline is `3bfd2abea430bc8036105ce85adfdc78706d367d`; the reviewed observer-purity change is `a9b0d0e1d45b64ce833343dbfa3dd9f034a20770`. This alpha installs the `aegis` observation CLI from a pure-Python wheel. It reads Debian `dpkg` inventory and local signed Mesh finding files only. It does not enroll a host, fetch intelligence, verify independent T4/T5 status, or authorize enforcement. Missing current independent Evidence status is always `independent_status="unknown"`.

The validated installation matrix is Debian 13 (Trixie) on arm64 with Python 3.12.16 and Ubuntu 24.04 (Noble) on arm64 with Python 3.12.3. The cached image IDs are `sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e` and `sha256:706130e55f22d2c81e272e0bf987be194bbbca232ab554b440f3116e74b00b60`, respectively. Each was an actual installation in a disposable image using its real `/etc/os-release` and `/var/lib/dpkg/status`; the Ubuntu claim does not rely on a fixture. Other releases, architectures and Python minors have not been validated. The Python metadata requires 3.12 or later, which is broader than this measured matrix.

Ordinary read access to `/etc/os-release` and `/var/lib/dpkg/status` is enough. The supported workflow uses UID 1000, no capabilities, no network and a read-only root. It requires no enforcement permission. Only the explicit global `--state-dir PATH` option persists an identity in `PATH/identity.json` (0700 directory, 0600 file). Default invocations leave identity and state absent. Install/uninstall themselves write only inside the selected disposable Python environment.

## Offline build and dependencies

The baseline declared Hatchling without a cached copy, so `uv build --offline --wheel` could not resolve it. This alpha replaces that build backend with `setuptools==84.2.1`, which was already in the approved local uv cache. The exact pin prevents silently taking a later backend. No network fetch or image pull was performed. `scripts/build_phase5b_alpha.sh` archives only `pyproject.toml` and `src/aegis` from a full commit ID into a disposable staging directory, fixes `SOURCE_DATE_EPOCH` to the approved baseline timestamp `1795143126`, and builds with `uv build --offline`. The backend must be provisioned into the local cache through the organization's approved dependency process before reproducing on a new machine; an empty cache fails closed.

The CLI's direct runtime dependencies are `cryptography>=44,<47` and `pydantic>=2.10,<3`. The application server dependencies moved to the optional `lab` extra. The wheel still contains lab modules, but normal CLI import does not load `core`, `config`, `agent_runtime` or `mitigation`; publisher-grant parsing was separated into `publisher_config.py`. The lab extra is needed for server and broker workflows. The test matrix uses the Debian image's preinstalled runtime libraries; because the cached Ubuntu image lacks `ensurepip` and these libraries, the script exports the already installed Debian Python 3.12 libraries to a read-only test mount and installs the candidate wheel in an Ubuntu venv with `pip --python --no-index --no-deps`. This proves wheel entry-point behavior on Ubuntu; it does not prove independent dependency resolution from a fresh Ubuntu package index.

Build twice from the same full commit, then compare hashes:

```sh
pin=$(git rev-parse HEAD)
bash scripts/build_phase5b_alpha.sh "$pin" /tmp/aegis-build-a
bash scripts/build_phase5b_alpha.sh "$pin" /tmp/aegis-build-b
shasum -a 256 /tmp/aegis-build-{a,b}/aegis_network-0.1.0-py3-none-any.whl
```

The output wheel is `aegis_network-0.1.0-py3-none-any.whl`. The two offline builds from the same source were byte-identical. To install on a host with approved cached runtime wheels, create a Python 3.12+ virtual environment and use `pip install --no-index --find-links WHEELHOUSE` with the candidate and its runtime dependencies. The Linux matrix below performs its install without any index access.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../../.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_phase5b_cli.py tests/test_slice.py tests/test_rapid_policy.py
bash scripts/smoke_phase5b_linux.sh
```

The matrix installs the archived wheel separately on Debian and Ubuntu with `--pull never --network none --read-only --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges`. It runs the installed console script through its Python interpreter because `/tmp` is noexec. It exercises all default commands, a signed exact match, an invalid signature, a signed withdrawal, exact-version mismatch, range-like version, malformed `dpkg` inventory, and explicit state opt-in. The retained independent five-case default-state oracle is rerun unchanged. Each default call is compared against before/after content and mtime hashes of its writable state and install trees. The root is read-only. After uninstall, the console script, package and distribution metadata must be absent from the venv. The same matrix records ten independent process samples for `--help`, `inventory`, and `doctor` on each distribution.

The private JSON schemas are `inventory-v2`, `status-v2`, `observation-results-v2`, `exposure-observation-v2`, `doctor-v2` and `observation-error-v2`. Signed exact matches remain possible exposure leads with `overall_assessment="unknown"`; invalid signatures are rejected. Versions compare as full strings, including epoch and distribution revision. Unsupported PURLs and comparator syntax are unknown. Exit 0 means a local observation completed against supported input, never that the host is safe; exit 2 means missing, incomplete or rejected local input. Human output states that independent Evidence status is unknown.

The benchmark reports process wall time, CPU time and peak RSS from Linux `wait4`, along with wheel and installed package bytes. `--help` is the measured process startup path; `inventory` and `doctor` include startup and observation work. Runs are limited to one CPU and 256 MiB; the numbers are local observations, not a universal resource guarantee. See `benchmarks/phase5b-alpha/validation.json` for captured results and hashes.

No syscall tracer was cached for this run, so syscall-level auditing remains inconclusive. The writable-tree hashes, offline container boundary and Python import/API checks are the available controls. This alpha is not a production deployment and has not been merged to master.
