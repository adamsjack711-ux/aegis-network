# Phase 5B alpha owner evidence

These files were produced by the CLI owner from implementation commit
`876988ba30abed9c2954668d02b2c4c13f84e50f`. They are **owner-reported,
not independently accepted**. `SHA256-manifest.json` records the byte hashes.
No source, test, or shared contract changes are part of this evidence commit.

The wheel and source distribution were built three times with
`SOURCE_DATE_EPOCH=1735689600` and the cached Hatchling backend. All three
wheel hashes were `7f4701b30303f47e645374f6d0ee085e74e927bd06dfc26da533ae5bd60a8698`;
all three source distribution hashes were
`d73bca0e0f36a231b3f5a77d51e8c0ed25faf87d056aabfb1ea6cd3380de85fc`.
The raw third build output is included. The original backend wheel is absent
from the cache; the manifest's backend hash covers its extracted `RECORD`, not
the wheel archive.

For each matrix, the exact wheel was installed with `pip install --no-index
--no-deps --no-cache-dir` in a disposable container and invoked via its
installed `/tmp/v/bin/aegis` console script. Docker used `--pull never`,
`--network none`, `--read-only`, UID/GID 1000, `--cap-drop ALL`,
`--security-opt no-new-privileges`, `--cpus 1`, `--memory 512m`, executable
`/tmp` tmpfs, and a separate disposable `/var/lib/dpkg` tmpfs. Scripts
`scripts/phase5b_alpha_matrix.py` and `scripts/phase5b_alpha_rusage.py` were
mounted read-only and called with `--console /tmp/v/bin/aegis` and the real
container `--distro` (`debian` or `ubuntu`). The matrix checks 12 default
logical cases in JSON and human mode, five extra signed negatives, and four
explicit-state controls. It compares file content hashes and mtimes before
and after each invocation. The resource script launches three fresh console
processes at 100, 10,000, and 100,000 synthetic package rows; it records
monotonic wall time, child CPU time, and peak RSS. Debian and Ubuntu hybrid
each recorded 33/33 matrix cases and 9/9 resource trials with no observed
default-state writes.

The Ubuntu Noble image lacked the project's runtime dependencies. Its run
mounted **read-only copies of dependencies from the cached Debian image**.
Thus Ubuntu results diagnose CLI behavior but do not clear independent Ubuntu
installation. Cached `ubuntu:22.04` contained no Python. No cached syscall
tracer was available, so attempted network, execution, and privilege syscalls
remain unmeasured. The complete host suite was not run: `test_slice.py`
collection failed because the host Python 3.14 environment lacked `nats`.
An offline `uv run` on host Python 3.15 failed dependency resolution because
cached `psycopg[binary]` was unavailable. The cached Debian Python 3.12 image
lacked `pytest`; focused host Python 3.14 CLI/grant/Rapid tests passed 41/41.

The outputs include synthetic throwaway public signing material and local
fixture paths. They contain no private signing keys, real credentials, or
production identifiers.
