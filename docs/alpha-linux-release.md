# Alpha 2 Linux release engineering handoff

## Pin and interface

This branch starts at `29455087922a728a41936d8c5c79ff9942e1e3df` in
`.worktrees/alpha-linux-release`. That commit is not an ancestor of the dirty
`master` checkout. The reviewed `pyproject.toml` keeps Hatchling, Python
`>=3.12`, the full default lab dependency set and the `aegis` entry point.
No shared CLI, grant, schema, Trust, Evidence, or writer interface was changed;
Main Astra therefore has no interface delta to integrate. The previously
reviewed alternate wheel with a `lab` extra was not adopted.

## Release procedure

`scripts/alpha_linux_release.py` takes an exact source commit, a canonical
local wheelhouse directory, and an empty output directory. It performs these
local checks in order:

1. Verify every original wheel archive against `manifest.json` SHA-256 and
   `provenance.json` identity, tags, source, license, role, and exact review
   commit. The reviewer record is a supplied assertion; the script cannot
   independently establish supplier authenticity or license accuracy.
2. Copy the verified wheelhouse into a disposable directory and check it
   again. Build an exact `git archive` source twice with the reviewed 5B-1
   helper and fixed `SOURCE_DATE_EPOCH`. Require identical wheel and sdist
   SHA-256, then check package metadata and the generated console entry.
3. Run each available Debian 13/Ubuntu 24.04 × Python 3.12/3.13 cell in a
   fresh venv as UID 65534, with `--network none`, `--pull never`, a read-only
   root and only `/tmp` writable. pip uses `--no-index`, normal dependency
   resolution, and a report whose installed original archive hashes must
   match the frozen manifest. Invoke the generated script, check offline and
   unknown status, default-write file inventory, uninstall and absence of
   the script/module. Missing images are skipped. An optional `--image
   CELL=LOCAL_IMAGE` supplies a cached image for a missing cell; OS and Python
   version are checked inside it.

The input directory needs both the existing `aegis-offline-wheelhouse-v1`
`manifest.json` and a second record of this shape. Each wheel named in one
must appear exactly once in the other. The `review_commit` must refer to an
actual independent review of the supplied archive bytes, not an arbitrary
label.

```json
{
  "schema": "aegis-release-provenance-v1",
  "review_commit": "<exact 40-character independent review commit>",
  "wheels": [
    {
      "file": "<original wheel archive filename>",
      "sha256": "<archive SHA-256>",
      "distribution": "<METADATA Name>",
      "version": "<METADATA Version>",
      "tags": ["<WHEEL Tag>"],
      "source": "<supplier and acquisition record>",
      "license": "<reviewed license>",
      "role": "build"
    }
  ]
}
```

`role` is `build`, `runtime`, or `both`. The manifest must include the actual
`hatchling-1.33.0-py3-none-any.whl` archive and its build dependencies, plus
all platform runtime wheels needed by the package's direct and transitive
requirements. An extracted cache directory or a preinstalled dependency is
not an original wheel archive. The entry point is `aegis = aegis.cli:main`.

From this worktree, the terminal handoff command is:

```sh
python3 scripts/alpha_linux_release.py \
  29455087922a728a41936d8c5c79ff9942e1e3df \
  /absolute/path/to/reviewed-wheelhouse \
  /absolute/path/to/empty-output \
  --image ubuntu-2404-py313=reviewed-cached-ubuntu-image
```

The command exits zero only when both artifacts reproduce and all four fresh
installed cells pass. It records `release-report.json` and both build outputs
in the chosen output directory.

## Measured result at this handoff

The local release preflight exited **2** before building because
`/private/tmp/aegis-alpha-reviewed-wheelhouse` does not exist. No
**release-eligible** wheel or sdist was produced. An additional, explicitly
unreviewed `uv build --offline` diagnostic used only the local **extracted**
uv cache with the exact source archive and fixed epoch. Its two independent
builds were byte-identical: wheel SHA-256
`4c3b6a9edcc78efc2dada9f3a88e8dbe4e3fb472abafe438336936425033502d`
and sdist SHA-256
`8a074b379fe8c4bac82f8dc70c7a183a409198e596be3c77ea151209c7f9d306`.
The wheel contains all 68 source package files unchanged, the reviewed
default dependencies, `Requires-Python: >=3.12`, and the console entry.
Its backend archive provenance is unavailable, so neither artifact is
promoted to the release gate or installed as a fresh-platform acceptance
test. Both pairs and build logs are retained under
`benchmarks/alpha-linux-release/diagnostic/`.
The direct dependency manifest is in
`benchmarks/alpha-linux-release/source-dependencies.json`; a resolved,
hash-pinned transitive dependency manifest is unavailable. The original
Hatchling archive and Linux runtime archives were not found in the inspected
local wheel locations. No package download, image pull, or external service
was used.

| Cell | Cached image and verified runtime | Fresh installed-wheel result |
| --- | --- | --- |
| Debian 13 / Python 3.12 | `aegis_phase4_baseline-coordinator`, Python 3.12.16 | **Skipped:** reviewed wheelhouse absent |
| Debian 13 / Python 3.13 | `python:3.13-slim`, Python 3.13.18 | **Skipped:** reviewed wheelhouse absent |
| Ubuntu 24.04 / Python 3.12 | Playwright Noble image, Python 3.12.3 | **Skipped:** reviewed wheelhouse absent |
| Ubuntu 24.04 / Python 3.13 | No reviewed matching cached image identified | **Skipped:** image and wheelhouse absent |

The release-gate unit tests passed **4/4** on the macOS host and **4/4** in
each of the three cached Linux images, non-root, offline and read-only. Those
tests validate harness behavior only. Entry-point execution, uninstall,
default no-write behavior and dependency compatibility in a fresh installed
venv remain **0/4 exercised**. The existing `tests/packaging_phase5b1`
requires pytest, which is not installed in the host Python 3.15 used here;
its previously retained result is not a new result from this branch.

Two earlier equal wheels at `/private/tmp/aegis-alpha-pin-build-{a,b}` have
SHA-256 `0e4a815ad95f5fab9d8bb997bec4ea8f67896460db86bb838441ca7318cbd0fa`.
They use an alternate `lab` extra and differ from this exact source in seven
package files, so they are **not** release artifacts for this pin.

Raw records: `benchmarks/alpha-linux-release/attempt/release-report.json`,
`benchmarks/alpha-linux-release-preflight.stdout`,
`benchmarks/alpha-linux-release/cached-images.txt`, and
`benchmarks/alpha-linux-release/stdlib-tests.log`, plus the diagnostic
`result.json` and `inspection.json`. The SHA-256 evidence
manifest covers these files and the direct dependency manifest.

## Handoff and limits

Main Astra can review this isolated branch as release tooling without a
shared-interface change. A release decision requires a separately approved
original-archive wheelhouse, exact independent provenance, a cached
Ubuntu 24.04/Python 3.13 image, two reproducible builds, and all four fresh
installed-console cells. The cell runner checks files created under `/tmp`
during default CLI calls but is not a syscall-level attempted-effect tracer
and does not exercise the frozen full CLI/resource case denominator. These
remain separate release gates. **Installable Linux alpha is NO-GO.** No
master merge or distribution publication occurred.
