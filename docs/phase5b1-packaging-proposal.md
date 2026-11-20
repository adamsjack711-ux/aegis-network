# Phase 5B-1 offline packaging proposal

## Exact baseline and ownership

This proposal precedes package changes. The clean isolated branch
`feat/phase5b1-packaging-astra` starts at
`ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`. It contains the
independently reviewed source-only streaming serializer, but `pyproject.toml`
has no `aegis` console script. No source or shared protocol change is made
here. VAL-1's acceptance freeze is pending and must be read before an
implementation diff is reviewed.

The prior `1b30cf8` stabilization branch and separate `0df40c9` alpha branch
diverge from earlier baselines; neither is a drop-in merge. Both add a console
entry point, make `cryptography`/`pydantic` direct runtime requirements, and
move server/broker dependencies to a `lab` extra. `0df40c9` additionally
changes the build backend to pinned setuptools and moves grant parsing out of
shared `config.py`. `1b30cf8` retains Hatchling. Those metadata changes alter
the default install contract; the loader movement is owned outside 5B-1.
The reviewed `4ad4d8d` branch supplies the streaming serializer's owner
measurements and raw evidence, not packaging authority. At the integrated
baseline, the private v2 CLI still imports `config -> core` through the local
feed adapter; 5B-2 owns any approved import-boundary repair. The 5B-1 wheel
must not claim pure observer contents or a clean import graph on its own.

## Proposed minimal metadata delta

1. Retain the existing Hatchling backend, package name/version, Python
   `>=3.12` declaration, full lab dependency set and package layout. Add only
   `[project.scripts] aegis = "aegis.cli:main"` and a direct
   `pydantic>=2.10,<3` requirement, because signed Finding parsing imports
   Pydantic directly. Pin the build backend to the **reviewed** Hatchling
   1.33.0 artifact only after VAL-1 approves its offline cache manifest.
   This preserves today's default lab installation contract and avoids
   adopting either branch's unreviewed extras split or shared loader move.
2. Build from an exact `git archive` source tree, never a dirty worktree.
   Fix `SOURCE_DATE_EPOCH` in the build invocation. Build wheel and source
   distribution twice in separate disposable directories using `uv build
   --offline` with a read-only, hash-recorded cache copy. Require byte-equal
   outputs and inspect wheel member list, `METADATA`, `WHEEL`, `RECORD`,
   `entry_points.txt` and `Requires-Python`. No post-install hook, daemon,
   service, listener or privilege request is permitted.
3. Install through `pip --no-index --find-links <approved-wheelhouse>` in
   disposable non-root read-only-root containers, verify dependency
   resolution without `--no-deps`, invoke the **generated** `aegis` script
   directly, then uninstall and verify no candidate package, script, state
   or service remains. A source `PYTHONPATH` run or borrowed Debian library
   tree is a separate diagnostic and does not satisfy this gate.

An observer-only distribution with only CLI modules would reduce package
surface, but it would introduce a second namespace/package contract and
cross-package versioning. That is a separate proposal; this lane does not
silently split or remove enforcement modules from the current wheel.

## Frozen interface and compatibility decisions

- `SignedFinding` 1.0 canonical bytes, `InventoryItem(purl, version)` exact
  matching, publisher grant and revocation semantics, native T4/T5 and all
  writer interfaces are frozen. Package metadata may expose the existing
  observation-only `main()` but cannot create an authority route.
- Private JSON/human CLI output, exit 0/2 behavior, default zero persistent
  writes, explicit `--state-dir`, and `independent_status=unknown` remain
  unchanged. Package tests must exercise installed script invocation, not
  infer behavior from imports or wheel metadata alone.
- Keep the full original lab dependency set until a separate resolver and
  regression review approves an extras split. Adding the direct Pydantic
  requirement is additive to the existing transitive requirement; exact
  resolution must still be recorded. Do not edit `config.py`, `trust.py`,
  `core.py`, `publisher_config.py`, 5B-2 files or any signed schema.
- The wheel still contains non-observer Aegis modules. Its CLI import path
  remains a 5B-2 integration gate; this package proposal makes no claim of
  code-content isolation.

## Offline wheelhouse contract

The wheelhouse is an input artifact, not a network task. Its manifest must
record, for every wheel: filename, exact SHA-256, distribution/version,
Python/ABI/platform tags, source and review provenance, license, and whether
it is build or runtime material. Freeze the manifest hash before building;
copy it to a private disposable directory for a build and verify the input
copy again afterward. An extracted uv-cache `RECORD` hash is useful for an
integrity snapshot but **is not** the original wheel archive hash or a
publisher-authenticity proof. Never fetch missing wheels automatically.

The prior owner cache has extracted Hatchling 1.33.0; its `RECORD` hash is
`e3b5d3ab14063323c18d7edb898bc0975a3634c636394030766a44798f481df0`.
The default VAL-D cache previously lacked Hatchling; the later supplied
cache-backed wheel build reproduced byte-identical output, while the cache
miss remains retained. A read-only inventory of that local cache found
`cryptography-46.0.7` tagged **macOS universal2** and
`pydantic_core-2.50.5` tagged **CPython 3.15 macOS arm64**. No reviewed
Linux arm64 wheel archives for these two direct requirements were found in
the inspected local cache. Hatchling was present only as an extracted cache
directory, not its original wheel bytes. Fresh Linux installation therefore
remains a missing prerequisite until an approved offline wheelhouse is
supplied.

| Required real platform arm | Cached image/runtime | Dependency status | Current decision |
| --- | --- | --- | --- |
| Debian/Python 3.12 | Cached Debian lab image, Python 3.12.16, preinstalled libraries | Suitable for a diagnostic install only unless a reviewed wheelhouse resolves from scratch | Pending |
| Ubuntu/Python 3.12 | Cached Noble image, Python 3.12.3 | No `cryptography` or `pydantic`; borrowed Debian packages are prohibited for acceptance | Skip prerequisite |
| Debian/Python 3.13 | Cached `python:3.13-slim`, Python 3.13.18 | No `cryptography` or `pydantic`; offline runtime wheels not reviewed | Skip prerequisite |
| Ubuntu/Python 3.13 | No reviewed cached matching image | Image and runtime wheels missing | Skip prerequisite |

The frozen alpha denominator is real Debian and Ubuntu with both Python
3.12 and 3.13. All four platform rows must be independently exercised on
one exact installed-wheel pin for release consideration. At minimum, the
source-only 5B-R memory pass, hybrid Ubuntu behavior, and 5B-A 24+8 matrix
must not be promoted to this installed-platform gate. A cached syscall
observer must also record attempted effects; none is yet approved in this
lane. Missing prerequisites are **skipped**, never passes. The independently
retained 256 MiB baseline OOM and all signature/status failures remain in
the comparison corpus.

## Handoff and release boundary

After VAL-1 freezes the exact package oracle, 5B-1 may implement only the
reviewed metadata/build script and `tests/packaging_phase5b1/` fixtures.
Every raw build/install result, cache/image hash, failure and skip belongs
under `benchmarks/phase5b1/` with an owner-reported label. The package is
not an installable Linux alpha release until VAL-1 reproduces the full
platform, no-write, syscall, resource and import-boundary gates. No master
merge or production distribution follows from this proposal.
