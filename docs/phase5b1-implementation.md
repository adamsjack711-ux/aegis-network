# Phase 5B-1 isolated packaging experiment

## Exact source and scope

VAL-1 froze the alpha oracle at
`0960e6f43af83b221da47e873cc64a9fe899fca7` and reviewed the proposal
at `0cf8724b5e332c239bf9c0ca51053d67726eaa0e`. The clean owner source
pin for this experiment is `47314c6f9bc478f334c494e1e7d31ac3a10e9e2f`
on `feat/phase5b1-packaging-astra`, descended from integrated baseline
`ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`.

The `pyproject.toml` diff adds only the generated
`aegis = "aegis.cli:main"` console entry and direct
`pydantic>=2.10,<3` requirement. It retains Hatchling, the existing full
default lab dependency list, project name/version and Python `>=3.12`.
No CLI, grant loader, SignedFinding, Evidence, T4/T5, InventoryItem, writer
or 5B-2 source was changed. The wheel would still contain non-observer Aegis
modules; no package-content or import-path isolation is claimed.

`scripts/phase5b1_build_offline.py` accepts an exact 40-character source
commit, canonical local wheelhouse, empty output directory and build Python.
Before creating a build environment, it checks a bounded `manifest.json`
with exact wheel filenames, SHA-256, source and license strings. It requires
the actual `hatchling-1.33.0-py3-none-any.whl` archive and rejects missing,
aliased, unlisted, duplicate, unsafe or hash-mismatched archives. It then
archives only committed `pyproject.toml` and `src/aegis`, creates a private
venv, installs the backend with `pip --no-index --find-links` and **normal
dependency resolution**, and invokes Hatchling's wheel/sdist hooks with
fixed `SOURCE_DATE_EPOCH=1735689600`. If inputs are supplied, its report
records actual wheel/sdist SHA-256, member list, entry point, Python version,
and direct/optional `Requires-Dist`. Manifest fields are integrity metadata,
not an automatic assertion of independent supplier trust.

## Verified local result

The focused offline packaging, CLI, streaming and Rapid suite passed
**35/35** on host Python 3.14. Direct build-helper preflights at the first
implementation pin `4ff3c77` and final source pin `47314c6` both used
an absent wheelhouse. Both exited **2** with bounded JSON and created no output
directory. No actual backend archive was available in the inspected local
locations. The older extracted uv cache has Hatchling package files and a
checked `RECORD`, but VAL-1 correctly rejected that as a substitute for a
reviewed **wheel archive**. No `uv build`, pip index, dependency download,
image pull, borrowed Debian library mount or `--no-deps` was used. The
source `pyproject.toml` metadata is recorded; wheel and sdist bytes and
installed metadata remain **unmeasured**.

`benchmarks/phase5b1/` preserves the exact test log, preflight JSON/exit,
cached-image inventory, empty Hatchling archive search, source metadata,
structured planned/attempted/skipped denominators and SHA-256 manifest.
This is owner evidence pending independent VAL-1 review. The scoped
prerequisite result is **2/2 builds skipped**, **4/4 Debian/Ubuntu × Python
3.12/3.13 installed cells skipped**, and **84/84 minimum logical CLI cases
skipped**. The cached Python 3.13 image is real Debian 13/Python 3.13.18;
Ubuntu Noble/Python 3.12.3 is cached, but neither has `cryptography` or
`pydantic`. No inspected Ubuntu/Python 3.13 image or reviewed Linux runtime
wheelhouse was present. The raw status file records each of the four cell
skip reasons separately. Missing inputs were not turned into behavioral
failures or passes.

## Remaining gates

An independently reviewed actual build/runtime wheelhouse, two byte-identical
offline wheel/sdist builds, direct installed console and uninstall in all
four real platform cells, syscall attempted-effect observation, 5B-2 import
and privacy safety, installed resource controls and full integrated
regression remain required. The original 256 MiB OOM, default-write and
ambiguous-status failures remain retained. **Installable Linux alpha is
NO-GO**. No master merge or production distribution is authorized.
