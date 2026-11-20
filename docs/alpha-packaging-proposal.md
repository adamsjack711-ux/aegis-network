# Alpha Readiness Linux packaging proposal

**Source:** clean `feat/alpha-linux-packaging` worktree created from reviewed integration `29455087922a728a41936d8c5c79ff9942e1e3df`. This is a packaging acceptance proposal and local prerequisite inventory. No `pyproject.toml`, CLI, grant reader, SignedFinding, inventory matcher or native T4/T5 file has changed. Implementation review waits for the new independent validator freeze.

## Frozen package boundary

The current project metadata already exposes `aegis = "aegis.cli:main"`, requires Python `>=3.12`, directly requires Pydantic and preserves FastAPI, HTTPX, NATS, psycopg and Uvicorn in the default lab dependency set. Keep this behavior. Do not adopt the separate `d0cd520` branch's dependency-extras split, duplicate publisher parser or extracted-cache Hatchling provenance without a versioned compatibility decision. The wheel still contains lab modules; an installed-console result does not establish an observer-only wheel or a no-enforcement-import boundary.

## Local prerequisite inventory

The read-only search examined actual `*.whl` files under `/private/tmp`, existing repository worktrees and the local uv cache, including exact names for Hatchling, cryptography and pydantic-core. It found many historical **Aegis-built** wheel/sdist artifacts, but no actual dependency wheel archive matching those three names in the searched paths. This is a scoped inventory, not proof that no other authorized archive exists. An extracted uv package cache or installed distribution `RECORD` is not a reviewed wheel archive. No network lookup, dependency download or image pull occurred.

The locally cached container IDs were inspected with `docker run --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534` and `cat /etc/os-release; python3 --version` only:

| Frozen cell | Cached image and observed Python | Present for inspection | Fresh install acceptance |
| --- | --- | --- | --- |
| Debian 13 / Python 3.12 | `sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e`; 3.12.16 | Yes | **Skipped**: no reviewed backend/runtime wheelhouse. Resident image packages cannot satisfy fresh install. |
| Debian 13 / Python 3.13 | `sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`; 3.13.18 | Yes | **Skipped**: no reviewed backend/runtime wheelhouse. |
| Ubuntu 24.04 / Python 3.12 | `sha256:706130e55f22d2c81e272e0bf987be194bbbca232ab554b440f3116e74b00b60`; 3.12.3 | Yes | **Skipped**: no reviewed backend/runtime wheelhouse. |
| Ubuntu / Python 3.13 | No matching inspected cached image | No | **Skipped**: image and wheelhouse absent. |

The Aegis wheel in `dist` on `d0cd520` and the historical `/private/tmp` build outputs are diagnostic artifacts from other source pins. They cannot be substituted for a reproducible wheel built from this integrated candidate. [Machine-readable prerequisite inventory](../benchmarks/alpha-packaging/prerequisite-inventory.json) records planned/attempted/skipped counts.

## Proposed offline supply and build gate

Use an operator-provided, **independently reviewed** actual archive wheelhouse. For each archive, pin its filename, SHA-256, size, package/version, wheel tags, license, supplier provenance, review reference and intended platform cells. Reject path aliases, symlinks, duplicate filenames, unlisted archives, hash mismatch, incompatible ABI/tag, missing license/review reference and manifest data without actual archives. A manifest's self-declared `source` string is not supplier authentication. Keep the source archive and wheelhouse immutable during a run, and bind the manifest to an exact review commit before treating it as a release input.

From one clean exact integration commit, archive the committed `pyproject.toml` and `src/aegis`, set one fixed `SOURCE_DATE_EPOCH`, then build **two** wheel/sdist pairs in fresh environments using only `pip --no-index --find-links` with normal dependency resolution. Compare wheel and sdist bytes and SHA-256 pairwise; inspect `METADATA`, `WHEEL`, `RECORD`, `entry_points.txt`, complete `Requires-Dist` and package member list. Verify generated `aegis` points to `aegis.cli:main`; retain the full default lab dependency set. Any missing archive is a prereq skip, not a reproducible-build pass. The existing `scripts/phase5b1_build_offline.py` provides a fail-closed source-level starting point, but its manifest provenance fields alone are not independent review.

## Proposed four-cell install matrix

In each pinned image, use a disposable non-root environment with no network, no image pull, read-only root, dropped capabilities, no new privileges and a declared writable install prefix/tmpfs. Install the exact built wheel with **normal offline dependency resolution** (`pip --no-index --find-links`) into a fresh venv. No `--no-deps`, source `PYTHONPATH`, host site packages, copied libraries, preinstalled-dependency shortcuts or internet fallback. Record every distribution version, wheel archive hash, `RECORD`, console path and import graph. Run the installed `aegis` script directly; verify uninstall removes the script/distribution and creates no implicit state or service. Declare all mounts and side effects. The independent validator owns the full command oracle: at least **84 logical installed-console cases** across four cells, including defaults, signed negatives and explicit state; privacy owns the separate **68 child resource/privacy** matrix and attempted-syscall tracing. Packaging supplies exact installed artifacts and environment pins, then runs assigned cells without claiming the privacy lane's results.

Report `planned`, `attempted`, `eligible`, `passed`, `failed`, `skipped` and `inconclusive` for each cell, each build and every installed case. The current prerequisite state is **0/2 built**, **0/4 fresh installed cells** and **0/84 installed logical cases**. These are blocked/skipped for unavailable reviewed inputs, not behavioral failures. Linux CLI alpha remains **NO-GO** until independent exact-pin acceptance of every required cell and the separate privacy/syscall gate.

## Ownership and next review

This lane may change `pyproject.toml` only after Main and VAL approve a versioned compatibility diff. It owns `docs/alpha-packaging-*.md`, `scripts/alpha_packaging_*.py`, `tests/alpha_packaging/**` and `benchmarks/alpha-packaging/**`; it does not edit CLI, grant, inventory, signing or enforcement source. Next step is for VAL to freeze and hash the release oracle, then Main to review this proposal. If a reviewed offline wheelhouse or Ubuntu/Python 3.13 image is supplied through an authorized local process, run only the affected fresh disposable cells and retain the original skips and first failures.
