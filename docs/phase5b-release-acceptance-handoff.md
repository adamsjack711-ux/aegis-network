# Phase 5B release acceptance: blocked prerequisite handoff

This branch begins at `8292e531194216a578c32c912d066f98cdbce9ea`. Product source and package metadata are unchanged. The existing `aegis = aegis.cli:main` package source is the candidate to build after supply review; **no release-eligible wheel or sdist was built here**. This is an engineering handoff, not alpha approval.

## Reviewed evidence and this run

The [Alpha release decision](alpha-release-readiness.md), [packaging proposal](phase5b1-packaging-proposal.md), [grant implementation and custody limits](alpha-grant-implementation.md), [security acceptance](alpha-security-acceptance.md), [privacy handoff](alpha-cli-privacy-handoff.md), and [independent acceptance freeze](alpha-readiness-validation-freeze.md) were read before changes. The old stat/read grant race and older 256 MiB OOM are retained failures. The integrated bounded grant reader has conditional source-level evidence, but world-writable grant modes and same-UID file custody remain release concerns.

The exact-source offline release preflight at the starting commit exited 2 before a build: `reviewed wheelhouse directory is missing or aliased`. Its [raw report](../benchmarks/phase5b-release-acceptance/preflight-attempt/release-report.json) and [machine-readable prerequisite inventory](../benchmarks/phase5b-release-acceptance/prerequisites.json) record the attempted and skipped denominators. A read-only search of `/private/tmp`, the local uv cache and repository worktrees found historical Aegis wheels, but no original Hatchling 1.33.0, Linux cryptography, or Linux pydantic-core archive. This search does not prove absence in other locations. Extracted cache contents, installed distributions and historical Aegis wheels were excluded from release supply. No dependency was downloaded and no image was pulled.

Read-only, non-root, network-disabled container probes confirmed the cached image IDs in the prerequisite inventory and observed Debian 13/Python 3.12.16, Debian 13/Python 3.13.18 and Ubuntu 24.04/Python 3.12.3. No cached Ubuntu 24.04/Python 3.13 image was identified. The three probes ran with `--pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534`; they only printed OS/Python/pip information. **They were not installation tests.**

Focused source checks on the reference tree passed **52**, with **one retained historical xfail**: `tests/test_alpha_linux_release.py`, `tests/packaging_phase5b1`, `tests/alpha_grant/test_grant_reader.py`, `tests/test_phase5b_cli.py` and `tests/cli_safety_phase5b2`. The original-evidence verifier independently confirmed **44 prior files plus 10 later files** with manifest SHA-256 `03f356012fcdc599c8cb423c57126482a639b3b2f92e7a33d775e84376f4434`. These are source and retained-evidence checks, not installed-console acceptance.

## Release matrix and limits

| Cell | Fresh dependency resolution | Installed-console cases | 256 MiB and attempted-effects evidence | Uninstall |
| --- | --- | --- | --- | --- |
| Debian 13 / 3.12 | Skipped: reviewed wheelhouse absent | 0 attempted | 0 installed children/traces | 0 attempted |
| Debian 13 / 3.13 | Skipped: reviewed wheelhouse absent | 0 attempted | 0 installed children/traces | 0 attempted |
| Ubuntu 24.04 / 3.12 | Skipped: reviewed wheelhouse absent | 0 attempted | 0 installed children/traces | 0 attempted |
| Ubuntu 24.04 / 3.13 | Skipped: wheelhouse and image absent | 0 attempted | 0 installed children/traces | 0 attempted |

Frozen totals remain **0/2** reproducible build pairs, **0/4** fresh installation cells, **0/84** installed-console logical cases, **0/68** installed resource/privacy children, and **0/4** uninstall checks. Non-root image availability was confirmed, but non-root installed operation and read-only-root installed behavior are unverified. Zero unrequested persistent writes and zero unexpected network attempts are unverified on an installed console. Prior source-only privacy measurements under a hard 256 MiB limit and source-only syscall traces remain diagnostic; their different pin and installation path cannot score this matrix. The 100,000-row installed ceiling remains ≤256 MiB RSS, ≤5 seconds wall and CPU, ≤64 MiB output, three hard-cap completions per cell, and zero OOM.

Source tests retain exact `(purl, version)` package matching and `independent_status=unknown` without independent Evidence. This handoff changes neither behavior. The installed JSON/human negative matrix, grant custody, default and explicit persistence, attempted syscall effects, and independent exact-pin review remain open.

## Required offline handoff

Provide a separately reviewed directory containing original upstream wheel archives and `manifest.json` plus `provenance.json` in the format required by `scripts/alpha_linux_release.py`. Every build and transitive runtime archive needs an exact version, original SHA-256, wheel tags, supplier/custody record, license and independent review commit. Include Hatchling 1.33.0 and its build dependencies, all Linux-compatible cryptography and pydantic-core wheels for both Python versions, and the complete resolved dependencies of the unchanged default lab set. Supply a locally cached, reviewed Ubuntu 24.04/Python 3.13 image. The manifest must bind archive bytes and provenance; a self-authored provenance label alone is insufficient.

From this worktree, after those inputs exist, use the exact candidate commit printed by `git rev-parse HEAD`:

```sh
python3 scripts/alpha_linux_release.py \
  "$(git rev-parse HEAD)" \
  /absolute/path/to/reviewed-original-wheelhouse \
  /absolute/path/to/empty-output \
  --image ubuntu-2404-py313=reviewed-local-image
```

The runner performs two offline builds and fresh non-root installs with normal offline dependency resolution, a small generated-console smoke and uninstall. The independent frozen **84-case** console matrix, **68-child** installed resource/privacy matrix, mounted-tree snapshots, syscall-level attempted-effects tracing, and exact-pin independent review are additional mandatory work; a `matrix-passed` runner status alone is insufficient for alpha approval. Keep source-only diagnostics and failed attempts as separate evidence. No master merge or alpha declaration follows from this handoff.
