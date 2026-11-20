# Phase 5B final-pin cache-backed independent supplement

This supplement **adds** evidence to `phase-next-alpha-5b-final-review.md`; it does not replace the retained default-cache Hatchling failure. Exact source remains clean `feat/phase5b-alpha-astra` `876988ba30abed9c2954668d02b2c4c13f84e50f`. All work used disposable localhost/container fixtures, cached images and throwaway signing material, with `--offline`, `--network none` and `--pull never`.

## Offline cache and wheel provenance

The owner supplied local cache `/private/tmp/aegis-phase5b-uv-cache`. VAL-D independently hashed its 1,635 regular files and 37 symlinks into `benchmarks/phase-next-alpha-astra/5b-final-backend-cache-manifest.json` (SHA-256 `ef2506f559f38e8c9840272604015f001dcdc592cf23ab73994ac07ea302ee04`); the original manifest matched byte-for-byte after all builds. Extracted Hatchling 1.33.0 `RECORD` SHA-256 is `e3b5d3ab14063323c18d7edb898bc0975a3634c636394030766a44798f481df0`; 72/72 recorded package-file digests and sizes verified, with zero missing or mismatched entries. This is an **integrity snapshot**, not independent publisher authentication or a reviewed software supply chain.

VAL-D copied the cache to a private disposable directory and built from `git archive 876988b`; the original cache was not the build's writable cache. `UV_CACHE_DIR=<private copy> uv build --offline --wheel` succeeded. Its default timestamp wheel SHA-256 was `0a14026c9b98b8d356ef771b2faac9baa998888a5c19a6a6f6f6269f569d9dd3`. Zip member names and contents matched the owner wheel, but Zip timestamps differed. With `SOURCE_DATE_EPOCH=1735689600` (2025-01-01 UTC), the exact-source wheel SHA-256 became **`7f4701b30303f47e645374f6d0ee085e74e927bd06dfc26da533ae5bd60a8698`**, matching the owner's reported wheel byte-for-byte. It contains 70 members and `[console_scripts] aegis = aegis.cli:main`. The earlier offline build without this supplied cache exited 2; both results remain retained.

## Installed direct-console matrix

Used the independently rebuilt wheel, forced local installation to avoid a same-version preinstalled system package, and invoked generated `/tmp/alpha/bin/aegis` **directly**. Both images were non-root UID 1000, one CPU, 256 MiB for the command matrix, read-only root, no capabilities/new privileges, no network and no image pull. Debian 13/Python 3.12.16 image `sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e`; Ubuntu 24.04/Python 3.12.3 image `sha256:706130e55f22d2c81e272e0bf987be194bbbca232ab554b440f3116e74b00b60`.

| Fixture | Frozen default logical cases | Default JSON/human invocations | Extra signed negatives | Explicit-state controls | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Debian | 12/12 | 24/24 | 5/5 | 4/4 | **33/33 pass** |
| Ubuntu hybrid | 12/12 | 24/24 | 5/5 | 4/4 | **33/33 pass** |

Thus the frozen **24/24 logical defaults and 8/8 explicit controls** were independently exercised, with 48 default format invocations and 10 additional negatives. Default calls made **zero changes** to the harness's before/after path, mode, size, mtime and content-digest trees under `/tmp` and `/var/lib/dpkg`; root was read-only. The only intended explicit creation was `chosen/identity.json` under requested state, with symlink controls rejected. Signed current exact matching produced `publisher_authenticity=verified`, `software_match=matched`, `local_claim_status=current-in-supplied-file`, `independent_status=unknown`, `overall_assessment=unknown` in both images. Direct console creation and uninstall cleanup passed once per image.

The Ubuntu fixture borrowed a SHA-256-pinned 57 MiB Debian Python dependency archive (`25c1cfc8a10b7032e4ef2779b5eee262d41eca8620cbdb088d97912d274bf37e`). This proves Ubuntu execution with that local hybrid dependency set; it does **not** prove independent Ubuntu runtime-wheel resolution or a fresh-host install. No syscall tracer was cached. Writable-tree snapshots and network isolation do not prove zero attempted `connect`, `exec` or privilege syscalls, nor detect writes to any unobserved writable mount. The package still bundles non-observer modules even though the tested CLI import graph loads none of the protected-writer modules.

## Resource envelope and confirmed memory limit

Each resource run used fresh direct CLI processes on synthetic `dpkg` status inputs of 100, 10,000 and 100,000 rows, three trials per size, one CPU. At **512 MiB**, Debian and Ubuntu hybrid each completed **9/9** without default state creation. For 100,000 rows, Debian wall p50/p95/p99 was **1050.423/1072.237/1074.176 ms** and peak RSS **297.805 MiB**; Ubuntu hybrid was **1091.338/1109.027/1110.600 ms** and peak RSS **295.883 MiB**. Raw CPU and all size-level samples are retained in `5b-final-*-rusage-512m.json`. Three-sample percentiles are descriptive, not a broad capacity estimate.

At **256 MiB**, Debian's 100- and 10,000-row cases passed 3/3 each, but all **3/3 100,000-row CLI children exited -9** (process peak RSS about 241 MiB). A repeat read of that container's cgroup `memory.events` changed `oom_kill` from **0 to 3**, confirming OOM kills. At 512 MiB the same 100,000-row workload passed 3/3 with about 298 MiB peak RSS. The 256 MiB result is a measured resource failure, not an omitted case; it requires a declared resource envelope or bounded streaming implementation before a 256 MiB operational claim.

## Gate decision

**GO for the independently reproduced offline wheel, direct-console 24+8 laboratory matrix, and 512 MiB descriptive resource runs. NO-GO for installable Linux CLI alpha release** under the frozen full acceptance because syscall-level attempted-effect evidence, independent Ubuntu dependency provenance and a declared resource envelope remain open. The 256 MiB 100,000-row OOM is a demonstrated limitation. No production distribution, native T4/T5 validation, local approval or protected-write authority follows from these tests. Original failures and the earlier cache-miss review stay visible.
