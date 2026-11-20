# Independent Linux alpha supply review

**Exact owner evidence pin:** `test/linux-alpha-supply-prep` at `c9f2c8ea5028a7b50e8806aead00b8d99533e46e`. It includes supply staging `777f4304`, build and trace controls `f942939e`, custody probes `c3b1e1f`, and the isolated executable venv mount `7660f986`. **Exact CLI candidate:** `fc4a17bc6f9f0c289a645c4fb7006c999ba90e99`, descendant of reviewed `0045e88`. The owner worktree was clean at opening inspection; while this review was being finalized, it acquired separate uncommitted harness changes. Those changes are excluded from this verdict. No owner file was edited and no binary was downloaded in this review.

## Reviewed byte binding and disposition

- `supply-prep/manifest.json` SHA-256 **`39653937e83dd3d53a4becf9009c9a87234dddd7cf07bfb263451ae5cfed3784`**.
- Draft `supply-prep/provenance.json` SHA-256 **`e1b4e383f76342651061800c25cb8981456dcdc37763ca2f8f6f78ae53caa530`**, with `review_commit: null`.
- The matching files in `../alpha-fc4a-inputs/wheels` were byte-identical at review time. Bind the final provenance bytes separately after filling the exact reviewer commit.

**GO for exact archive and laboratory observation-tool input appraisal. Conditional GO to start the isolated installed validation matrix only after the revised harness independently binds this reviewer commit, the manifest hash and final provenance hash. CLI alpha release remains NO-GO.** This establishes official published byte identity under PyPI, Astral and Debian metadata trust assumptions; it does not audit package code or prove production safety.

The current `validate_provenance()` checks only that `review_commit` is *some* existing Git commit. In a disposable copy, setting it to unrelated old `8292e53` was accepted for all 32 wheels. The current null value correctly fails with `OfflineBuildError: exact reviewer commit is required`. This review commit alone cannot make that validator safe. The integration lead's proposed exact reviewer/manifest/final-provenance binding requires a separate exact-pin review before scored validation begins. The original two hashes above are fixed inputs to that review.

## Independently verified supply

| Input | Result | Limit |
| --- | --- | --- |
| 32 PyPI wheels | 32/32 local SHA-256 matched manifest and provenance; ZIP integrity, embedded distribution/version and tags matched; no missing or extra wheel. Scoped read-only requests to **29** official `pypi.org` release JSONs matched 32/32 exact filenames, SHA-256 and `files.pythonhosted.org` URLs. | PyPI publication identity; no package code or complete license audit. |
| Two Astral CPython archives | 2/2 official GitHub release-asset JSON records matched exact names, digests and URLs; both existing local tarballs matched. | Modified Ubuntu image construction is still a lab build assumption. |
| Debian tracer | Local `gpgv` verified InRelease with Debian 13 stable release signer `41587F7DB8C774BCCF131416762F67A0B2C39DE4`, matching the [Debian archive key listing](https://ftp-master.debian.org/keys.html). Independently traced signed InRelease SHA-256 `0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675` → arm64 `Packages.xz` digest/size → unique `strace 6.13+ds-1` package digest/size → extracted `usr/bin/strace` SHA-256 **`e4f0c42a07574df2fc6b353f5bc24423099d8c896cee72c605671d878fedeb5a`**, matching the local tracer. | Approved only as a pinned lab observation tool; actual installed-console trace classification is unrun. |

Only official JSON metadata was fetched in this independent review; no wheel, CPython archive or `.deb` was downloaded. The PyPI checker limits destinations, response size, redirects and proxies. The tracer audit read only retained signed metadata and archives. The supplying keyring's authenticated release signer was checked against the official Debian fingerprint; the remaining trust assumption is Debian's archive key custody and public web metadata.

Two separate owner build reports and actual artifact files matched exact `fc4a17` outputs: wheel SHA-256 **`28943894bfe543338a353a538fac3a26e9fd552df730e4cb83921953503727e5`**, sdist **`3aeb30b7c3c9befd89b5ecc3cf71b3c3b14e63b45662e45b902544eb6cb61908`**. Both report files were byte-identical. I did not independently rebuild them; the frozen reproducible-build gate must be checked again by the scored validation run.

## Environment and custody

Owner logs show four fresh non-root UID 65534 venv requirement resolutions and `pip check` successes with exact image IDs, `--pull=never`, `--network=none`, read-only root, dropped capabilities and no new privileges. Initial three noexec failures and one Ubuntu missing-ensurepip failure remain under `supply-prep/initial/`. The revised launch confines executable tmpfs to `/tmp/venv`; `/tmp` remains noexec and both mounts nosuid/nodev. I independently reran the four local harness tests: **4 passed**. These preparation probes are not installed `aegis` runs.

Four retained syscall control logs independently show an allowed temporary write, an `EROFS` host write denial, a failed loopback connection, a child `/bin/true` exec and denied `setuid(0)` with `EPERM`. The control script deliberately attempts these effects and is not the product. The tracer is mechanically capable of observing them in these lab images; exact installed-console behavior remains unmeasured.

Four disposable public-grant probes show read-only `/grants` mounts, matching public digests and non-root consumer access. The host issuer and custodian were the same UID 501; same-UID host mutation remains inside a trusted operator boundary. These probes did not run an installed CLI or issue the actual signed release fixtures. The scored matrix must check actual grant ancestors, ACLs, custody, digest and file-read race conditions. No real credential was used or retained.

## Frozen gates

This preparation scores **0/4 installed cells, 0/84 installed console logical cases, 0/68 installed resource/privacy children, 0/4 installed uninstalls and zero classified installed-console syscall traces**. The historical grant race xfail, 256 MiB hard controls and independent final-pin release decision remain open. SignedFinding 1.0, exact InventoryItem matching and native T4/T5 remain unchanged; no production or distributed enforcement is authorized.

Raw independent audits, negative reproduction and official metadata checker are in `benchmarks/phase5-alpha-validation/linux-supply-prep-*`. Retain `benchmarks/linux-alpha-fc4a/preflight/release-report.json` and all `supply-prep/initial` failures.
