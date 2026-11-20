# Phase 5B Linux observation CLI owner proposal

Reviewed at Phase 4E parent `ee739cacfaa3f81a0994b4d7802fd2943c067d86` on `feat/phase5b-linux-cli`. This is an interface and test proposal. The branch adds no CLI executable or package dependency in this preparation step. Frozen preparatory contract at `docs/phase5b-cli-contract.md` in `docs/phase4f-phase5a-preparation` commit `880ce5f18d9fbe0522373bc99d89e0a7ce21e399`

## Existing code and boundary

`pyproject.toml` builds a Hatchling wheel for `src/aegis`, requires Python 3.12+, and has no console entry point. `src/aegis/core.py` uses an exact `(purl, version)` set for `InventoryItem` and couples a positive result to local lab authorization, template policy and a durable audit. `src/aegis/artifact.py` validates strict signed Finding 1.0 bytes and lists enumerated affected versions. There is no Linux package database adapter, ecosystem version comparator or observation-only CLI. Reusing `LocalAgent.evaluate` would write an audit decision and produce `allow_dry_run`, so the CLI needs a separate read-only observation service. Import the strict artifact parser and signature verifier only when the operator supplies a local trust root; a research advisory remains labeled unverified research.

## Owned implementation surface

Agent 3 proposes a new `src/aegis/observe/` package for `cli.py`, `inventory.py`, `matching.py` and output models, with `tests/observe/` and disposable Linux fixture files. An eventual `[project.scripts]` entry in `pyproject.toml` needs integration review because it changes package installation. Agent 3 does not edit `src/aegis/core.py`, `phase3c.py`, `agent_runtime.py`, `mitigation/`, Evidence, journal, owner home or broker code. Agent 2 owns the optional research-candidate format. Agent 4 owns the negative security and packaging oracle.

## Offline source and inventory

The first proposed adapter reads the installed package paragraphs in a bounded, local Debian-family `/var/lib/dpkg/status` snapshot using ordinary user permissions. It records a content digest, read time, adapter version, OS-release identity, package name, architecture, epoch/upstream/revision text and whether the status entry says installed. It reports unreadable, malformed, duplicated or changing input as partial inventory. The adapter does not execute a package-manager command, scan hosts or follow an advisory-provided path. Inputs are local files selected by the operator. The scanner opens an allowed inventory path, limits bytes and package count, and refuses non-regular files. A second RPM adapter needs an independent review of database access and version semantics.

A host-local snapshot ID is a digest of canonical normalized inventory plus adapter version and source digest. It is not a stable machine identity. Do not include hostname, account name or inventory path in default JSON. The CLI reports the package ecosystem, name, raw version and architecture. Package URL normalization is optional until distro namespace and qualifier handling have golden fixtures.

## Matching and uncertainty

The initial matcher supports an explicit, enumerated exact version list in a locally supplied Finding 1.0 or a Phase 5A advisory candidate with exact package identity. It does not reinterpret OSV ranges as exact matches. A package with a different exact version is `unmatched` only for that exact-list claim. A range, alias, distro backport, missing epoch/revision, unknown architecture or unrecognized ecosystem is `unknown` with a stable reason. Source age and withdrawal are reported separately from version match. A stale, unsigned or research-only advisory cannot be labeled verified. Native T4/T5 status is shown only with a separate verifiable local proof and trust roots; otherwise `status=unknown`.

An observation is an assessment of inventory against a claim, not a Rapid policy decision. Its `matched` value never means exploitability or authorization. For a partial inventory, a present exact package may yield a package-level match while the overall snapshot remains partial. An absent package in a partial snapshot yields `unknown`.

## Proposed commands and output

`aegis-observe inventory --format json` reads the local package database and emits one `InventorySnapshot/v1`. `aegis-observe assess --inventory SNAPSHOT.json --input CLAIM.json --format json` consumes pinned local files and emits one `ExposureObservation/v1` per relevant identity. `--format text` produces concise operator output using the same result and reason codes. Both commands default to offline behavior and never accept a network URL as an input fetch target.

A proposed stable JSON object contains `schema_version`, `cli_version`, `snapshot_id`, `captured_at`, `inventory_complete`, `source_digest`, `claim_digest`, `claim_kind`, `claim_source`, `claim_status`, `package` with ecosystem/name/version/architecture, `comparator`, `result`, `reason_code`, `uncertainty` and `checked_at`. Each `result` is `matched`, `unmatched` or `unknown`. `claim_status` is `verified`, `research`, `stale`, `withdrawn` or `unknown`, with `verified` requiring checked local proof. Empty `uncertainty` is permitted only when all fields needed for the stated exact match have been checked. The stable JSON writer sorts keys and emits no absolute local paths or secret material.

Proposed exit codes are `0` when observation completed with no unknown entries, regardless of exposure result, `2` when inventory or claim status is partial or unknown, `3` for invalid input/schema or an unsupported mandatory comparator, and `4` for operational failure such as an unreadable source. These codes describe observation quality. A future optional policy to exit nonzero on exposure needs a separate reviewed CLI version. Text output must say `possible exposure` for a match and include the claim source and uncertainty. It must not say a host is protected or safe.

## Threat and packaging checks

Advisory and package strings are bounded data. They cannot select import paths, subprocess commands, file paths, network endpoints, templates or output filenames. Reject path traversal in input references and oversized files before parsing. Use strict JSON models with unknown fields rejected, no YAML deserialization and no shell. The installed wheel adds no service, post-install hook, writable system file or credential. A fixture run checks imports and open files, denies network at the test namespace, and confirms zero native target writes and zero mitigation or broker calls. Supplying a signed Finding does not bring in publisher approval or local write authority.

## Independent container matrix and release gate

The validator should pin image digests at execution time and publish them with the raw manifest. Do not invent digest values in this proposal. Use a disposable Debian stable container for a normal installed-package database, a Debian/Ubuntu fixture with an unreadable or truncated database, a minimal container with no package database, and an RPM-family fixture only for explicit `unsupported` or `unknown` until its adapter is approved. Run as a non-root UID with no network, a read-only root filesystem, a bounded writable temporary directory and no host mounts beyond test fixtures. Install the wheel, invoke both commands twice, compare canonical JSON, then inspect file and network activity.

Golden cases include an exact match, a different exact version, ecosystem mismatch, missing package, epoch/revision ambiguity, unsupported range, stale/withdrawn source, malformed or oversized JSON, prompt-injection text, symlinked database path and partial inventory. Include at least one version with Debian epoch and one with a distro backport string. Report case counts by `matched`, `unmatched`, `unknown` and invalid. Measure elapsed p50/p95/p99, CPU and peak RSS at 100, 10,000 and 100,000 synthetic package rows over repeated runs, with parser errors and censored runs included in denominators. Validate the wheel on every claimed Python minor version and named Linux distribution before calling it installable.

## Decisions needed before implementation

1. Confirm Debian-family `dpkg` status as the first supported adapter and the exact distribution/image matrix. RPM remains unclaimed until its read access and comparator are tested.
2. Choose whether PURL mapping includes distro namespace and architecture qualifier, and provide golden cross-distribution package identities. The current Rapid exact `purl,version` pair cannot decide this.
3. Decide who supplies a trusted offline advisory bundle and which source signatures and withdrawal proofs can be checked locally. A Phase 5A research candidate has only research provenance.
4. Decide whether the first CLI supports a verified signed Finding at all or reports research/advisory snapshots only. If signed findings are supported, provide a separately reviewed local trust-root file format with rotation and expiry behavior.
5. Define approved file-size, package-count and parser time limits based on container measurements. Keep unsupported cases `unknown` until evidence supports a tighter claim.
