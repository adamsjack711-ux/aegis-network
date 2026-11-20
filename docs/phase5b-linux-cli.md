# Phase 5B observation-only Linux CLI

## Scope

`aegis` is an on-demand, offline package observer. It has no daemon, listener, broker subscription, target writer, command executor, firewall integration, mitigation privilege or network option. It does not call audit-writing `LocalAgent.evaluate`. Its supported inventory source is the ordinary-user-readable `dpkg` status database on Debian and Ubuntu. Unsupported distributions and incomplete inventories return unknown observations.

The authoritative claim is unchanged: `SignedFinding` containing `Finding.schema_version="1.0"` from `aegis.artifact`. Its original Ed25519 signature, locally pinned publisher grant, role and signed scoped revocation are checked. Matching uses the exact `InventoryItem(purl, version)` pair from `aegis.core`. A valid signature establishes origin and integrity only. It does not prove vulnerability, current independent Evidence status, reachability or authorization to act. The `mesh-events-v1` wrapper is a local file adapter, not a new shared finding schema. Unsigned research candidates and advisory JSON are rejected.

## Installation and use

Python 3.12+ is required. Build and install from this checkout with dependencies already cached for offline operation:

```sh
uv build --offline --wheel
uv venv .venv
uv pip install --offline --python .venv/bin/python dist/aegis_network-0.1.0-py3-none-any.whl
.venv/bin/aegis doctor --json
.venv/bin/aegis inventory --json
```

The wheel adds the `aegis` console entry point. Installation adds no service or post-install action. `scripts/smoke_phase5b_install.sh` performs a disposable offline wheel install, invocation and uninstall. It requires the declared build and runtime dependencies in the local cache. A cached Debian container can exercise the same wheel as an ordinary user with `--network none`, read-only mounts and no capabilities; record its exact image digest for each run.

For signed local claims, supply a JSON file containing the original signed Mesh envelopes and a separate local publisher grant file in the existing `aegis.config.load_publishers` format. The event file cannot supply its own trust grant.

```json
{"adapter_version":"mesh-events-v1","events":[{"kind":"finding","key_id":"default","finding":{"...":"original Finding 1.0 fields"},"signature":"original base64 Ed25519 signature"}]}
```

The example is a shape only; replace the placeholder with a real signed envelope. No URI is fetched.

```sh
aegis status --feed ./mesh-events.json --trust ./publishers.json --json
aegis inventory --json
aegis findings --feed ./mesh-events.json --trust ./publishers.json --json
aegis explain FINDING_ID --feed ./mesh-events.json --trust ./publishers.json --json
aegis doctor --json
```

Default invocations do not create identity or state. JSON `asset_id` is `null` and `identity_scope` is `none`. To opt in to a private persistent UUIDv4 asset ID, put the global `--state-dir PATH` option before the command. Its parent must already exist; the selected path is resolved to a canonical parent and only that directory receives `identity.json`. User-controlled ancestor symlinks and a symlink at the selected directory are rejected. The exact root-owned macOS `/var` and `/tmp` aliases to `/private` are accepted. Permissions are 0700 for the directory and 0600 for the file. The ID is neither Mesh enrollment nor an approval credential. Inventory, claims and observations are never stored. No hostname, machine ID, username, IP address or user files are collected.

## Private v2 output and interpretation

`inventory-v2`, `status-v2`, `observation-results-v2`, `exposure-observation-v2` and `doctor-v2` are private CLI output versions. They change the prior private v1 output because `asset_id` may be null and software matching is split from independent status. They do not alter signed bytes or shared Evidence, Trust, Mesh, Rapid or enforcement contracts. Consumers of v1 must migrate explicitly; the CLI does not emit an implicit v1 alias.

Every signed observation carries `publisher_authenticity="verified"`, `local_claim_status`, `software_match`, `match_reason`, `independent_status="unknown"`, `independent_status_reason="NO_VERIFIABLE_T4_T5_PROOF"` and `overall_assessment="unknown"`. `local_claim_status` can say `current-in-supplied-file`, `expired`, `future` or `withdrawn-in-supplied-file`; a local file without a withdrawal cannot prove that none exists elsewhere. No verifiable current native T4/T5 proof is accepted by this CLI version. A signed exact package match therefore remains a possible exposure lead, never confirmed protection or an actionable authorization.

The collector records installed binary name, raw Debian version, architecture, provisional `pkg:deb/<distribution>/<name>` identity, source and UTC collection time. Matching compares the full version string exactly, including epoch and distribution revision. It does not apply Debian version ordering, OSV ranges, aliases, backport rules, source-to-binary mapping or architecture qualifiers. Unsupported PURLs and range-like versions yield `software_match="unknown"`. An incomplete inventory emits no asserted package rows, and absence against it is unknown. `unmatched` means only that the signed exact version list did not match a complete supported inventory; it does not mean safe.

`findings` reports signed-claim and observation counts plus `current_exact_package_match_count`. `status` reports the same local scope and independent status. Exit 0 means the requested observation completed with complete supported inputs and no unknown local claim; it does not indicate safety. Exit 2 means incomplete or unknown local input, missing intelligence, expired/withdrawn local claim, or rejected input. Malformed or untrusted signed envelopes are rejected before observation output. JSON errors include `schema_version="observation-error-v2"` and `status="unknown"`.

## Bounds and validation

The `dpkg` file is capped at 64 MiB, each line at 16 KiB and installed rows at 100,000. The signed local event file is capped at 8 MiB and 10,000 envelopes; the trust file is capped at 1 MiB. Text output is escaped. Malicious mitigation template names, evidence URIs and summary text are data only.

Run `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_phase5b_cli.py` for focused tests. The tests cover the original five default-state commands, default failure paths, explicit identity opt-in, signed exact match with structured unknown independent status, unsupported and partial inventory, malformed/untrusted/expired/withdrawn inputs, and an offline socket guard. `scripts/phase_next_probe_cli.py` preserves the independent five-command oracle; its retained original failure under `cc2e918` remains evidence, not a candidate result. A clean candidate requires an independent offline Linux rerun with filesystem tree hashes and, if cached, syscall tracing. Without a tracer the syscall gate stays inconclusive.

`scripts/smoke_phase5b_linux.sh` uses the cached `aegis_phase4_baseline-coordinator:latest` image with `--pull never`, `--network none`, read-only root, no capabilities, ordinary UID 1000 and a disposable tmpfs. It installs the wheel in a temporary virtual environment, runs real Debian inventory, runs the frozen five-command default-state probe, and uninstalls. The image already contains an older `aegis-network` distribution, so the temporary environment force-installs the candidate wheel; `/tmp` is noexec, so Python interprets the generated console script. The test does not establish independent Ubuntu behavior or a syscall trace. Record the image digest in the run output.

`PYTHONPATH=src python scripts/benchmark_phase5b.py --output benchmarks/phase5b-observer-purity.json` measures synthetic package parsing and exact in-memory matching. The retained single local macOS/Python 3.15 run is exploratory, not a controlled performance comparison. It excludes signed-envelope verification, process startup and native RSS. Native Debian/Ubuntu matrices, broader ecosystem/version comparison, current independent T4/T5 proof, a signed Phase 5A-to-5B conversion and production integration remain outside this CLI alpha.
