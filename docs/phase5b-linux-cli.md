# Phase 5B — observation-only Linux CLI

## Scope and compatibility

`aegis` is an on-demand local observer. It has no daemon, listener, network client, broker subscription, target writer, command executor, firewall integration or mitigation privilege. It does not call `LocalAgent.evaluate`, which records a lab policy decision. The first supported inventory source is the ordinary-user-readable `dpkg` status database on Debian and Ubuntu. Fedora/RHEL and other distributions produce an incomplete inventory and exit status 2.

The authoritative signed claim remains `SignedFinding` / `Finding.schema_version="1.0"` in `aegis.artifact`; the authoritative Rapid comparison remains exact `InventoryItem(purl, version)` in `aegis.core`. `MeshV1Adapter` checks locally pinned publisher role and key, the original Ed25519 signature, timing and exact scoped signed withdrawals. It does not alter signed bytes, TrustStore, Evidence, enrollment, audit, Mesh or enforcement interfaces. A signed claim is still only a lab-scoped publisher claim. It is not proof of vulnerability, external reachability, current independent Evidence status or authorization to act.

The `mesh-events-v1` wrapper is a **local CLI input adapter**, not a shared finding schema. `inventory-v1` and `observation-results-v1` are provisional private CLI JSON outputs pending Main Astra's Phase 5A/5B schema freeze. Research candidates and unsigned advisory JSON are not accepted by `aegis findings`.

## Install and use

Python 3.12+ is required. Build and install from this checkout with the existing project build system:

```sh
uv build --wheel
uv venv .venv
uv pip install --python .venv/bin/python dist/aegis_network-0.1.0-py3-none-any.whl
.venv/bin/aegis doctor
.venv/bin/aegis inventory --json
```

The wheel adds the `aegis` console entry point; installation adds no service or post-install action. To uninstall, run `uv pip uninstall --python .venv/bin/python aegis-network`. `scripts/smoke_phase5b_install.sh` builds a disposable wheel, installs it with declared dependencies in a temporary virtual environment, invokes the CLI, checks the read-only doctor response and uninstalls it. The smoke script uses `uv --offline` throughout and requires build/runtime dependencies to be present in the local cache beforehand.

For offline claims, prepare a local JSON file whose `events` are the original signed Mesh event envelopes, and a separate locally provisioned publisher grant file in the existing `aegis.config.load_publishers` format:

```json
{"adapter_version":"mesh-events-v1","events":[{"kind":"finding","key_id":"default","finding":{"...":"original Finding 1.0 fields"},"signature":"original base64 Ed25519 signature"}]}
```

The example shows the wrapper shape; replace the placeholder finding with an actual signed envelope. No key or trust grant is accepted from the event file.

```sh
aegis status --feed ./mesh-events.json --trust ./publishers.json
aegis inventory
aegis findings --feed ./mesh-events.json --trust ./publishers.json --json
aegis explain FINDING_ID --feed ./mesh-events.json --trust ./publishers.json
aegis doctor --feed ./mesh-events.json --trust ./publishers.json
```

The observer never fetches a URI. All file paths are operator-supplied local paths. There is no network opt-in in this release. `--state-dir` is a global option placed before the command; it changes where the local asset ID is stored.

## Inventory and observation semantics

The collector reads `/etc/os-release` and `/var/lib/dpkg/status` only. It accepts `ID=debian` or `ID=ubuntu`; derivatives are unsupported until their identity mapping is reviewed. It records installed binary package name, raw Debian version, architecture, a provisional `pkg:deb/<distribution>/<name>` identity, source, UTC collection time, opaque asset ID, confidence and limitation. It ignores removed packages. It compares the complete raw version string exactly, including epoch and distribution revision. It does not apply Debian version ordering, OSV ranges, aliases, backport rules, source-to-binary package mapping or architecture qualifiers. Range-like signed versions and unsupported PURLs yield `unknown`.

`inventory` includes a snapshot digest of the normalized rows and completeness state. Malformed, duplicate, unreadable, missing, oversized or unsupported input yields `inventory_complete=false`, no asserted package rows, `inventory_reason` and exit 2. A signed claim against such a snapshot yields `unknown / INVENTORY_INCOMPLETE`; it cannot become an unmatched absence claim. A complete snapshot with no exact installed version yields `unmatched / NO_EXACT_PACKAGE_VERSION`, which means only that this exact version list did not match. It does not claim the host is safe. A current exact match yields `matched / EXACT_PACKAGE_VERSION` and means possible exposure only. Stale and signed-withdrawn claims remain visible as `unknown / CLAIM_NOT_CURRENT` with `claim_status` recorded. Missing current independent Evidence and T4/T5 status remains an explicit uncertainty.

`findings` reports `claim_count`, `finding_count` (current exact matches) and `observation_count` (all signed claims observed). `intelligence_scope` is always `supplied-signed-events-only`; an empty or incomplete local bundle never proves absence of vulnerabilities. `explain` looks up the current local observation ID. Exit 0 means the requested observation completed with complete inventory, at least one supplied signed claim and no unknown claim. Exit 2 means incomplete inventory, unknown claim status, no supplied claim, absent intelligence for `status`, or invalid/untrusted local input. This exit code is about observation quality, not exploitability or a mitigation decision. JSON errors include `status: "unknown"`.

The only persistent CLI state is a random UUIDv4 asset ID in `${XDG_STATE_HOME:-~/.local/state}/aegis/identity.json`. Its directory must be mode 0700 and file mode 0600; symlinks and group/world-readable state are rejected. The ID is not the Mesh deployment UUID or enrollment credential. Inventory, claims and observations are not stored. No hostname, machine ID, username, environment, user files or IP address is collected. A user can supply `--state-dir` to keep or remove this ID with their chosen workspace.

## Bounds, verification and integration dependencies

The collector caps the status file at 64 MiB, each line at 16 KiB and installed rows at 100,000. The local event file is capped at 8 MiB and 10,000 envelopes; the trust file is capped at 1 MiB. Output is escaped for terminal display. All matching uses an in-memory exact lookup. This limits work from local input size, though the current signed event parser still builds the bounded JSON document in memory. A malicious signed `mitigation_template`, evidence URI or text field is data only and cannot select a path, subprocess or network target.

Focused tests: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_phase5b_cli.py`. They cover Debian/Ubuntu fixtures, unsupported distro, package identity and raw-version matching, malformed/missing inventory, partial/unknown, offline operation, private identity, tampering, malformed event fields, expired findings and scoped withdrawal. The disposable wheel installation and uninstall smoke passed on macOS/Python 3.15. A second smoke installed the wheel in cached image `aegis_phase4_baseline-coordinator@sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e` (Debian, Linux arm64, Python 3.12.16), ran as non-root UID 1000 with `--network none`, read-only root, 128 MiB temporary storage, 256 MiB memory limit, one CPU, no capabilities and no new privileges. `aegis inventory --json` reported a complete snapshot of 87 installed packages; uninstall removed the CLI entry point. This validates that cached image, not the full Debian/Ubuntu release matrix. An independent Ubuntu runtime and native RSS benchmark remain open.

The synthetic benchmark is `PYTHONPATH=src python scripts/benchmark_phase5b.py --output benchmarks/phase5b-local-observer.json`. One local macOS/Python 3.15 run measured 1,000 packages/100 normalized claims at 520.42 ms wall, 102.72 ms CPU and 0.68 MiB Python peak allocation; 10,000 packages/1,000 claims at 2,375.01 ms wall, 902.53 ms CPU and 6.12 MiB. The figures exclude signature parsing, process startup and native allocator RSS, and do not establish Linux performance. See the raw JSON for inputs and denominators.

Main Astra must finalize the Phase 5A finding and Phase 5B inventory/observation schemas before any shared serialization commitment. The integration review must decide the Debian/Ubuntu PURL namespace and architecture handling, whether package source mapping and a raw source digest are needed, how signed bundle completeness and current withdrawals are established, and whether a future research candidate can be displayed without being promoted to a signed finding. No adapter here confers local policy approval or target authority.
