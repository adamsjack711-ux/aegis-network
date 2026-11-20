# Phase 5B-R owner design and reconciliation

## Pin and review boundary

This read-only design review uses clean `feat/phase5b-release-r-astra` at
`d15a3a756b8066c5cb2d98665662220e52f4a7d6`. The prior owner
implementation is `876988ba30abed9c2954668d02b2c4c13f84e50f` with
owner-only raw evidence added at `7bd8639`; the separate packaging candidate
is `0df40c9`. Both diverge from common `3bfd2abe`. The independent alpha
NO-GO and cache-backed supplement are retained in `b81dac8` and `9c54a14`.
No implementation from either branch has been copied into this worktree.
VAL-R's new acceptance freeze is pending; this document is a proposal.

## Reconciliation before implementation

| Boundary | `876988b` private observer candidate | `0df40c9` separate candidate | Decision needed |
| --- | --- | --- | --- |
| Publisher grants | `observer_grants.py` reads bounded local grant JSON and delegates role, time, revocation and scope authorization to the frozen `TrustStore`. Golden tests compare decisions with `config.load_publishers`. Shared config is unchanged. | Moves the loader body from shared `config.py` to `publisher_config.py` and reexports it; the CLI imports the new module. | Prefer a private bounded reader if shared-code freeze remains. Require negative parity vectors and no `core` import. Review the alternative's shared config movement and full regression before any adoption. Do not combine both loaders. |
| Build and dependencies | Restores the console entry point with Hatchling. Keeps the full lab dependency list and bundles enforcement modules despite an observer-only runtime import graph. Offline owner and cache-backed independent builds succeeded with a supplied integrity-snapshotted cache. | Pins setuptools 84.2.1; narrows required dependencies to cryptography and pydantic, moves lab dependencies into an optional extra. It still packages Aegis modules together. | Choose one reviewed offline build path from exact source. Confirm fresh Ubuntu and Python 3.13 runtime wheels, generated console, install/uninstall and complete lab regression. A change in the package's default dependencies needs integration review. |
| Output/authority | Signed Finding 1.0 and exact local package match remain separate from `independent_status=unknown`; no protected write follows. | Same source-level CLI intent; packaging changes do not establish independent Evidence status. | Preserve frozen signed bytes, local-grant semantics, private v2 observation schema and zero enforcement authority. |
| Tests | Adds grant rotation, duplicate publisher/key rejection, malformed top-level input, bounded errors, import graph and Linux matrix/resource scripts. | Its raw `validation.json` reports separate alpha tests, but does not substitute for the frozen independent denominator. Its diff from the common base also removes `tests/test_phase5a_alpha_eval.py`; never copy that deletion. | Retain all original failures and independently rerun at one exact integrated pin. |

The two grant approaches both seek to remove the `cli -> config -> core`
import path. The private reader changes less shared code but duplicates parsing;
the extracted shared reader reduces duplication but changes a shared module.
Neither packaging route establishes an observer-only wheel or proves fresh
Ubuntu dependency availability. No external network or production interface
is needed for these decisions.

## Measured 100,000-package RSS bottleneck

The retained independent cache supplement measured approximately 298 MiB
peak RSS at 512 MiB and confirmed three OOM kills under a 256 MiB cgroup for
the 100,000-row CLI. I ran a separate **single-run diagnosis**, not an
accepted benchmark, on the clean `d15a3a7` source in cached Debian Linux
arm64/Python 3.12.16, non-root UID 1000, one CPU, read-only root, 512 MiB,
`--network none`, `--pull never`, and disposable `/var/lib/dpkg` tmpfs. The
synthetic status contained 100,000 installed rows in the resource-harness
format. `/proc/self/status` and `resource.getrusage` gave:

| Stage | Current VmRSS | Process peak RSS |
| --- | ---: | ---: |
| Input written | 17,708 kB | 17,664 kB |
| `collect_snapshot(None)` complete | 73,652 kB | 79,828 kB |
| 100,000 `Package.as_dict()` rows retained | 89,892 kB | 89,708 kB |
| `json.dumps(..., sort_keys=True, indent=2)` complete | 136,044 kB | **308,588 kB** |

The JSON string was 43,888,912 bytes. A second one-run diagnostic with the
same rows and `json.dump(..., sink, sort_keys=True, indent=2)` instead of
bulk `json.dumps` completed under a **256 MiB** cgroup at **89,956 kB peak**.
The bulk pretty-JSON construction in `cli._emit` is therefore the measured
primary spike. The intended narrow change after the freeze is incremental
JSON output with a final newline while preserving byte-for-byte output,
structured errors, zero default writes and all trust checks. A complete
installed-console 3-trial run on Debian and fresh Ubuntu must establish the
actual new envelope; the diagnostic cannot by itself clear the <=256 MiB gate.

## Post-freeze acceptance proposal

1. Freeze one exact source pin and immutable offline build inputs. Build twice
   from an archive; compare wheel bytes, metadata, member list and console
   entry point. Keep both prior backend/cache failures as evidence.
2. Install the generated console offline on real Debian and **fresh** Ubuntu
   with independently available runtime dependencies. Run the 24 default
   logical cases, JSON/human variants, eight explicit-state controls, signed
   negatives and install/uninstall checks. Run Python 3.13 as a separate
   compatibility arm; `requires-python >=3.12` must not be overclaimed.
3. At 100, 10,000 and 100,000 package rows, run at least three fresh
   processes per distro and interpreter. Record wall/CPU/RSS/output bytes and
   cgroup memory events. Require the published <=256 MiB 100,000-row target
   only after direct installed-console measurements, including human output.
4. Record writable-tree before/after hashes and syscall-level attempted
   network, subprocess, privilege and write effects using only reviewed,
   cached tracing tools. If a tracer is unavailable, mark that arm incomplete.
   Keep explicit-state writes within the canonical selected directory and
   challenge ancestor/final symlinks and concurrent replacement.
5. Compare the observer's private grant parser against the frozen loader for
   legacy/structured inputs, duplicate publisher+key rejection, legitimate
   two-key rotation, malformed/oversized input, roles, time, revocation and
   scope. Run the import-boundary test and full integrated regression before
   any packaging or loader selection is accepted.

SignedFinding 1.0, exact `InventoryItem(purl, version)`, native T4/T5,
shared config/trust/core and all protected-writer contracts remain frozen.
The CLI remains offline observation only, with independent Evidence status
unknown and no approval, mitigation or production integration.
