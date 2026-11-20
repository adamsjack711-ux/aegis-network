# Phase 5B-2 explicit-state safety review

Source reference: `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`. Independent successor freeze: `0960e6f43af83b221da47e873cc64a9fe899fca7`. This change is confined to `src/aegis/local_observer.py`; SignedFinding 1.0, `InventoryItem(purl, version)`, Mesh signature/grant/revocation interpretation, private observation output and native T4/T5 are unchanged.

## Failed first, then repaired

`benchmarks/phase5b2/failed-first-state-races.txt` reruns the new tests against the frozen baseline module, not the candidate. Both deterministic disposable path-replacement cases fail: the final directory can become a symlink after `mkdir`, and the parent can become a symlink after `resolve`; the raw assertions confirm an identity was written outside the selected directory in each case. Existing-symlink, fixed-byte identity and nonregular-file controls pass. `scripts/phase5b2_reproduce_baseline.py` reproduces these failures without a network, real credential or host state.

The candidate opens every existing path component from `/` with `O_DIRECTORY|O_NOFOLLOW`, creates the final directory relative to its held parent descriptor, opens the final directory with the same flags, checks its mode using `fstat`, and creates/reads `identity.json` relative to the held final descriptor with `O_EXCL|O_NOFOLLOW`. The read uses `O_NONBLOCK` before `fstat` so a malicious FIFO cannot stall the CLI. Only root-owned macOS `/var` and `/tmp` aliases to `/private/...` are expanded. Relative `..`, other symlinks and platforms without the necessary descriptor flags fail closed. The resulting private UUIDv4 file remains `0600`, and the explicit state directory remains `0700`. Default commands never call this function and remain zero-write in the existing CLI tests.

This closes the reproduced pathname check/use gap against symlink replacement by another process. A principal that can rename the already-open directory itself may move that inode while the descriptor is held; the write remains descriptor-bound to the opened inode. Protecting a path from its own owner is outside this local-file trust boundary. `state_directory()` retains its path-returning API for compatibility; callers needing race-resistant I/O must use the descriptor-bound `asset_identity()` operation, not perform later writes via its returned path.

## Local validation and limits

`benchmarks/phase5b2/focused-tests.txt`: **14 passed, 1 expected failure** on macOS arm64/Python 3.15.2 using the repository's existing local venv and `PYTHONPATH=src:scripts`. The expected failure is the retained, unfixed grant-file check/read race below. Existing exact package matching, no-default-write, signed-current/withdrawn/expired status separation, fixed identity bytes/modes, FIFO rejection and CLI output tests all pass. `benchmarks/phase5b2/import-graph.txt` shows a cold import of `aegis.artifact`, `aegis.cli`, `aegis.config`, `aegis.core`, `aegis.intelligence_adapter`, `aegis.local_observer` and `aegis.trust`; no writer, mitigation, broker or native-enforcement module was imported. The `core` import is transitive through the shared grant loader and needs its own boundary review before removal.

`benchmarks/phase5b2/local-full-suite-macos-py315.txt` retains the broad attempt: **298 passed, 55 failed, 25 errors, 37 skipped, 1 expected failure** in 33.05 s. Many unrelated lab tests encountered sandbox `PermissionError: [Errno 1] Operation not permitted` while binding local Unix sockets. This broad run is a failure, not a regression pass; Main/VAL must rerun on a suitable local socket fixture and investigate any remaining failures. No production or external endpoint was used.

The current change does not alter inventory serialization, so the prior independently reviewed same-image source-only resource figures remain the relevant reference: Kali/Python 3.14 synthetic Debian 100,000 rows, baseline/candidate RSS 190.762/107.027 MiB and p50 wall 846.143/1,198.759 ms over three fresh runs. That figure is not an installed Linux alpha result. The frozen Debian/Ubuntu × Python 3.12/3.13 installed matrix, 256 MiB hard limit per cell, slow/closed stdout, syscall attempted-effect tracing and zero-default-write whole-mount oracle remain open. No current benchmark improvement is claimed.

For this candidate, installed Linux platform cells **planned 4, attempted 0, passed 0, skipped 4**; the frozen 68 child resource trials are **planned 68, attempted 0, passed 0, skipped 68**. A reviewed offline wheelhouse and Linux attempted-effect syscall tracer were not available to this lane. The macOS source-level tests above do not count toward those Linux denominators.

## Separate open grant-file race and compatibility decision

`benchmarks/phase5b2/grant-race-open.txt` runs the retained test with `--runxfail`: **1 failed**. `load_intelligence()` checks a trust path with `stat()` and then calls `config.load_publishers(path)`, which reads the path again. A disposable replacement after the size check supplies over 1 MiB of JSON; the loader accepts it, bypassing this CLI's documented bound. The ordinary suite marks this precise test expected-fail so the gate remains visible. It is not fixed by the state-directory change.

A compatible repair requires **one bounded descriptor read** for the grant bytes, then the existing parser's exact semantics on those same bytes. The preferred reviewed interface proposal is `config.load_publishers_bytes(raw: bytes)` with `load_publishers(path)` delegated to it; the parser body stays singular. Main owns `config.py` and must approve a versioned shared-loader change before 5B-2 adopts it. A duplicate private parser is prohibited pending golden old/new behavior tests for:

| Field or form | Frozen behavior to preserve |
| --- | --- |
| Legacy map without `grants` | Base64 Ed25519 public keys become legacy trust entries. |
| `grants` entries | Required `publisher_id`, `key_id`, `public_key`, `roles`, `not_before`, `expires_at`, `revoked_at`; only optional `revocation_publishers` is allowed. |
| Authorization | Finding/revocation roles, scoped revocation publishers, key expiration and revocation remain enforced by `TrustStore`. |
| Duplicate or conflicting entries | Preserve current `TrustStore` construction and rejection behavior. |
| Input integrity | Read one regular, non-symlink file descriptor at most 1 MiB plus one byte, reject excess and malformed JSON, and never accept bytes different from the checked inode. |

Golden legacy/grant/revoked/expired/key-rotation vectors, old/new reader results, signed event compatibility and independent negative review are required before changing the shared loader. No network access or enforcement authority is granted by this proposal.

## Acceptance request

VAL-1 should inspect this exact clean candidate, rerun the two failed-first state reproductions against the baseline and candidate, check existing CLI output and no-default-write tests, and independently challenge final/ancestor symlink replacement and existing identity symlinks on an installed Linux cell. Source safety approval is separate from installable alpha approval. CLI alpha remains **NO-GO** until all frozen platform, resource and syscall gates pass. Distributed autonomous enforcement remains **NO-GO**.
