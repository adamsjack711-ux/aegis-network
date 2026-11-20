# Alpha Grant Security: single-read local grant contract proposal

**Status: proposal only.** Source baseline `29455087922a728a41936d8c5c79ff9942e1e3df` on `feat/alpha-grant-security`. SignedFinding 1.0, exact `InventoryItem(purl, version)`, native T4/T5 authority and all protected-writer semantics stay unchanged. Shared `src/aegis/config.py` and `src/aegis/intelligence_adapter.py` are **not edited** until Main and VAL review this contract after the independent release freeze.

## Reproduced failure and scope

`load_intelligence()` currently calls `trust_path.stat()` to enforce a 1 MiB regular-file limit, then calls `config.load_publishers(path)`, which reopens the pathname and reads it without a bound. The retained test replaces the file after the first check with a JSON grant file over 1 MiB. On this exact baseline, `--runxfail tests/cli_safety_phase5b2/test_grant_race.py` exited 1: **FAILED, DID NOT RAISE ObservationError**. Raw output is `benchmarks/alpha-grant/baseline-grant-race.txt`. The result proves a size/check-use bypass in the observation CLI; it does **not** by itself prove publisher authorization bypass. No network, credential or real host state was used.

The repair scope is the CLI's **local operator-supplied publisher-grant file**. It must parse only the bytes read from one held file descriptor under the 1 MiB cap. A valid publisher signature remains necessary and never proves a vulnerability claim correct. This proposal does not make a path under attacker control into an authenticated trust root: the operator still must enroll and protect the grant file and its path. It does not change the server's or Rapid's authority rules.

## Proposed internal `GrantInputReader.v1` boundary

1. Add **one parser body** in `config.py`: `load_publishers_bytes(raw: bytes) -> TrustStore` decodes UTF-8 and calls the current JSON-to-`PublisherGrant` logic. Keep `load_publishers(path)` as a backward-compatible wrapper around that same parser. Do not add `publisher_config.py` or copy parser code. Preserve legacy map, grants, roles, scoped revocation, timestamp, revocation and key-rotation interpretation. No canonical signed bytes or grant wire fields change.
2. In the CLI adapter, replace `stat(path) → load_publishers(path)` with `read_local_grants(path, 1_048_576) → load_publishers_bytes(raw)`. The read opens the selected file **once**, with `O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK`; it rejects missing no-follow support, symlink, FIFO/device/socket/nonregular files, mode or ownership inconsistent with an operator-controlled file, and bytes above the bound. `fstat` applies to the opened descriptor; read at most `limit + 1` bytes from that descriptor and close it on every path. Neither `Path.stat()` nor a second pathname read may authorize its content.
3. For ancestor path replacement, prefer descriptor-relative traversal of each component from a pinned root directory with `O_DIRECTORY|O_NOFOLLOW`, with only independently checked root-owned macOS `/var` and `/tmp` aliases as compatibility exceptions. Resolve the exact Linux/macOS path and parent-mode rules in tests before adoption. If a secure descriptor walk cannot be provided on a platform, fail closed. A file replaced after the descriptor opens may change the path but cannot change the bytes evaluated for this invocation.
4. Mode compatibility proposal: accept normal operator-owned private or world-readable public-key files such as `0600` and `0644`, while rejecting group/other **writable** files; pin exact owner rules for current UID versus root-owned read-only files. This narrows unsafe filesystem input and needs an explicit compatibility decision. The file contains public keys/grant metadata, so world readability alone is not a secret leak. The chosen policy must be tested on Debian/Ubuntu and macOS fixtures.
5. Preserve CLI error behavior: malformed, oversized, symlinked, nonregular, changed/unknown or unreadable grant input yields a bounded `ObservationError` and no optimistic `independent_status` or finding match. Do not log grant bytes, full paths or secrets. The CLI remains observation-only; no local approval, Evidence status or protected write can be derived from this file alone.

## Backward compatibility and golden vectors required before source edit

| Case | Required old/new behavior |
| --- | --- |
| Legacy `{publisher_id: base64_public_key}` map | Same trust entries and signature acceptance/rejection for the same exact signed event. |
| `grants` list with all required fields, optional `revocation_publishers` | Same roles, issuer scope, not-before/expiry and revoked-at decisions at boundary times. |
| Key rotation and multiple grants | Same key-id selection, overlap and rejection of revoked or retired keys. |
| Duplicate/conflicting grant and legacy entries | Preserve current `TrustStore` construction/rejection semantics; do not silently select a different key. |
| Malformed JSON, invalid base64/Ed25519 bytes, unexpected grant fields | Same parser decision and a bounded CLI error; no fallback to a legacy map. |
| UTF-8, BOM and duplicate JSON keys | Compare the current `Path.read_text()`/`json.loads()` behavior against the proposed exact-byte parser; any intentional rejection tightening needs a separate versioned decision. |
| File `0600`, `0644`, group/other writable, symlink, FIFO, device, path swap and growth after `fstat` | Document newly rejected filesystem forms separately from unchanged grant semantics; `limit + 1` must detect growth and fail closed. |
| Golden SignedFinding 1.0 and Revocation 1.1 bytes | Old/new loader must yield identical TrustStore authorization for fixed signed vectors; artifact signatures and digests remain byte-identical. |

The existing strict `xfail` test must first be observed failing on the baseline, then pass after the repair without weakening its assertion. Add deterministic descriptor-swap and file-growth negative tests that target the actual new seam, plus no-default-write, local exact match and independent-status-unknown regression. Run focused tests and the full suite on a clean exact integrated commit. VAL must independently rerun the original failure and golden vectors; source-owner green tests alone do not approve intake.

**Test-seam hazard:** the retained xfail monkeypatches `adapter.load_publishers` to replace the file after `stat()`. A repaired adapter may no longer call or even expose that symbol; the old test could then xfail from `AttributeError` or an unrelated expectation while the actual open/read boundary remains untested. Preserve its raw baseline failure, but add a new deterministic hook around the descriptor open/fstat/read sequence. Independently replace the path *after* the descriptor opens and verify the original inode's bounded bytes are parsed, then grow the opened inode during the read and verify denial. A strict xfail count alone is not evidence that the race is fixed. Do not delete the original reproduction.

## Review decisions requested

- **Main:** approve or revise the new internal byte-parser interface, path traversal and mode/ownership policy before shared source changes. Confirm exclusive ownership of `config.py` and `intelligence_adapter.py` for this lane. No change to SignedFinding, InventoryItem or native T4/T5 is proposed.
- **VAL:** freeze exact baseline failure and golden old/new reader vectors before reviewing any implementation. Independently verify the race is closed by one descriptor read, not hidden by a changed test seam. Verify no parser duplication, authority expansion, default write or source-claim promotion.
- **Release:** even if this repair passes, installed Linux alpha remains NO-GO until four-cell offline packaging, 84 console cases, 68 resource/privacy children and attempted-syscall tracing pass independently. Distributed enforcement remains NO-GO.
