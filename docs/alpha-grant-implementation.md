# Alpha grant reader: isolated implementation attempt

**Branch:** `feat/alpha-grant-astra`; source parent `29455087922a728a41936d8c5c79ff9942e1e3df`. **Status:** implementation candidate only, pending exact-pin Main and independent VAL review. No intake or release decision follows from the source-owner tests.

## Compatibility decision applied to this attempt

The pre-edit probe in `docs/alpha-grant-mode-baseline.md` showed that the old loader accepted readable `0600`, `0644`, `0640`, `0444`, `0400`, `0666`, and `0622` files. Thus the earlier proposal's `0600`/`0644` and ACL-unknown-deny mode profile is **not implemented or approved**. The descriptor reader leaves OS read permission in control of readable file modes and does not add owner/mode/ACL authorization. This preserves the tested mode behavior but leaves weak file custody possible. Tightening requires a separate versioned contract and platform compatibility review.

`config.load_publishers(path)` and `config.load_publishers_bytes(data)` use one JSON-to-grants parser body. The path loader retains its text decoding; the new CLI byte input decodes UTF-8 strictly. Neither changes SignedFinding 1.0, grant roles, scope, intervals, revocation, key rotation or native T4/T5 status. The CLI opens the final grant file once relative to a held parent descriptor, rejects ancestor and final symlinks (except macOS's checked `/var` and `/tmp` system aliases), checks regular type and size, reads at most 1,048,577 bytes, then checks inode metadata and byte count before parsing. No path reread or grant cache participates in authorization.

Ancestor no-follow traversal is a new filesystem-input restriction. Existing configurations that rely on other symlinked ancestors need explicit migration review. The reader does not authenticate file provenance or make a same-UID-writable path trustworthy. An attacker able to modify an inode and conceal all checked metadata may defeat the mutation detector; that is outside the tested custody assumption. A valid signed Mesh event remains only an observation lead, and independent Evidence status remains unknown without separate proof.

## Verification

- Retained baseline failure: `benchmarks/alpha-grant/baseline-grant-race.txt` records the pre-edit `--runxfail` test failing with `DID NOT RAISE ObservationError`. The original strict xfail is preserved; it monkeypatches the old pathname-loader seam and now xfails because that seam is no longer called. It is **not counted as repair proof**.
- New `tests/alpha_grant/test_grant_reader.py` covers G00 static signed fixture hashes and signed intake; old/new JSON parser equivalence and role, scope, expiry and rotation; F readable modes, no-follow, FIFO and inclusive 1 MiB boundary; R00 post-open path replacement; R01 same-inode growth; R02 same-size rewrite; R03 open/fstat/read/decode/parser faults and descriptor close; R04 concurrent readers with a path swap. Focused result after the final test edits: **37 passed, 1 historical xfail** across the new tests, retained xfail and existing CLI tests.
- Full suite with local UNIX/loopback socket access on the final source and test tree: **417 passed, 37 skipped, 1 xfailed**, one Starlette deprecation warning in 131.80 s. Raw summary: `benchmarks/alpha-grant/full-suite-elevated.txt`. The 37 skips are opt-in tests, not verification.
- Restricted-sandbox full-suite attempt: **55 failed, 332 passed, 37 skipped, 1 xfailed, 25 errors**. Representative failures were `PermissionError: [Errno 1] Operation not permitted` when disposable lab services tried to bind UNIX sockets. The elevated rerun removed those failures. The restricted run was not saved verbatim because its full traceback was 114,508 tokens; its counts and root cause are recorded here.

## Independent review requests

VAL should rerun the exact committed tree, including retained baseline reproduction, descriptor-level R00–R04, static signed fixtures, Linux/Debian and macOS cells, and grant-file symlink compatibility. In particular, verify the same-inode rewrite oracle fails closed on each supported filesystem and that a protected actor cannot use the CLI's grant file to bypass native status or local approval. Main should decide whether no-follow ancestor restriction is acceptable for Alpha or requires an operator migration path. No release approval is requested here.
