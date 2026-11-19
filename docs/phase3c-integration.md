# Phase 3C integration

## Pre-change conflict register

Recorded before modifying source. The worktree starts from Phase 2 RC `ffe5c322b144ab3fb40d2ee29b1486b917d339f1`. Reviewed the Phase 2 contracts, threat model, hardening and RC handoffs, Phase 3 design proposals, and the three feature handoffs.

| Input | Ancestry and conflict | Integration choice |
| --- | --- | --- |
| Evidence `b2628f2d0a59d0eed1352e8d3f0ef7055909efe2` | Bespoke Evidence signature domain and opaque claim digest. Its parent `14440ee` predates hardened Mesh. | Import additive files. Bind the evidence claim to the exact Phase 2 finding payload excluding its circular evidence reference. Reappraise signed records locally. |
| Mitigation `83cacbd8f9eac9dc4a5eef558cb613fe1a46a498` | Also based on `14440ee`. Its standalone plan starts from local fixture state and has no Evidence or Rapid binding. | Keep the existing disposable adapter. Add a typed, hash-bound integrated plan to the local approval path and guard target transactions. |
| Validation `1fca3858165c67d491f35b15c7009fef6d940d1c` | Common ancestor with the RC is `65ebb3a`. Its scripted oracle validates synthetic scenarios and hardened dry-run audit behavior. | Preserve the independent fixtures and existing assertions. Add live candidate checks using HTTP observations and durable audit readback. |
| Phase 2 RC | Phase 2 signed payloads, scoped revocations, UUID durable leases, journal and ack rules are distinct from the new contracts. | Leave the existing wire contracts and default dry-run entry points in place. Use the standard Mesh path and commit-before-`ack_sync()` handler. |
| Signature-reason regression | The Evidence and Mitigation handoffs report a text mismatch on `14440ee`. The pinned RC test already asserts `INVALID_SIGNATURE`, no watermark advance, and acceptance of a later valid lower sequence. | Preserve the RC assertion and verify it in the combined suite. Keep signature rejection and separate expiry reasoning. |

Evidence and effectiveness have different authority. The former qualifies a finding about one exact inert fixture. The latter observes actual HTTP behavior after an approved local transaction. Only local review can issue a capability. A local status feed and the existing Mesh journal are available in the lab. Neither constitutes independent proof that a compromised coordinator disclosed every withdrawal.
