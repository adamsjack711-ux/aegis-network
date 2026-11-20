# Proposal: GrantFileCustody.v2

**Status:** review proposal only. No runtime mode, owner, ACL or ancestor-ownership restriction is authorized by this document. The isolated grant reader at `644a1841fab56c641ba0a25cdcbdd19ae6eec519` retains legacy readable-mode behavior while closing its pathname check/read race. SignedFinding 1.0, publisher-grant JSON, native T4/T5 and exact inventory matching are unchanged.

## Problem and compatibility boundary

The legacy parser and current descriptor candidate accept a grant file whenever the OS lets the process read it. A pre-edit macOS probe in `benchmarks/alpha-grant/legacy-mode-probe.json` accepted modes `0600`, `0644`, `0640`, `0444`, `0400`, `0666`, and `0622`; `0000` failed for a non-root process. World- and group-writable grant files allow another local principal to replace the trust root when directory permissions or ACLs also permit it. The current reader's `O_NOFOLLOW` directory walk blocks symlink traversal but does not establish owner or write custody. These are separate from the bounded-read repair and require an explicit compatibility decision.

## Proposed v2 policy for review

The policy should be applied to a held final descriptor and every held ancestor directory descriptor, never to a pathname that is later reopened. Require the final file to be regular, owned by the current effective UID or root, and not writable by group or other. Preserve readable `0400`, `0444`, `0600`, `0640`, and `0644` where ownership and ACL checks pass; do not reduce the mode allowlist to only `0600`/`0644` without migration evidence. Require each ancestor to be a directory owned by root or the current effective UID and not writable by group or other, with a narrowly specified root-owned sticky system-temp exception. Deny nontrivial ACL entries granting writes to other principals. If the platform cannot verify ACLs on held descriptors, return `CUSTODY_UNVERIFIED` and prevent trust-root use under v2; do not treat absence of an ACL inspection API as proof of safety. Define exact Linux POSIX ACL and macOS native ACL semantics, including inherited ACLs, in a platform-specific appendix before implementation.

The baseline's `0666` and `0622` modes would be rejected under v2, so this is a **versioned breaking filesystem-input change**. The policy cannot retroactively make an attacker-controlled same-UID path safe, and a privileged actor with metadata control remains outside its guarantee. A file under a world-writable ancestor must be denied unless the sticky-directory exception is proven to prevent unauthorized replacement for the relevant owner and path.

## Required acceptance before release

1. Freeze a four-cell Debian/Ubuntu and Python 3.12/3.13 installed matrix plus macOS developer cell. Test root-owned and current-UID files, each legacy readable mode above, ACL grants/denials, sticky and non-sticky ancestors, symlink aliases, and concurrent rename/growth on the actual descriptor seam.
2. Publish a migration plan for operators using `0666`, `0622`, symlinked ancestors or custom ACLs. A dry-run preflight should report the specific custody reason without writing state or printing grant content or key material.
3. Compare old and new parser results for all grant-role, scope, expiry, revocation, rotation and legacy vectors. Run golden signature and old/new reader tests. The custody gate may reject a file but must never broaden accepted grant semantics.
4. Obtain Main contract approval and independent VAL security review of the exact clean implementation commit. Retain the current failed reproduction and the world-writable compatibility probe. Keep CLI alpha and distributed enforcement release gates separate.

Until those conditions are met, `GrantFileCustody.v2` is **not an active policy** and world-writable grant files remain an explicitly documented operator-custody risk in the observation-only candidate.
