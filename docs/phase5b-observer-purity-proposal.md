# Phase 5B observer purity: contract and validation proposal

## Scope and pins

This is a branch-local proposal, not an adopted shared contract or an implementation. The clean parent is `192feacf0c015c1fa37b075228b258d70e565d42` on `feat/phase5b-observer-purity`. The prior CLI source is `cc2e918603beff4cd296b4f39a723b6c30beed06`; it is not an ancestor of this branch. The independent failure freeze is `2eb2ca27be986f3b55e3f85c2067ae6672d213a5` on the validation lane; it is also not an ancestor. Review those commits by exact object ID before porting code. Preserve the retained traces and failed verdicts under `benchmarks/phase-next-validation/`.

The owner of this branch proposes only the Phase 5B observation output, local identity behavior and no-write acceptance tests. The integration lead owns promotion of any shared interface. The independent validator owns scoring of the frozen failures. Signed `Finding.schema_version="1.0"`, `SignedFinding`, its canonical Ed25519 bytes, publisher grants, scoped signed revocation, native T4/T5 and exact `InventoryItem(purl, version)` remain authoritative and unchanged. No CLI observation grants protected-write authority.

## Reproduced failures and required separation

The retained five-case default-state probe shows four unrequested `XDG_STATE_HOME/aegis/identity.json` creations and one explicit `--state-dir` control writing inside the selected directory. The unsupported Linux default `status --json` case also wrote before it exited 2. The separate signed-current fixture had `result=matched` and `claim_status=current` but no machine-readable independent Evidence/Trust status. The free-text uncertainty field is insufficient for automation. These observations are from the clean prior CLI pin; they are not evidence that a new candidate passes.

The observer must keep four different questions separate: (1) whether the supplied signed Finding is authentic under a local publisher grant, (2) whether the claim is temporally valid and whether a withdrawal is **observed in the supplied local file**, (3) whether the exact local package pair matches, and (4) whether current independent T4/T5 Evidence and withdrawal status has been established. The current CLI has no verified T4/T5 proof input, so question 4 is always `unknown`. A local file with no withdrawal cannot establish that none exists.

## Private output compatibility decision

Introduce private CLI `inventory-v2`, `observation-results-v2`, and `status-v2` outputs. Do not label these as shared `InventorySnapshot/v1` or `ExposureObservation/v1` contracts. Bump the version because default `asset_id` becomes nullable and the old top-level `result`/`claim_status` fields are ambiguous. The CLI should emit v2 only, with a documented migration example; no implicit v1 alias or signed-byte translation. The integration lead must approve any external consumer or long-term compatibility promise. Human text must use the same status distinctions and must not say protected, safe, verified vulnerability, or authorized mitigation.

In default mode, `asset_id` is JSON `null` and `identity_scope` is `none`; the CLI does not call the state-directory or identity-creation path. No random host ID is generated or stored. A snapshot digest can be computed from normalized package rows, source adapter and completeness state without host identifiers. With an explicit `--state-dir PATH`, the existing random UUIDv4 identity may be created under that path only, with private directory/file permissions, symlink rejection and no other writes. `--state-dir` is an explicit persistence opt-in, not an environment-variable default. Existing identities may be read only when that path was explicitly supplied. `doctor`, error handling, unsupported platforms and missing inputs follow the same rule.

Proposed minimum JSON fields for each signed observation:

```json
{
  "schema_version": "observation-results-v2",
  "asset_id": null,
  "identity_scope": "none",
  "snapshot_id": "sha256-of-normalized-inventory-and-completeness",
  "inventory_complete": true,
  "observations": [{
    "finding_id": "stable-local-display-id",
    "artifact_id": "signed-artifact-uuid",
    "claim_digest": "sha256-of-original-canonical-finding",
    "publisher_authenticity": "verified",
    "local_claim_status": "current-in-supplied-file",
    "software_match": "matched",
    "match_reason": "EXACT_PACKAGE_VERSION",
    "independent_status": "unknown",
    "independent_status_reason": "NO_VERIFIABLE_T4_T5_PROOF",
    "overall_assessment": "unknown"
  }]
}
```

`software_match` is only `matched`, `unmatched`, or `unknown`, using exact `(purl, version)` equality. `matched` means possible package exposure, never exploitability or protection. `unmatched` means only that the exact signed version list did not match a complete supported inventory. Ranges, aliases, backports, missing or partial inventory, unsupported distributions, and uncertain package identity remain `unknown`. `local_claim_status` explicitly describes the bounded supplied file and time check; values distinguish `current-in-supplied-file`, `expired`, `future`, and `withdrawn-in-supplied-file`. A malformed or untrusted envelope is rejected as input, not converted into a verified observation. `independent_status` is `unknown` with the reason above until a separately reviewed T4/T5 proof adapter and trust roots exist. The `overall_assessment` stays `unknown` even when an exact package matches. No `current`, `valid`, or `clear` independent status may be inferred from a signature, broker ACK, local event file, absence of a withdrawal, or model output.

`inventory-v2` must include `identity_scope`, nullable `asset_id`, snapshot ID, capture time, adapter/source, distribution, complete flag and reason, and the exact package tuples with architecture. `status-v2` must state `mode=observation-only`, `network=offline`, counts for signed claims and exact package matches, and `independent_status=unknown`. For all commands, exit 0 means the requested observation completed against supported complete inputs; it does not assert current independent status or safety. Exit 2 means incomplete, unknown, missing or rejected local input. `status` without a signed feed remains exit 2. `findings` and `explain` preserve machine-readable unknowns; an invalid signature, revoked publisher grant or malformed file is rejected before any observation is emitted. CLI parse errors may retain argparse's documented exit 2. No optional network path or process invocation is added.

## Exact acceptance matrix before implementation approval

| Case | Input and invocation | Required observation | Required filesystem result |
| --- | --- | --- | --- |
| Original implicit cases | Fresh empty state for `status --json`, `findings --json`, `findings --feed missing --trust missing --json`, `inventory --json` | Preserve appropriate 0/2 result and structured error or inventory record | Zero created or modified files across declared writable mounts; no `identity.json` |
| Explicit identity control | Fresh state, `--state-dir chosen inventory --json` | `identity_scope=explicit-local`, UUIDv4 ID and same ID on repeat | Only `chosen/identity.json` and chosen directory; mode 0600/0700 |
| Additional failure paths | `doctor`, `explain` without feed, unsupported distro, malformed/oversized feed, malformed/duplicate/unreadable inventory, invalid signature, revoked/expired publisher key | Unknown or rejected, with exit 2 as applicable | Zero writes without explicit `--state-dir`, including on failure |
| Signed exact match | Disposable unprivileged Debian/Ubuntu package fixture and a locally generated signed `Finding 1.0` with pinned grant | `publisher_authenticity=verified`, `software_match=matched`, `independent_status=unknown`, `overall_assessment=unknown`; no text implying protection | Zero default writes |
| Signed status negatives | Expired, future or signed-withdrawn claim; absent/withheld withdrawal; unsupported comparator; partial inventory | Temporal/local-file state and software match remain separate; no independent positive from local file completeness | Zero default writes |
| Offline and privilege boundary | Network-disabled, no capabilities, no-new-privileges, ordinary UID, read-only root and source mounts | CLI runs without scan, subprocess, listener, mitigation import or privilege escalation | Before/after tree hashes of all declared writable mounts match for default mode |

Run at least the original five-state commands plus malformed, missing, unsupported and successful signed-match cases in a cached disposable Linux image; pin image digest, candidate full commit, fixture and harness hashes. Preserve the original failed trace bytes. Compare before/after full trees, including mtimes and content digests. If an already-cached syscall tracer is available, capture file/network/privilege syscalls as additional evidence; otherwise mark that gate inconclusive. Prevent Python bytecode creation in the harness (`PYTHONDONTWRITEBYTECODE=1`) or mount the installed package read-only; record which control was used. Do not pull images or fetch dependencies. Independently rerun `tests/test_phase5b_cli.py` and adjacent Rapid/slice regressions at the clean exact candidate pin. Offline wheel build/install/uninstall and bounded CPU, RSS and elapsed time are separate alpha gates; a source invocation does not establish wheel behavior.

## Reconciliation order and open decisions

1. Review the prior CLI's `cli.py`, `local_observer.py`, `intelligence_adapter.py`, packaging and tests at `cc2e918` against the frozen oracle. Port source selectively onto this branch only after the integration lead accepts this private v2/no-write decision. Keep existing signature parsing and exact comparison unchanged.
2. Move identity creation behind explicit `--state-dir`; validate feed and platform before any optional write. Audit imports and output paths for implicit caches. Add v2 JSON construction around the existing matcher, keeping original signed inputs intact.
3. Add the exact tests above before declaring a fix. Ask the independent validator to rerun the original failure harness and fresh signed-status fixture against a clean full commit. Compare exact raw output and hash evidence, not branch names.
4. Reconcile v2 with the provisional Phase 5A `ResearchCandidate` and `InventorySnapshot/ExposureObservation` proposals only through explicit later adapters. Research candidates cannot become `SignedFinding`; no shared protocol or local enforcement contract changes in this lane.

Open decisions for integration review: whether `asset_id=null` is the preferred default compatibility break versus an explicitly marked ephemeral per-run ID; whether v2 should omit the old `result` field entirely (recommended to avoid automation treating software match as independent status); and whether any future T4/T5 status adapter belongs in the observation CLI at all. Until decided, the existing v1 CLI alpha is not promoted and its default-write and structured-status gates remain open.
