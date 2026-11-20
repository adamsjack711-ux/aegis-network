# Phase 5C-1 provisional diagnostic contracts

**For interface review, not implementation approval.** These are private `proposal-v0` records. None is a signed Mesh Finding, Evidence record, verifier attestation, status endorsement, local approval, action capability or executable artifact. The authoritative contracts remain `SignedFinding 1.0`, exact `InventoryItem(purl, version)` matching and native T4/T5. The Diagnostic Runner has no reader or writer in those authority paths.

## Proposed records

All request/result JSON would be strict UTF-8 with duplicate-key rejection, no NaN, unknown-field rejection and declared byte limits. A digest covers canonical serialized bytes for correlation; no unkeyed hash is called an authenticated signature. Version changes receive new `kind` values and old/new reader tests. Initial limits below are *proposed local-lab profile maxima*, subject to benchmark and validator review: request ≤64 KiB, selected immutable input ≤1 MiB, worker result ≤1 MiB, sanitized stderr ≤4 KiB, wall deadline ≤3 s, CPU ≤1 s, address space ≤256 MiB, process count ≤4, tmpfs ≤8 MiB and zero host output unless an explicit path was provided.

| Record | Required fields and interpretation |
| --- | --- |
| `DiagnosticTargetEnrollment.proposal-v0` | `kind`, stable local `target_id`, disposable fixture ID and immutable image/root digest, operator identity and enrollment digest, permitted profile IDs, local pathname root, `not_before`, `expires_at`, `network=disabled`, `writes=none`, exact scope. It is locally pinned enrollment data, not supplied by Mesh or research. A future signed enrollment needs separate key, custody and revocation review. |
| `DiagnosticProfile.proposal-v0` | `kind`, profile ID/version, source-reviewed registry digest, pinned worker/image bytes digest, accepted input grammar and limit, fixture family, positive/negative control IDs and expected results, bounded output schema, limits, deterministic parser revision, `side_effects=none`. It contains no shell command, download URL, dynamic module name or remote script. Only installed registry entries are selectable. |
| `DiagnosticRequest.proposal-v0` | `kind`, unique run ID, exact target-enrollment digest, target snapshot digest, selected profile ID/version/digest, operator-invoked flag and bounded local invocation time, optional explicit output-path grant, and requested budget ≤ profile ceiling. A research candidate may provide a displayed suggestion but cannot fill the operator-invoked flag or override enrollment/profile pins. |
| `DiagnosticObservation.proposal-v0` | `kind`, run ID, target/profile/input digests, worker/image digest, launch and finish UTC correlation times, same-host monotonic elapsed span, bounded CPU and peak RSS, control observations, outcome, reason code, partial/complete flag, parser revision and sanitized result digest. `independent_status="unknown"` unless a separate native proof was actually supplied and checked by a distinct reviewed adapter; this proposal defines no such adapter. No action, mitigation, approval or `verified=true` field. |
| `DiagnosticTranscript.proposal-v0` | Ordered run-stage hashes for preflight, launch, result read, validation and disposal, plus source commit/image pin and a local transcript digest. Optional explicit output capture records the chosen destination and file digest. A local transcript does not establish independent custody or successful host cleanup without separate observation. |

`outcome` is one of `observed`, `not-observed`, `inconclusive`, `rejected`. `not-observed` means this *specific registered check* did not see its marker under passing controls; it is not `unaffected` or `safe`. `inconclusive` covers unavailable target, failed/absent controls, timeout, truncated output, resource denial and incomplete snapshot. `rejected` covers invalid enrollment, unsupported profile, malformed request, mismatched digest or attempted scope escape before a valid observation. Each non-`observed` result has a stable reason code; success cannot be inferred from process exit 0 alone. An error result remains in the planned-run denominator.

## Frozen adapters and compatibility

| Producer → consumer | Proposed handling |
| --- | --- |
| 5A research → 5C | Optional, untrusted `suggested_profile_id` and source span only. Operator must independently select an installed profile and locally enrolled fixture. No model tool call or automatically accepted request. |
| 5B CLI → 5C | No default call or import. A future explicit local-lab command would display the DiagnosticObservation with its provisional kind, exact target scope, controls and unknown independent status. 5B owns CLI UX and package metadata. |
| 5C → existing `SignedFinding 1.0` | **No adapter.** `SignedFinding.model_validate` must reject a diagnostic result. A publisher may later research it, but must use the existing independent Evidence and signing pipeline. |
| 5C → native Evidence/T4/T5 | **No adapter.** Existing Evidence schemas must reject it; a registered verifier must independently reproduce a pinned Evidence bundle through native rules. A diagnostic transcript is not an attestation, withdrawal or status endorsement. |
| 5C → local approval, Rapid or protected writer | **No reader.** The output is inert even if its digest or local audit transcript validates. Unknown/stale/conflicting Trust remains a protected-write denial. |
| Old readers | Existing CLI/Evidence/Mesh readers ignore or reject the new kind; no reinterpretation of `vulnerability_id`, signed evidence refs, package ranges or exact inventory equality. |

The proposed local enrollment must not be confused with the native ownership generation or a target action lease. It grants permission to *observe an inert disposable fixture* only; it neither bypasses 4F fencing nor extends local approval expiry. The default output does not disclose hostnames, network addresses, process arguments, credentials, source documents or raw environment variables. If later diagnostics need any of those, update the privacy and data-flow review before code.

## Versioned review checklist

Before adopting a contract, the integration lead and VAL-1 should require golden canonical bytes, duplicate-key/unknown-field/oversize negatives, old/new reader rejection, explicit enrollment scope and expiry, exact profile and image hash checks, result-state semantics, deterministic control failures, safe cancellation and resource-bound proofs. An authority bridge would additionally require independent T4/T5, SignedFinding and local-policy review. No authority bridge is proposed here.
