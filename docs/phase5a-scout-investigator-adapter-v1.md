# Scout → Investigator adapter proposal v1 (review required)

**Status:** proposed, not connected. Scout `54c7ec4d90e612c667d9cd5f217a5e2f18e38d54` and Investigator `97265de36a67de4a7ae6f374fb8cd64362fcb6fe` have different private `AdvisoryInput` schemas. This proposal does not change either schema or authorize a bridge to SignedFinding, Evidence, Trust, local approval, or a protected writer.

## Input and output

The proposed `scout-investigator-adapter-v1` operation takes a pinned Scout event or revision, a caller-supplied local `Asset`, one explicitly selected vulnerability ID from `vulnerability_ids`, and the exact raw snapshot bytes from Scout's `source_bytes(content_sha256)`. Its output is either a private Investigator `advisory-input-v1` or a typed **hold** with reason codes. The adapter must not turn Scout `priority`, `exploited`, `exposed`, `confidence`, or summary text into an applicability conclusion.

| Scout field / state | Investigator mapping or hold |
| --- | --- |
| `source_kind`, `source_uri`, `retrieved_at`, `acquisition`, `content_sha256` | Construct one `SourceSnapshot` with the *original bytes*; recompute SHA-256 and compare to both Scout and snapshot digests. Preserve URI and acquisition exactly. |
| `advisory_id` | Copy to private Investigator `advisory_id`. |
| `vulnerability_ids` | Require explicit member selection; copy that ID only. Never infer identity from aliases or order. |
| `claims`, `missing` | Re-normalize raw bytes; require the selected Scout claims to match the normalized claim set and source references. Hold on missing product/version applicability, lossy projection, or unknown scheme. |
| `withdrawn_at`, `conflict`, revision/event sequence | Hold when withdrawn or conflicted. Verify event/revision freshness at the pinned Scout cursor; a replayed old positive revision must not erase later withdrawal or contradiction. |
| `provenance`, `redistribution` | Carry as unverified sidecar metadata in the adapter audit, never silently upgrade to authenticated provenance. `synthetic-fixture` is lab only; `unverified-archive` is not source authentication. Unknown redistribution blocks export. |
| `priority` | Omit from Investigator applicability assessment; retain only in private triage audit. |
| Local `Asset` | Must be supplied independently; no conversion from advisory package aliases or exposure score to exact inventory identity. |

The proposed audit envelope records both schema versions, adapter version, Scout sequence/revision digest, source URI/kind/acquisition/provenance, raw SHA-256, selected vulnerability ID, asset digest, mapping decision, and hold reasons. It contains no raw advisory bytes, local identity, credential, or prompt. Its role is traceability, not authority.

## Deny and compatibility rules

* Reject missing bytes, digest mismatch, mismatched normalized claims, unsupported source kind, incomplete claim projection, withdrawn or contradictory revisions, unknown selected ID, and stale cursor. A hold yields no Investigator input.
* Preserve unknown applicability and conflicting source dispositions. Multiple Scout notices require separately pinned snapshots and explicit grouping; v1 does not infer a unified source set.
* Recheck the current Scout revision/cursor immediately before private research. New withdrawal or conflict invalidates cached adapter output. A `SourceSnapshot` digest alone does not prove freshness or Trust status.
* Private Investigator `ResearchCandidate` and its exact-byte excerpts remain **unverified research**. Exact quote bytes do not establish semantic truth. Independent semantic review and native T4/T5 remain required for any later authority path.
* This adapter requires an independent contract/security review and golden tests before implementation. Both private input schemas remain at v1; `SignedFinding 1.0` and exact `InventoryItem(purl, version)` are unchanged.

## Required independent acceptance

Test matching raw bytes and Scout normalized claims, tampered bytes, alias mismatch, missing applicability, withdrawn-first and withdrawn-after-cache, contradiction, out-of-order replay, unknown provenance, unverified archive, uncertain inventory, and no promotion of any research record into signed or local authority. Include source-byte digest and semantic-adjudication denominators separately. No external feed or model call is part of this proposal.

## Offline Investigator revision

The revised Investigator accepts only the exact `ScriptedProvider` class. `OpenAIProvider.complete()` always raises before touching environment or transport, and `investigate()` rejects custom providers before reading input. `Authorization` and `SpendLedger` remain importable solely to avoid breaking private experiment readers; they cannot grant inference. A future real-model design needs a new, independently reviewed out-of-band operator capability, exact endpoint/model/export approval, credential custody, rate/token/USD stops and actual billing oracle. None is implemented here.
