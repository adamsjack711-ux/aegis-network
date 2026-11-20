# Phase 5A and 5B schema authority map

Reviewed against Phase 4E `ee739cacfaa3f81a0994b4d7802fd2943c067d86`. This document identifies existing authority and proposed private adapters. It changes no signed bytes or runtime contract.

## Authoritative signed finding

The current published defensive finding is `Finding` with `schema_version = "1.0"` in `src/aegis/artifact.py` at Phase 4E `ee739ca`. It is wrapped by `SignedFinding` with `kind = "finding"`, `key_id` and base64 Ed25519 `signature`. The signed payload is the canonical UTF-8 JSON of `Finding`, sorted keys and compact separators, as returned by `canonical_bytes`. Signature verification also requires the publisher/key grant, role, time and local policy. A valid signature establishes record origin and integrity, not truth or authority to write.

| Existing field | Authority and compatibility meaning |
| --- | --- |
| `schema_version`, `artifact_id`, `publisher_id`, `sequence`, `issued_at`, `expires_at` | Version `1.0`, stable logical identity, publisher sequence and bounded time. Replay and durable decision semantics depend on these exact values. |
| `vulnerability_id` | Signed claim identifier; it does not establish independent verification. |
| `software.purl`, `software.affected_versions` | Signed package URL and explicit nonempty version list. The current local matcher uses exact `(purl, version)` equality. It does not evaluate advisory ranges or distro backports. |
| `evidence[]` | Signed URI, SHA-256 and method (`lab-reproduction`, `source-review`, `advisory`) references. The reference is not a verifier attestation or status certificate. |
| `applicability`, `mitigation_template` | `authorized-lab` only, and a named template subject to independent local policy. The CLI displays claims and has no template execution path. |
| `SignedFinding.kind`, `key_id`, `signature` | Existing envelope selector, publisher key ID and Ed25519 signature over `canonical_bytes(finding)`. No new advisory or inventory field may be inserted into these signed bytes without a separately versioned contract. |

`Revocation` is a different event with schema versions `1.0` and `1.1`. Version `1.1` binds `target_publisher_id`, target artifact UUID and digest. Current withdrawal and Evidence status must be checked through their established validators; merely reading a signed finding does not establish current status. [Source model](../src/aegis/artifact.py) · [Local exact matcher](../src/aegis/core.py) · [Phase 4E freeze](phase4e-contract-review.md)

## Authoritative local inventory today

`InventoryItem` in `src/aegis/core.py` at `ee739ca` is a local immutable pair of `purl` and `version`. `LocalAgent` stores exact pairs and compares them with the signed `software` list. It also enforces separate local publisher trust, template policy, lab authorization, revocation and durable audit. `InventoryItem` has no schema version, OS, architecture, source, snapshot digest or completeness marker. It is a Python runtime value, not an installable Linux inventory interchange format. The CLI's observation path must not call the audit-writing `LocalAgent.evaluate` merely to obtain a match. [Runtime model](../src/aegis/core.py)

## Provisional Phase 5 records

| Proposal | Location and version | Current authority | Owner and adapter requirement |
| --- | --- | --- | --- |
| `AdvisoryInput.v1`, `ResearchCandidate.v1`, `ResearchCheck.v1`, `ResearchReview.v1` | [5A architecture](phase5a-architecture.md), Agent 2 proposal `086a1df2764bd496a811cff584861bd02570df24` in `feat/phase5a-intelligence` | Documentation proposal only. No committed Phase 5A **signed finding** schema exists. Research confidence, source spans and model outputs are untrusted research metadata. | Agent 2 owns its private format. A future conversion to signed Finding or Evidence needs integration lead and T4/T5 trust-owner approval plus Agent 4 negative tests. |
| `InventorySnapshot/v1`, `ExposureObservation/v1` | [5B CLI contract](phase5b-cli-contract.md), Agent 3 proposal `553587615de8319e742a70f28926b4150f8c5094` and signed-Mesh adapter correction `443a2c4779948b5be24342c9c3bdad9eea6b5d54` in `feat/phase5b-linux-cli` | Documentation proposal only. No committed Linux inventory schema or CLI implementation exists. | Agent 3 owns private inventory and observation records. The adapter to current `InventoryItem` uses exact purl/version and retains partial or unsupported cases as `unknown`. Agent 4 challenges output and side effects. |
| Implemented private `SourceSnapshot`, `Claim`, `Asset`, `Assessment`, `ResearchResult` | `src/aegis/intelligence/{models,baseline,research}.py` on `feat/phase5a-intelligence` at `e3da3876df413f080095dc7568a664f75ffba5b6`; field gap map in `docs/phase5a-intelligence.md` on that branch | Committed, but **provisional and not adopted as shared contracts**. These names do not implement the proposed research records field for field. The feed client rejects external fetch, and no external provider is shipped. The independent unsupported-positive-point test currently fails. | The active Phase 5A task confirmed ownership. Agent 4 owns its independent failure reproduction. Integration lead holds all cross-system adapters pending reviewed mapping and guardrail disposition. |

The Linux CLI's first signed-claim adapter uses `SignedFinding`/`Finding 1.0` unchanged and a locally supplied publisher trust root. It verifies the signature and current validity, then compares only explicit signed versions with local inventory. It reports publisher claim, local match and independent status as separate fields. Missing withdrawal proof, incomplete inventory, aliases, unsupported version ranges and research-only candidates produce `unknown` where applicable. The CLI does not convert a 5A research candidate into a signed finding, verifier attestation, local approval or mitigation action.

## Change control

Agent 1 owns native writer and ownership proposals, Agent 2 owns research-only records, Agent 3 owns observation records, and Agent 4 owns independent adversarial and compatibility oracles. The integration lead owns any shared signed-contract adoption. Changing `Finding 1.0`, its signature domain/canonical bytes, `InventoryItem` matching semantics, revocation rules or T4/T5 binding requires a numbered interface proposal with old/new field examples, versioned readers, migration and denial preservation, golden signatures, independent tests and an explicit integration decision. Until then, the existing signed Mesh finding is the compatibility reference and the Phase 5 formats remain provisional.

At the initial read-only review, Agent 3's worktree contained uncommitted `pyproject.toml`, `src/aegis/cli.py` and `src/aegis/local_observer.py` from concurrent work. The active Phase 5B implementation task is now identified as their owner; the implementation remains uncommitted and excluded from interface approval. The owner-specific documentation correction is `443a2c4779948b5be24342c9c3bdad9eea6b5d54`; it changes no signed bytes. This attribution update does not promote any private record to authority.
