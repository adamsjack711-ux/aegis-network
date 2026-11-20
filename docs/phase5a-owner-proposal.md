# Phase 5A owner proposal

Prepared against `ee739cacfaa3f81a0994b4d7802fd2943c067d86`. The common contract freeze is `880ce5f18d9fbe0522373bc99d89e0a7ce21e399` in the architecture worktree. This proposal changes no shared schema or enforcement path.

## Existing authority boundary

`src/aegis/artifact.py` defines a strict `Finding` with `schema_version="1.0"`, authorized-lab applicability, one bounded software identity, bounded evidence references and a mitigation template. Its signature covers canonical finding bytes. `src/aegis/evidence/records.py` defines distinct submitter, verifier and revoker roles, exact material pins, strict signed observations and withdrawals. `src/aegis/evidence/service.py` requires registered materials and enrolled worker profiles. A research candidate must not be cast as `SignedFinding`, `SignedAttestation`, `SignedManifest`, a Rapid decision or a locally signed mitigation plan. The candidate namespace and on-disk store have no route to `MeshIntake`, `VerifiedLab`, `TargetStore`, publisher private keys or local approval keys. Any later promotion starts a separate existing evidence and local policy review.

## Owned files and integration seams

Own new `src/aegis/intelligence/` modules, `tests/intelligence/`, pinned local advisory corpus, `benchmarks/phase5a/` and Phase 5A handoff. Keep `artifact.py`, `evidence/`, `phase3c.py`, `agent_runtime.py`, `mitigation/` and trust policy out of this branch. No `pyproject.toml` dependency or entry point change until the integration lead reviews it. The Phase 5B CLI can consume an exported observation report by an explicit read-only adapter after field and version review. No direct 5A-to-CLI or 5A-to-Mesh import at this stage.

## Proposed versioned private records

All records are strict JSON, reject unknown keys and duplicate keys, have bounded byte lengths and use canonical SHA-256 to identify immutable local inputs. Field names below are proposed, not changes to existing signatures.

| Record | Required fields | Rejection or uncertainty rule |
| --- | --- | --- |
| `AdvisoryInput.v1` | `source_namespace`, `source_advisory_id`, `source_uri`, `snapshot_digest`, `snapshot_size`, `supplied_at`, `source_identity`, `provenance_kind`, `provenance_digest`, `license_id`, `content_type`, `raw_bytes_pin`, `revision` | A URI or model claim is not source authentication. Missing or failed provenance, unsupported license, revision rollback or digest mismatch is rejected before research. The raw snapshot stays immutable. |
| `ResearchCandidate.v1` | `candidate_id`, `advisory_digest`, `advisory_revision`, `vulnerability_ids[]`, `affected_packages[]`, `claims[]`, `research_confidence`, `uncertainty_codes[]`, `missing_facts[]`, `follow_up_checks[]`, `producer`, `producer_revision`, `run_id`, `created_at`, `resource_usage` | Each package binds ecosystem, normalized name or PURL, and range expression with named comparator. Every claim has source digest and byte span or structural path. Confidence is a descriptive research rating, never a verifier probability or authorization. Missing provenance yields inconclusive. |
| `ResearchCheck.v1` | `candidate_digest`, `advisory_digest`, `checker_revision`, `package_identity_result`, `range_result`, `citation_result`, `contradiction_result`, `outcome`, `reason_codes[]` | Outcome is `supported`, `rejected` or `inconclusive`. Unsupported comparator, incomplete range or disputed source remains inconclusive. Any hallucinated span, added command or unsupported claim is rejected. |
| `ResearchReview.v1` | `candidate_digest`, `check_digest`, `reviewer_id`, `decision`, `reasons[]`, `reviewed_at` | Decision is `accept-for-verification`, `reject` or `needs-evidence`; it only queues independent research. It is never a publisher authorization, Evidence attestation or local approval. |

`producer` is a discriminated record with `kind=deterministic` plus parser revision or `kind=model` plus provider and model IDs, prompt/template digest, response digest and usage. The model interface receives only bounded advisory text and returns bounded bytes. It exposes no tools, network or filesystem actions. Input snapshots and prompt template are versioned locally. Max input bytes, output bytes, tokens, elapsed time and call budget are fixed per test run and audited. A failed provider call produces an explicit inconclusive record, with zero candidate claims.

## Deterministic non-AI baseline

Use a local corpus of signed or otherwise pinned trusted advisory snapshots. The first corpus fixture set should include at least one example for affected exact version, fixed version boundary, unaffected ecosystem, alias or package name ambiguity, contradiction, revision correction, withdrawn advisory, missing provenance, malformed record and prompt-injection text. Maintain a separate immutable `corpus-manifest` with raw SHA-256, expected package identity and range interpretation, reviewer adjudication, version comparator and source-provenance status. The test can use synthetic OSV-shaped records and explicit license metadata. It must not claim those records came from live OSV or other external authorities.

The baseline parser extracts only explicitly structured fields from supported local schema versions, normalizes PURL or ecosystem/name with a pinned rule, evaluates only a named ecosystem comparator, validates citation paths against the same snapshot and emits `ResearchCheck`. A `missing`, `unknown` or unsupported range stays inconclusive. It does not infer affected versions from unstructured prose. A deterministic parser version and corpus digest identify every run. Repeat the same run to prove stable candidate digests and reason codes.

## Evaluation and independent challenges

Run the deterministic arm first, then the optional model arm on the identical pre-registered corpus and adjudicated truth. Report per-arm eligible advisories, attempted inputs, parsed inputs, candidate claims, supported/rejected/inconclusive outputs, true positives, false positives, false negatives and true negatives. Specify whether the unit is an advisory, package claim or version point before calculating precision or recall. Include abstentions in coverage and the denominator, with a separate conditional precision on answered cases. Report p50/p95 elapsed time by stage, CPU and memory, and for model runs input/output tokens, call failures, censored timeouts and cost according to the provider's recorded rate card. Use repeated paired trials with pinned prompts and order randomization; do not extrapolate from one fixture.

The independent validator should inject an instruction-looking advisory body, forged source URI, mismatched digest, untrusted correction, stale withdrawn revision, malicious JSON, oversize text, unsupported version syntax, cross-ecosystem collision, unsupported VEX assertion, hallucinated source span, duplicate advisory IDs with differing bytes, model refusal and provider timeout. Expected result is rejection or explicit inconclusive with zero native signed artifacts and zero protected writer effects. Check that the deterministic arm performs no provider call and no external network request.

## Open research decisions

- Which advisory authorities and redistribution licenses are authorized for real enrollment? Local synthetic snapshots suffice for initial tests.
- Which OSV ecosystem comparator implementations and package alias policies can be reused without silently converting ambiguous ranges into supported claims?
- How should a withdrawn or corrected advisory invalidate prior candidate digests while preserving audit history and reviewer decisions?
- What confidence vocabulary can reviewers interpret consistently, and how should it be calibrated against held-out adjudicated examples?
- Which later interface converts reviewed research into a new Evidence submission without giving the investigator a publisher or verifier credential?

No performance or accuracy result is asserted by this preparation document.
