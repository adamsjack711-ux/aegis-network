# Phase 5A — read-only vulnerability intelligence

**Implementation pin:** `feat/phase5a-intelligence`, based on Phase 4E `ee739cacfaa3f81a0994b4d7802fd2943c067d86`. This branch adds private research records. It does not change `Finding 1.0`, Mesh subjects, Evidence signatures, Rapid decisions, approval, or the protected writer. Research reports cannot be cast as verified Evidence or authorize mitigation. The Phase 5 authority map and owner proposal are design inputs, not adopted shared contracts.

## Architecture and source choices

`local pinned advisory bytes → digest and timestamp → deterministic parser → preserved source claims → conservative asset appraisal → optional bounded JSON provider → citation and schema checks → read-only report`.

The executable accepts only local fixture snapshots and an explicitly named local target. `FeedClient` describes allowlisted official source URIs but its `fetch()` method always rejects; no network transport is shipped in this implementation. No external target, feed, or model was contacted in this phase. The default path uses no provider. A caller may inject a local `JSONProvider` implementation into `research()` for isolated experiments, but this does not supply publishing or verification authority.

| Source | Official interface and parsed fields | Current limit |
| --- | --- | --- |
| NVD CVE | [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities): ID, English description, CVSS, CPE match criteria and version bounds. | CPE Boolean configuration context is retained but never automatically resolved into a conclusive asset result. NIST's [August 2026 update](https://www.nist.gov/itl/nvd) changed audit-history delivery of affected data; current CVE records are the planned input. |
| OSV | [OSV API](https://google.github.io/osv.dev/api/) and [OSV range schema](https://github.com/ossf/osv-schema/blob/main/docs/schema.md): ID, aliases, ecosystem, PURL, explicit versions and introduced/fixed events. | Only simple numeric dotted `ECOSYSTEM` and `SEMVER` ranges are evaluated. Git, prerelease, epochs and ecosystem-specific ordering abstain. |
| CISA KEV | [CISA's catalog and JSON mirror](https://github.com/CISAGov/kev-data): CVE, vendor/product, date added and known exploitation. | KEV is an exploitation signal, not an affected-version list. Its count is checked; version appraisal remains unknown. |
| Vendor advisory | [GitHub repository security advisory API](https://docs.github.com/en/rest/security-advisories/repository-advisories): GHSA/CVE aliases, package ecosystem, vulnerable range, first patched version, publication and withdrawal. | Only explicitly enrolled repository names are planned for retrieval. Simple numeric comparison syntax is supported. Other vendor bulletins require a reviewed adapter and source enrollment. |

Each `SourceSnapshot` holds original bytes, acquisition label, URI, retrieval time and SHA-256. Normalized claims retain a source pointer, source digest, affected and fixed version expressions, severity, exploitation indicator, publication/modification/withdrawal times, confidence label and missing-data reasons. `archive_snapshot()` writes the raw bytes under their digest without overwriting a prior pin. A URL alone does not authenticate a source. Offline fixtures are labeled `fixture`; the `https` label is reserved for a later enrolled collector. Duplicate JSON keys, mismatched IDs, malformed feed roots and inconsistent KEV counts fail parsing.

The baseline compares an exact asset package identity and a supported version expression. It returns `unknown` for missing identities, unsupported versions, old snapshots, withdrawn advisories and NVD configuration logic. It returns `conflicting` when matching sources disagree. It never silently chooses the latest or most severe claim. The default freshness limit is seven days from retrieval and is a research policy, not Evidence status. Source corrections retain separate digests; callers should archive both revisions and investigate the conflict.

The source confidence vocabulary describes provenance class only: `fixture`, `aggregated`, `vendor-published`, and `official-record`. It does not grade truth or supply independent verification. The repository's patch-gap and predictive-risk research motivated separate treatment of affected build, reachable code and exploitation prerequisites. This pipeline currently assesses only structured package/version claims; it does not establish reachability or actual vulnerability in a deployment.

## Provider boundary

`JSONProvider.complete_json()` is model independent. The first worker sends a bounded fact set, the asset alias `asset-1`, and an allowlisted version string. It withholds local asset ID, configuration text and package name. Source summaries and ranges are marked as untrusted data in the instructions; the provider receives no tool definitions. A provider response must be strict JSON with known fields, cited fact IDs, bounded text and lab experiment descriptions. Unknown citations, extra fields, oversized output and common command syntax are rejected. `independently_verified` is always false. Citation presence establishes only a link to a supplied claim, not semantic support for the model's prose; human review remains necessary.

No external model adapter is shipped in this phase. A future adapter should use an empty tool list, no stored conversation, a fixed output-token cap, a hard timeout and bounded retries. The [Responses API reference](https://developers.openai.com/api/reference/resources/responses/methods/create) documents possible request fields; this is design guidance, not an implemented provider. The provider interface records model/version and token usage supplied by the local provider. The configured input byte ceiling includes instructions and payload. Input and output token prices must be supplied explicitly to calculate estimated cost. Timeout and retry enforcement for a future real model adapter remains an open gate. No credential is stored in the repository.

## Offline operation

From this worktree, with the repository environment installed:

```sh
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_research.py tests/fixtures/phase5a_request.json --output /tmp/aegis-phase5a-report.json
PYTHONPATH=src ../../.venv/bin/python scripts/phase5a_evaluate.py
PYTHONPATH=src ../../.venv/bin/python -m pytest -q tests/test_phase5a_intelligence.py
```

The request names one authorized target, local source files and their declared official-format URIs. The CLI reads at most 64 KiB for the request and 8 MiB per local source before parsing. It rejects a mismatched target, any `https` source mode, or any non-`none` research provider. It emits a JSON report with source pins, all normalized claims and an assessment. It does not sign, publish, scan a host, run a model, or change a defended target. The report is research input for human and independent Evidence review.

## Evaluation and limits

The synthetic [corpus](../tests/fixtures/phase5a_cases.json) and [manifest](../tests/fixtures/phase5a_manifest.json) fix 12 asset-vulnerability scoring points, raw source digests and author-adjudicated labels. Cases cover affected, fixed boundary, prerelease ambiguity, contradictory sources, KEV without versions, NVD configuration, ecosystem collision, stale data, withdrawal, instruction text, corrected range and alias ambiguity. The [raw offline benchmark](../benchmarks/phase5a-offline.json) records the exact corpus and manifest digests, each outcome, citation presence, latency, fixture token counts and zero API cost. The fixture model responses are scripted; their token counts are length estimates, not billed usage.

| Measure | Deterministic | Scripted provider |
| --- | ---: | ---: |
| Correct labels / all points | 12/12 | 12/12 |
| Binary TP / TN / FP / FN | 2 / 1 / 0 / 0 | 2 / 1 / 0 / 0 |
| Correct abstentions on uncertain or conflicting points | 9/9 | 9/9 |
| Conclusive coverage | 3/12 | 3/12 |
| Citation validity | Source pointers present | 12/12 source fact IDs valid |
| Improvement in correct points | reference | **0** |

This is a single synthetic fixture run. It demonstrates parser and boundary behavior, not real model accuracy, production source authentication, independent claim truth, or a statistically meaningful advantage. Unsupported prose claims have only author labels in this corpus; a real model run requires independent claim-by-claim adjudication, repeated paired trials, actual token/cost accounting and held-out cases. The small binary denominator makes precision and recall unsuitable for promotion. Live feed and model enrollment, license review, revision/withdrawal history, ecosystem comparators and a reviewed bridge into existing Evidence are future decisions. No source or model output from this branch has a path to protected authority.

The focused Phase 5A suite passed 9/9. A broader `PYTHONPATH=src:scripts` run was stopped after 103 passes, 32 skips, 28 failures and 10 errors because existing Phase 4 fixture services could not bind Unix sockets in this sandbox (`PermissionError: Operation not permitted`). The first plain full-suite attempt also lacked `scripts` on `PYTHONPATH` and stopped during collection. Neither run is a full-suite acceptance result. No shared source files were changed to address that environment limit.

## Private field map against the provisional contract

The preparation proposal names `AdvisoryInput.v1`, `ResearchCandidate.v1`, `ResearchCheck.v1` and `ResearchReview.v1`. This implementation does **not** adopt those formats. `SourceSnapshot` covers raw bytes, digest, URI and retrieval time but has no signed source identity, license or revision field. `Claim` covers normalized identity, version expression, fixed version, source pointer and missing facts but has no accepted candidate digest or reviewer decision. `Assessment` covers the deterministic outcome and reasons but is not a signed `ResearchCheck`. `ResearchResult` holds bounded cited model prose and usage but has no promotion status. A field-level migration and independent review are required before another component consumes these records as a shared contract.
