# Phase 5A read-only intelligence architecture and contract freeze

Baseline `ee739cacfaa3f81a0994b4d7802fd2943c067d86`. This stream turns locally supplied, trusted advisory snapshots into reviewable candidate research. It has no path to the protected writer, local approval store or broker authority. No external advisory fetch or model provider is enrolled in this preparation phase.

## Pipeline

`pinned advisory snapshot → source authentication and parse → deterministic package/version extraction → optional bounded model research → schema validation → deterministic contradiction and provenance checks → read-only candidate report → human and independent verifier review`.

The non-AI arm uses the same advisory snapshot and deterministic parser/checker, with model calls disabled. Record eligible advisories and generated candidates in both arms. A later signed defensive finding requires the existing independent Evidence, publisher trust and local policy flow. Research output itself is never a signed verifier attestation or protected authorization.

## Proposed private contracts

| Record | Mandatory fields and semantics |
| --- | --- |
| AdvisoryInput v1 | Source namespace and stable advisory ID, canonical source URI, retrieved or supplied time, content digest, source signature or documented trusted-snapshot provenance, license or redistribution constraints, affected package ecosystem and raw immutable bytes. A URL string alone is provenance metadata. |
| ResearchCandidate v1 | Advisory digest and ID, source span or structured reference for each claim, normalized vulnerability ID, package URL or ecosystem/name, affected and fixed version expression with comparator type, confidence as an explicitly labeled research estimate, uncertainty and missing facts, proposed follow-up verification, model/provider identifier or `deterministic`, prompt/template revision, run ID and bounded resource usage. No command, executable mitigation or authorization field. |
| DeterministicCheck v1 | Parser version, input digest, field validity, package identity match, version-range evaluation or `unsupported`, contradictory claims, missing provenance, deduplication key and reason codes. Inconclusive is preserved as a first-class result. |
| ReviewDecision v1 | Reviewer identity, exact candidate digest, accepted/rejected/needs-evidence outcome, reason and time. It only controls research workflow. It does not alter native T4/T5 or Rapid policy. |

The existing signed Finding 1.0 and Revocation 1.0/1.1 and Evidence records retain their canonical bytes and trust rules. A model can quote adversarial advisory text, so instruction-looking text remains data and is excluded from tool authority. Bounded calls use allowlisted local fixture inputs, time/token/cost limits and deterministic output validation. Providers are pluggable behind a call interface. The default run requires no provider and no network.

## Acceptance criteria

1. A fixed, versioned local advisory corpus includes true affected, unaffected, conflicting, stale, withdrawn, malformed and prompt-injection examples. Record source digest, corpus version, denominator and ground-truth review method.
2. The deterministic arm emits schema-valid candidates or explicit inconclusive/rejected reasons for every corpus entry. No hidden model call or network access occurs. Golden outcomes cover package identities, version comparator boundaries, source links and contradictory advisories.
3. The optional model arm runs on identical inputs with fixed prompt/schema revisions and bounded resources. Invalid JSON, unsupported identities, hallucinated source spans, executable instructions and provider failure become rejected or inconclusive reports. No model result enters Mesh or the writer without existing independent verification and explicit local policy.
4. Compare arms using precision, recall, false positive and false negative counts with explicit denominators, inconclusive rate, p50/p95 latency, token or CPU usage and cost. Repeat trials and report variance and any censored failures. No benefit claim follows from a single fixture run.
5. A compromised coordinator, malicious advisory text or model response cannot create a valid native finding, verifier attestation, local approval or target action. Independent validation inspects outbound events and durable writer state.

Research questions include which advisory source identities and licenses qualify for enrollment, how ecosystem-specific version rules and aliases are normalized, how source corrections invalidate cached candidates, how human ground truth is adjudicated, and whether the optional model improves recall at an acceptable false-positive and cost budget. [Phase 0 reuse review](phase0.md) · [Evidence rules](phase4-contract-review.md)
