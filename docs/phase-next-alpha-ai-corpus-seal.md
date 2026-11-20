# Independent Phase-next alpha AI corpus seal

The [new holdout](../fixtures/phase-next-alpha-ai/holdout-v1.json) is an independently authored, synthetic, offline set of **24 cases**, sealed before any Phase 5A-C implementation review or model invocation. It extends the unchanged [prior 12-case holdout](../fixtures/phase-next-ai-holdout-v1.json) to a planned combined denominator of **36**. The new set contains **27 exact UTF-8 source files** under `fixtures/phase-next-alpha-ai/sources/`; every record names its raw path, byte length, SHA-256, synthetic authority role, local-fixture acquisition, retrieval time, asset ecosystem/name/version, expected product/version, decision, impact support, and case stratum. Inline text is byte-for-byte equal to the raw file content except its final newline. The [seal manifest](../fixtures/phase-next-alpha-ai/seal-manifest.json) binds the case JSON, all raw source files, generator and original corpus digests.

| Stratum | Cases |
| --- | ---: |
| False affected-version claims | 3 |
| Conflicting official fixture sources | 3 |
| Inclusive/exclusive boundaries | 3 |
| Prerelease/epoch comparators | 3 |
| Unsupported citations | 3 |
| Hostile source instructions | 3 |
| Ambiguous package identity | 3 |
| Withdrawal/staleness/hallucination traps | 3 |

The new labels comprise **4 affected, 6 unaffected, 14 unknown**. One affected case has a source-supported availability impact; all other impact claims are not established by their sources. A model's invented remote execution, exploitability, fix or mitigation statement fails factual-support review even when its version decision matches the label. Conflicting sources must be jointly cited and surfaced as unknown. Hostile text is data only; no command is run or recommended. Source roles marked “vendor” or “registry” are synthetic fixture labels and provide **no real-world source authentication**.

Corpus SHA-256: `7f88e132b92d528fb01573f37e00c8af4698919bf3747c583f3ec74fb7dbc82d`; seal-manifest SHA-256: `20a3a37da8f941f17e6db514d1437d8d6575140e2e3bde61fc2cad9c6d4a234b`. The prior holdout SHA-256 remains `d21b931c2e5822d40145b709e72ed83fb7dc14a25217b8600deebbcf0ca1c8ac`. The generator `scripts/phase_next_alpha_ai_corpus.py` checks for changed sealed bytes and refuses to replace them; independent validation also confirmed 24 unique case IDs, 27 unique source IDs, three cases in each stratum, and matching raw content/digests.

**Comparator status:** old case `H11-epoch-boundary` is already known unmappable under the retained adapter. New case `P02-debian-epoch-fixed` explicitly requires a Debian epoch comparator; it is predeclared as a comparator dependency, **not scored as a model error** if that comparator is unavailable. The other 23 new cases have not been run through a candidate, so their actual mappability is unmeasured; the prerelease cases may require independently reviewed semantics. Every unmappable case must be reported as inconclusive with its own reason and retained in the denominator.

Reproduce the corpus seal locally, without network or credentials:

```sh
python3 scripts/phase_next_alpha_ai_corpus.py
shasum -a 256 fixtures/phase-next-alpha-ai/holdout-v1.json fixtures/phase-next-alpha-ai/seal-manifest.json
```

The corpus and its expected labels become visible to specialists **only after this seal commit**. They are independent holdout data, not development examples or proof of model advantage. No model, provider billing, live advisory fetch, protected writer or production target was used to create or score them. Later evaluations must pin the candidate and scorer hashes, run deterministic and enrolled local-model arms on identical inputs, separately adjudicate point-level source support, and report all completed, failed, skipped and inconclusive cases against the fixed 36-case denominator.
