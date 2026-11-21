# Run the offline two-stage OSV benchmark

Use the reviewed Python 3.12 environment with the repository's dependencies.
All file inputs are local. Use a raw UTF-8 synthetic OSV object with an
`affected` array and a separate target JSON with exactly `ecosystem`,
`package` and `version`. Drafts are scripted JSON. [Evaluation design](studio-phase6-two-stage-evaluation.md)

```sh
export PYTHONPATH=src
script=benchmarks/phase6-offline-fixture-freeze/osv_two_stage.py
python3.12 -B "$script" prepare-a source.json target.json > prepared-a.json
python3.12 -B "$script" check-a source.json target.json draft-a.json
python3.12 -B "$script" prepare-b source.json target.json --arm linked draft-a.json > prepared-linked.json
python3.12 -B "$script" check-b source.json target.json --arm linked draft-a.json draft-b.json
python3.12 -B "$script" prepare-b source.json target.json --arm oracle frozen-identities.json > prepared-oracle.json
python3.12 -B "$script" check-b source.json target.json --arm oracle frozen-identities.json draft-oracle-b.json
```

Use only `instructions` and `payload` as the candidate-facing request.
Keep all evaluation labels and local report metadata outside that request.

- **A inputs and draft.** The target context contains ecosystem and package.
  Every row has the same shape, with opaque ID, ecosystem, package, an
  optional version-free PURL and a PURL-presence flag. Versioned, qualified,
  fragmented or malformed PURLs are suppressed and can make identity
  ambiguous. A does not export target version, range bytes or extra package
  fields. Identity IDs bind to this version-blind projection. A draft has
  `identity_outcome` (`match`, `no_match`, or `unknown`) and
  `selected_row_ids`. Match requires the full correct set. No-match
  requires locally verified absence plus no ambiguous identity. Unknown
  takes an empty set.
- **B admission and draft.** Linked B takes the raw A draft and rechecks it.
  Oracle B takes independently frozen `{"matched_pointers":["/affected/0"]}`
  and rechecks completeness independently of the A response. Neither arm
  admits a partial, forged or ambiguous identity set. Both use original
  source order, so the same admitted set gives an identical request and
  digest. B exposes target version plus each admitted row's original bytes
  under version- and source-bound IDs. Submit
  `{"proposed_outcome":"affected|unaffected|unknown","selected_row_ids":[...]}`
  with an actual outcome and IDs from that B preparation. A verified decision
  has original source SHA-256, JSON pointer, half-open byte offsets and the
  exact row text. B uses the existing standalone OSV union verifier.
- **Scoring.** Exit 0 means prepared, verified, or abstained. Exit 1 is a
  refusal of the requested stage. Exit 2 means B was blocked by upstream
  identity, including verified no-match. A blocked result has no B request
  or references. An abstention or refusal releases no references. Count
  linked blocks on the full case denominator and score oracle B separately.

The Python functions `prepare_a(source_bytes, target_bytes)`,
`check_a(source_bytes, target_bytes, draft_bytes)`,
`prepare_b(source_bytes, target_bytes, admission_bytes, *, arm)` and
`check_b(source_bytes, target_bytes, admission_bytes, draft_bytes, *, arm)`
return the same reports as the CLI. They share the standalone selector's
source/target/request/draft bounds and origination checks. Withdrawn input is
refused. Freshness and current-head verification require trusted history
state and remain outside this benchmark. The m82 launcher, product history
and normal offline gates retain their existing behavior.
