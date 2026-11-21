# Offline OSV evidence selection

This local synthetic trial presents all affected rows from one OSV document.
The model-facing object has the same two keys for every row, `row_id` and
`osv_row`. The row string preserves the original JSON lexeme. IDs are opaque
and bound to the source digest, target and row position. The source digest,
locations and verdict stay out of the model-facing object. The separate
`asset_context` identifies the package and version and supplies no citable
evidence. The request gives the verifier's generic rules without an expected
answer or selected rows.

## Run offline

Use the reviewed Python 3.12 environment. Supply a raw UTF-8 synthetic OSV JSON
file, and a second JSON file with exactly `ecosystem`, `package` and `version`.
The CLI accepts an existing local draft file and never calls a model.

```sh
script=benchmarks/phase6-offline-fixture-freeze/osv_row_selection.py
PYTHONPATH=src python3.12 -B "$script" prepare synthetic-osv.json target.json > prepared.json
PYTHONPATH=src python3.12 -B "$script" check synthetic-osv.json target.json draft.json
```

Use `instructions` plus `payload` to construct the scripted selection input.
The prepare report also carries the local source and request digests.
The draft has exactly `proposed_outcome` and `selected_row_ids`. Its outcome
is `affected`, `unaffected` or `unknown`. Copy the opaque IDs from the
prepared rows into the scripted selection. An abstention uses
`{"proposed_outcome":"unknown","selected_row_ids":[]}`.
The Python entry points are `prepare(source_bytes, target_bytes)` and
`check(source_bytes, target_bytes, draft_bytes)`.

## Local scoring contract

- For affected, each selected row must independently match the ecosystem
  and package and include the target version. A selected exclusion,
  unsupported row or different identity fails the selection. OSV rows for
  one package can describe a union of intervals. An unselected exclusion
  alone does not override a supported inclusion. The product matcher has a
  separate conservative conflict policy and remains unchanged.
- For unaffected, every matching row must be evaluable, exclude the target and
  be selected. One possible inclusion, ambiguous identity or unsupported
  matching row blocks the decision. A missing matching row cannot establish
  unaffected.
- An empty abstention exits 0 with `status=abstained` and zero references.
  A wrong, duplicate or stale ID, incomplete evidence or contradictory
  selection exits 1 with `status=refused`, reportable unknown and zero
  references.
- A verified selection returns each selected ID, the original source
  SHA-256, the `/affected/N` pointer, the half-open byte offsets and the
  exact row text. It finds positions by walking JSON tokens. Repeated literal
  rows have different pointers, IDs and offsets.

The experiment supports synthetic PyPI and npm identities, numeric dotted
versions, explicit version lists, and ordered introduced/fixed events in
`ECOSYSTEM` or `SEMVER` ranges within that numeric subset. Introduced is
inclusive, fixed is exclusive, and an unclosed final introduction is open.
Unsupported version grammar, extra matching-row applicability fields and
inconsistent identity metadata remain indeterminate. There is no full native
ecosystem comparator, source authentication, model accuracy claim or live
provider route. The existing m82 launcher and product offline gates are
unchanged.

Limits are 16 rows, 24,000 source bytes, 1,024 target bytes, 12,000 rendered
request bytes including instructions and JSON framing, and 4,096 draft bytes.
The check refuses overflow before any partial projection or citation.
