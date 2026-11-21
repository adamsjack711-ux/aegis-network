# Offline h75 version-only probe

This handoff prepares one oracle Stage B request with the original h75
OSV and target bytes from `46b5566`. It uses the frozen admission
`/affected/1` from
`a6ce6fe:benchmarks/phase6-two-stage-independent/preselection-h75.json`.
The case has one target version and one identity-admitted row with no
version evidence. Stage A and the wrong-ecosystem decoy are outside this
request. The bridge preserves the h28 and h53 bodies, native B builder,
typed parser and limits.

| Bytes hashed | Length | SHA-256 |
| --- | ---: | --- |
| Exact serialized create body | 1,189 | `4ba3b36148fecd4c4b081d0731cfb5a2e8bec1594c3b1a9d7499358a90e661b0` |
| UTF-8 bytes of the create body's `input` string | 172 | `473525251c76d2c8242ee1113c4651021e29e524099925a2807edac30eae20b3` |

The frozen local preparation hash including the instructions is
`4b718bf90275996488bc45a738dc6672016a96bdb53723df20670cf14e56679a`.
The request has no expected answer, source pointer, case label or oracle
labels. The unchanged strict `version_selection` schema is a closed JSON
object requiring `proposed_outcome` (enum `affected`, `unaffected`, or
`unknown`) and `selected_row_ids` (an array of strings). Semantic acceptance
remains local.

From the candidate checkout with the reviewed Python 3.12 environment:

```sh
export PYTHONPATH=src
script=benchmarks/phase6-offline-fixture-freeze/two_stage_trial.py
python3.12 -B "$script" B --case h75 > h75-B.json
shasum -a 256 h75-B.json
python3.12 -B "$script" B --case h75 --response "$retained_response"
```

An empty `unknown` draft is a warranted abstention, with zero references.
Any determinate proposal is unsupported on this fixture. Record the raw
proposal and local refusal separately from model abstention. There is one
required abstention opportunity and zero determinate version opportunities.
Pointer precision and recall are undefined with zero expected and released
references. The offline replay reports its contract hash and leaves request
provenance unverified. No request was sent during this preparation.
