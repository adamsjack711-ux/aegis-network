# Offline h53 fixed-boundary probe

The offline bridge at this candidate adds the preselected **original h53**
fixture to the existing native A and oracle B routes. Its source and target
bytes are pinned to the seal at `46b5566`. The oracle supplies only
`/affected/2`, from
`f0c6330:benchmarks/phase6-two-stage-independent/preselection-h53.json`.
The builder validates that admission locally. It uses the same model, strict
native schemas, typed adapter and limits as h28. The h28 commands and body
hashes are unchanged.

| Arm | Bytes | Create body SHA-256 |
| --- | ---: | --- |
| A, identity only | 1,449 | `bcd7a58962ec8aebdb0e6cbf1012e8edc9f501158252a414cbd56833426ee375` |
| Oracle B, version on the admitted row | 1,320 | `6d3e172a61c815be80f6f7118d835d451b5e0981301ac1eb4232370603298924` |

A presents three identity rows and no version data. B presents only the
target version and original bytes of the one oracle-admitted row. Neither
body contains labels, decisive pointers, or the fixture name. The two
unwrapped preparation digests are independently pinned in the preselection.
Only the `instructions` and `input` fields derive from the prepared probe.

## Prepare and replay locally

From the candidate checkout in the reviewed Python 3.12 environment:

```sh
export PYTHONPATH=src
script=benchmarks/phase6-offline-fixture-freeze/two_stage_trial.py
python3.12 -B "$script" A --case h53 > h53-A.json
python3.12 -B "$script" B --case h53 > h53-B.json
shasum -a 256 h53-A.json h53-B.json
python3.12 -B "$script" A --case h53 --response "$retained_a_response"
python3.12 -B "$script" B --case h53 --response "$retained_b_response"
```

The native replay verdict checks the frozen criteria. A checks the full
identity set. Oracle B checks that version 2.7.0 is outside the admitted
interval at its exclusive fixed endpoint and checks the exact source span
`/affected/2`, UTF-8 bytes `[167,303)`. A positive at the fixed endpoint is
refused. Valid empty abstention remains observable. Replay calculates the
evaluated contract hash and leaves request provenance unverified. Match
retained replies to the independently captured attempt and wire body
before scoring. This handoff involved no live requests.
