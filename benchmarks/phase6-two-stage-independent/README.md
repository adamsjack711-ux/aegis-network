# Independent two-stage offline verdict

**PASS** for the standalone verifier at `533508fbe6f915b098dcde33dc68f9996a54f440`. VAL sealed 12 unseen synthetic OSV source/target pairs at `46b55669f9534e6307260c98c245bf7f62734227` before viewing candidate outputs. The label SHA-256 is `2f134eeb764cc80a869956913793e5c143dccb30c7cd032328468c502ad4fa3d`. The freeze includes exact original and reversed source bytes, target bytes, independent pointer and span bindings, 16 negative controls, policy expectations and a fixed 2026-11-20 00:00 UTC clock. The source hashes are distinct from the two previous holdouts. The case types deliberately recur.

## Primary observations

| Case | A identity outcome and matched row indices | Oracle B | Linked B | Accepted B row indices |
|---|---|---|---|---|
| h28 | match 1 | affected | affected | 1 |
| h53 | match 2 | unaffected | unaffected | 2 |
| h31 | match 0 | affected | affected | 0 |
| h84 | match 0, 2 | unaffected | unaffected | 0, 2 |
| h46 | match 2 | affected | affected | 2 |
| h79 | match 0 | unaffected | unaffected | 0 |
| h62 | match 1 | affected | affected | 1 |
| h14 | match 0 | unaffected | unaffected | 0 |
| h90 | no match | ineligible | blocked | none |
| h37 | unknown, inconsistent PURL | ineligible | blocked | none |
| h75 | match 1 | unknown, missing version data | unknown | none |
| h19 | match 0 | unknown, unsupported range | unknown | none |

A returned the correct decision and complete set on **12/12** cases, including 10 matches covering 11 row IDs, one verified no-match and one warranted abstention. There were zero missing or extra IDs, false no-matches or missed determinate identities. A received only source/target bytes at render time. Its exposed rows had uniform identity fields and opaque IDs. As an additional check, changing all version evidence and target versions left A's rendered request hashes identical.

Oracle B ran on **10 eligible cases** and linked B accounted for **all 12**, including two blocked before version evaluation. Each arm resolved **8/8** determinate cases (4 affected, 4 unaffected), abstained correctly on **2/2** indeterminate versions, and had zero false affected, false unaffected or missed determinate decisions. Within each arm, **9/9** emitted references matched the independent source digest, pointer and exact original byte span. For the ten admitted cases, oracle and linked request hashes were identical: the two arms are diagnostic comparisons, not independent samples. B received only the target version as context and all admitted rows with their original bytes. The renderer received no decision labels or decisive citation hints.

All **12/12 paired reversals** preserved identity, version decisions and referenced row content after remapping positions. They are excluded from the primary denominator.

## Failure isolation

All **16/16** frozen negative-control scenarios matched expectations. Six invalid identity drafts were refused and blocked their linked B runs. Of those six cases, five remained eligible for oracle B: four resolved and one correctly abstained. The sixth had ambiguous identity and no oracle version result. Eight additional B controls ran in both arms: seven invalid drafts were refused in each arm, and one deliberate abstention on a determinate case was counted as a diagnostic miss in each arm. Two invalid oracle admissions were blocked. Refused, abstained and blocked version decisions emitted zero citations. No unsupported decision or citation was released.

The separate frozen h62 mixed-row control returned **affected** under single-record OSV union and **conflicting** through the pinned Aegis assessment. The latter would require a hold at a future history boundary. The evaluator issued no history writes. Freshness, withdrawal and supersession write-boundary expectations are frozen, with transaction and persistence behavior still untested on this path. [Mixed-policy observation](mixed-policy.json)

The curator supplied the selections and proposals for every run. These results measure validation, not model performance or the cause of the historical s43 miss. No discrepancies from the frozen primary or control expectations were observed.

## Reproduce

From this directory with the reviewed Python dependencies, run:

```sh
(cd seal && shasum -a 256 -c SHA256SUMS)
python3 score.py /path/to/533508f > /tmp/two-stage-observed.json
python3 summarize.py /tmp/two-stage-observed.json
python3 policy_check.py /path/to/533508f
```

The independent run used an OS network-denial policy. All 20 focused two-stage tests also passed on the exact candidate. [Raw observations](observations.json) · [Scores and status counts](scores.json) · [Frozen scoring rules](seal/oracle/scoring.md)
