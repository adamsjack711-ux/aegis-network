# Independent offline validation of OSV row selection

**PASS for single-advisory OSV selection** at `076ca6558b0079a3bf03426441298ec2ec2d75a4`. The candidate handled all 16 scripted attempts as specified under the OSV union interpretation. It emitted five supported pointers and zero false affected or false unaffected decisions. Under the pre-frozen conservative Aegis interpretation, one result is false affected. These scores apply to this offline checker. This review covers no write or promotion to Investigator history.

Seven source fixtures, labels, 16 selections and the primary scoring rules were frozen at `cc5a8f90fa479ac5ede14b3d40eff19cc983e546`. After main specified the single-record union rule and before any candidate run, VAL recorded a separate interpretation and six interface checks at `723e3b1688e0ac22426e142825e031102c0f9e8f`. The single-case preselection for the coordinator was s43 at `4811e17a43d0d820611ef750f3e10758dc856490`. Its canonical label hash is `08122d5e00f1d4f5b318ca0cd2c848d7318b82672c1eeab066e9ad690617f954`. All labels, including pointer choices, stayed outside prepared requests.

## Observed decisions

The curator scripted both the proposed decisions and selected rows. The checker generated the opaque IDs at runtime, checked source identity and version support, and emitted these decisions. A dash means zero released pointers. Reference numbers denote indices in the original affected array.

| Run | Fixture | Scripted decision and selected indices | Observed decision | Released indices |
|---|---|---|---|---|
| r01 | s17 | affected, 2 | affected | 2 |
| r02 | s43 | unaffected, 0 | unaffected | 0 |
| r03 | s26 | affected, 1 | affected | 1 |
| r04 | s91 | unknown, none | abstained | — |
| r05 | s68 | unknown, none | abstained | — |
| r06 | s32 | unknown, none | abstained | — |
| r07 | s54 | affected, 1 | affected | 1 |
| r08 | s17 | affected, 0 (wrong ecosystem) | refused | — |
| r09 | s43 | unaffected, 1 (wrong package) | refused | — |
| r10 | s26 | affected, 2 (decoy after reorder) | refused | — |
| r11 | s68 | affected, 0 (matching interval) | affected | 0 |
| r12 | s32 | unaffected, 1 (missing versions) | refused | — |
| r13 | s43 | affected, 0 (exclusive fixed endpoint) | refused | — |
| r14 | s17 | unknown, none | abstained | — |
| r15 | s17 | affected, 2 and 1 (correct plus decoy) | refused | — |
| r16 | s54 | affected, unissued ID | refused | — |

The first seven runs cover each fixture once. The remaining nine deliberately stress the guard. The checker verified five selections, accepted four explicit abstentions and refused seven drafts. All 11 abstentions or refusals yielded reportable unknown with zero references.

| Scoring axis | OSV union | Conservative Aegis |
|---|---:|---:|
| Primary decisions matching case labels | 6/7 | 7/7 |
| Primary determinate cases with correct decision and source coverage | 4/5 | 4/4 |
| Expected guard behavior, all scripted attempts | 16/16 | 15/16 |
| False affected / false unaffected, all attempts | 0 / 0 | 1 / 0 |
| Misses on determinate targets, all attempts | 8/13 | 7/11 |
| Correct pointer identity in scripted submissions | 7/13 | 6/13 |
| Correct pointer identity in released selections | 5/5 | 4/5 |
| Correct digest, byte span and source pointer for released rows | 5/5 | 5/5 |

Only **s68** changes interpretation. Its first target row includes version 2.2 in [2.0, 2.5); a second target row enumerates 3.1. For one OSV record a matching positive row establishes inclusion. The primary scripted abstention r05 is therefore a union miss. The r11 positive is correct for OSV and is false affected under the conservative Aegis rubric, which requires withholding a determination on these mixed rows. For s91 and s32, both rubrics require abstention on missing identity or version evidence. This experiment measures the checker on scripted selections, including intentional misses. Model selection ability remains unmeasured. [OSV evaluation algorithm](https://ossf.github.io/osv-schema/#evaluation)

## Reproduction and boundaries

From this evidence directory, run `python3 score.py /path/to/076ca65-checkout` using the reviewed Python environment. Compare its JSON with [the observed results](observations.json). VAL ran the scorer under an OS network-denial policy and reran all 23 selector tests. Every prepared request contained the target and all candidate rows with identical row fields. Representatives with reordered rows, duplicate JSON fields, excessive rows, and oversized source/request/draft passed their frozen expectations. The whitespace-preservation control resolved the original noncanonical bytes. All seven source digests matched the seal. The s43 prepared-request hash was `d9b0be472583b04e4570769be65e414d479bbf407812603245b6eab555904350`, which identifies the local preparation object before any provider envelope.

The negative controls share fixtures with the primary runs and do not constitute independent samples. The reviewer made no API calls or product changes. The coordinator owns any separately authorized live trial.
