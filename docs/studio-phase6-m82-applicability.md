# Corrected standalone m82 applicability trial

The corrected request uses the exact provider-accepted v1 `text.format`
content, name and property order. Its foreground Responses envelope keeps
the same snapshot model, standard tier, `store=false`, disabled tools and
512-output-token maximum. Only `input` and `instructions` change. The request
includes the synthetic package and version under non-citable `asset_context`.
Its sole source is the continuous `/affected/0` package-and-range row copied
from the sealed OSV bytes and bound to the original source digest. The
unrelated summary, eligibility answer and historical draft stay local. The
instructions describe generic OSV interval semantics, with `introduced`
inclusive and `fixed` exclusive. [Structured Outputs reference](https://developers.openai.com/api/docs/guides/structured-outputs)

| Request | Exact create SHA-256 | Result |
| --- | --- | --- |
| Original v1, 2,914 bytes | `ca82ce718189b2d7ba48137b0220391b09038fa6bbf2d794d825e6b72121085b` | The wire schema was accepted. The historical draft misattributed outer asset context to S1 and cited the unrelated summary as impact. Replaying the original checker returns rejected, reportable unknown. |
| Rejected v2, 2,167 bytes | `753a0c923658f1a371c701e9719988a68596558bdbe04e2ab23c45adaca74c4b` | The one POST returned HTTP 400, `invalid_json_schema` for `text.format.schema`, with no draft. The retained receipt does not identify the exact rejected keyword. Rebuild with `17e3f4b`. |
| Corrected v3, 2,980 bytes | `e90bc1b7aab14d23f9c535e8f3faafb8eaea4bb724e389c3b7a447a0982eedfe` | The coordinator’s single POST returned HTTP 200. The offline recheck returned research-consistent and reportable unaffected. |

For the corrected run, provider-reported usage was **423 input / 104 output
tokens**. One exact S1 citation resolved to `/affected/0`, with structured
and reportable outcomes both `unaffected`. The retained result bytes,
SHA-256 `abb94e1596789dfa8584e5a28092495a6181751b94d8fa145238d4ff64c7ef1d`,
reproduced that outcome with the offline `check-result` command below.
The v3 run used no count request. Billing and independently measured model
accuracy remain unverified. The trial covers this single synthetic case.

The 1,549-byte tail after the top-level `"text":` delimiter, including the
closing wrapper, has SHA-256
`f4ec19c40b7704c62115d30239acf49c4a6e064a4430c8f14f38d2bebf37a18f`
in both v1 and v3. The v2 HTTP summary SHA-256 is
`0c4b2bec3afe20289a4cffd8bacc33b7296e1bf768060879ce45518434f0e5b6`.
The original raw v1 reply has SHA-256
`334d469387f08c0f40ef3e207eda81cdd469e14ea984cdb585ffd4840bc0dfc1`.
The files remain in the local request review directory.

## Offline commands

Use the reviewed Python 3.12 environment from the worktree. The builder
requires the exact approved v1 bytes as a schema source. This does not admit
the v1 approval or make a count request.

```sh
base=benchmarks/phase6-offline-fixture-freeze
v1="${AEGIS_M82_ACCEPTED_REQUEST:?set to the frozen v1 body}"
stage=$(mktemp -d)
git show aec2456:benchmarks/studio-offline-citation-support/unseen-holdout-39d580a/seal/inputs.json > "$stage/inputs.json"
PYTHONPATH=src python3.12 -B "$base/m82_applicability.py" build "$stage/inputs.json" "$v1" "$stage/request"
PYTHONPATH=src python3.12 -B "$base/m82_applicability.py" check-draft "$stage/inputs.json" "$v1" "$draft_json"
PYTHONPATH=src python3.12 -B "$base/m82_applicability.py" check-result "$stage/inputs.json" "$v1" "$raw_responses_json"
```

The build emits `create.json`, `manifest.json` and the uncalled
`count-projection.json` (2,024 bytes, SHA-256
`1dcd3825c83000369b0f5eae7ac4935ca0dc74641649a90fb6dd49a7d115dce8`).
The check commands label the evaluated contract digest separately from
the input result or draft digest. They mark input request provenance
unverified. Result inspection has no current count or verified billing.

## Local acceptance and transport

The reused schema can represent kinds and quoted text beyond the task.
The local decoder requires empty `uncertainties`. A decision requires
exactly one `applicability` claim for `S1` with the whole allowed row
verbatim. Abstention requires `unknown` with no claims. Other source IDs,
the context quotation, summary, impact, shortened or altered citations,
extra claims and conflicting outcome are refused. An exact-row proposal
of affected reaches the unchanged Investigator, which yields reportable
unknown under the local structured unaffected decision. The historical
offline gates and source matcher are unchanged.

`m82_applicability.complete_m82_applicability(sealed, *, accepted_request,
approved_body_sha256, input_token_limit, credential_reader, deadline_seconds=10,
connection_factory=HTTPSConnection, error_body_path=None)` calls the shared
transport. The coordinator owns approval and the single-attempt marker.
The accepted request argument is raw frozen v1 bytes used solely for
the schema. Pass the exact approved v3 body digest. The positive
`input_token_limit` applies only after a response arrives. It does not
enforce the actual charge. There is no count call or count-receipt
parameter. The normal legacy decoder remains the default. The transport
calls the v3 decoder after envelope and usage checks and retains the
raw response and raw draft digests in the checked report.

For future authorized attempts, optionally pass a new error-body path in an
owner-only directory. On HTTP 4xx or 5xx the transport retains eligible raw
error bytes locally at mode 0600, up to 16,384 bytes. It refuses oversized,
incomplete or encoded bodies or an exact credential echo. The returned
error message only reports the status and whether diagnostics were stored.
The same deadline covers error reads. The offline CLI never dispatches.
