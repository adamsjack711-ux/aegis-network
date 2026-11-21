# h84 Stage A owner review

**Offline preflight.** The proposed trial is one identity query on the original
sealed synthetic h84 fixture, based on integration commit
`056b7d4cc11fa665196aeca886a3ca488db34213`. It measures whether one observed
reply supplies the complete identity set. The independent h84 gate and
scratch-history results used scripted drafts.
[Independent h84 gate](../benchmarks/phase6-two-stage-independent/offline-h84.md) ·
[Independent scratch review](../benchmarks/phase6-two-stage-independent/offline-h84-scratch.md)

## Exact export

| Canonical UTF-8 bytes, without a trailing newline | Length | SHA-256 |
| --- | ---: | --- |
| Stage A create body | 1,450 | `92b5e3a2318e5221b11749e2e536efc183b034a4b7dbabd07d58fb6cfd622e20` |
| Count projection | 1,387 | `2decf8568cdda2ac4d1933cb642c49d82d780701bd9f72123df568f862f8cd25` |
| Create body's decoded `input` string | 438 | `ee08d952541663db8b1ec7aebf6f10b10ae5df79ebb3f2f6c9e0de0ba20dd521` |
| Create body's decoded `instructions` string | 451 | `9e8568e692d0051c42d9a73fd8a36a2f560383b7c359abcedb6ba62758f36d51` |
| Canonical `text.format` object | 323 | `8ac8411591eeabf0a8f06aa8b97f85e088f1008c9008a25a5f329207f3a18d00` |

The create body uses `gpt-5.4-mini-2026-03-17`, `service_tier="default"`,
`store=false`, an empty tools array, `tool_choice="none"`, and a maximum of
512 output tokens. The count body projects the identical `input`,
`instructions`, `model`, `text`, `tool_choice`, and `tools` fields. Its
intended endpoint is `POST /v1/responses/input_tokens`. Create uses
`POST /v1/responses` on the same approved HTTPS host, `api.openai.com`.
[Existing one-shot contract](studio-phase6-openai-one-shot.md)

The input discloses the synthetic npm target package `pinevell-stage` and
three candidate identities, two npm and one PyPI, in their sealed source
order. Each candidate includes an opaque request-local ID, ecosystem,
package, `purl=null`, and `purl_present=false`. The instructions ask for the
complete identity set and require abstention for ambiguous identity. Target
version, source row text, selection labels, source digests and pointers,
advisory and inventory IDs, paths, grants, and history stay local. The create
and count endpoints would also receive ordinary HTTPS metadata and the
designated project bearer credential for authentication.

`text.format` uses strict `json_schema` named `identity_selection`. Its
closed object requires `identity_outcome` with enum `match`, `no_match`, or
`unknown`, and `selected_row_ids` as an array of strings. The local
`IdentityDraft` parser and complete-set verifier validate the native reply
and its selection before any Stage B preparation.

## Operator prerequisites

1. Review and authorize the two exact exports independently. Confirm the
   designated project's effective retention, data-sharing setting, endpoint,
   model, and credential reference. `store=false` is the saved-response
   setting. Record the separate project retention and sharing decisions.
2. After count authorization, obtain and retain an HTTP 200 count receipt
   for the exact 1,387-byte projection. Record the endpoint, attempt count,
   model, request SHA-256, positive integer input-token count, HTTP status,
   and outcome. Review the receipt digest. Use that h84 count and the
   512-token output ceiling with the reviewed rates and any fees to assess
   the proposed spend. The prior m82 signed basis treated this calculation
   as an estimate with residual billing risk. The owner must make a new
   h84 decision. Confirm actual create usage and billing separately.
3. Before create, have the owner bind a fresh signed, expiring approval to
   the operator UID, exact create and count digests, count receipt, model,
   endpoint, limits, spend basis, credential reference and retention record.
   Use the reviewed owner-controlled Ed25519 verifier enrollment and
   independent readback. Keep approval and receipt files owner-only.
   [Operator enrollment and approval precedent](studio-phase6-openai-owner-handoff.md)
4. The existing m82 signer and launcher bind the m82 plan and receipt.
   An h84-specific caller still needs review. It must pin the h84 plan and
   exact bytes, verify owner approval, and claim a durable exclusive
   attempt before credential access. Reuse `complete_responses_once` with
   `IdentityDraft`, the approved input-token bound, and the existing
   10-second deadline, 12,000-byte request, 16,384-byte response, and
   4,096-byte draft limits. The contract allows one create attempt and
   zero retries, including on an uncertain failure.

The h84 count receipt, final spend basis, approval, and reviewed create
caller are pending. This preflight records the review bytes and has no
dispatch entry point.

## Rebuild Stage A from a clean checkout

Run in the candidate checkout with CPython 3.12 and the reviewed local
project dependencies. The files contain the exact bytes to inspect.

```sh
(
  set -eu
  umask 077
  export PYTHONPATH=src
  preflight=benchmarks/phase6-offline-fixture-freeze/h84_identity_preflight.py
  review_dir=$(mktemp -d)
  python3.12 -B "$preflight" create > "$review_dir/h84-A.create.json"
  python3.12 -B "$preflight" count > "$review_dir/h84-A.count.json"
  wc -c "$review_dir"/h84-A.*.json
  shasum -a 256 "$review_dir"/h84-A.*.json
)
```

## Stage B is a separate review

Use only the owner-retained, observed Stage A response. Reconcile the
create authorization and attempt marker with the HTTP, response and
transport records before running offline review. The input directory uses
the existing receipt naming convention with prefix `h84-two-stage-A`.

| File suffix | Evidence checked during offline review |
| --- | --- |
| `.attempt.json` | Integer `attempt=1` and the exact Stage A `request_sha256` |
| `.http.json` | Integer `http_status=200` |
| `.response.json` | Exact bounded native response bytes, parsed as a completed typed Stage A reply under the approved limits |
| `.transport.json` | `evaluated_contract_body_sha256`, exact `response_sha256` and native `draft_sha256`, `model`, `input_tokens`, and `output_tokens` |

The replay matches the local records. Request provenance depends on the
operator's custody and reconciliation. The receipts provide no provider
attestation of the request hash. After the envelope and receipt checks, the
review passes the original UTF-8 draft bytes to the existing linked B
renderer, which verifies the complete identity set from the sealed inputs.
Abstention, partial selection, and receipt or reply failures emit zero B
bytes. Scripted drafts and oracle admissions are outside this live handoff.

After an observed A reply has been reconciled, set `receipts_dir` and
`approved_a_input_tokens` from the operator records. Render into a fresh
private review directory and record the exact B byte count and digest.

```sh
(
  set -eu
  umask 077
  export PYTHONPATH=src
  preflight=benchmarks/phase6-offline-fixture-freeze/h84_identity_preflight.py
  review_dir=$(mktemp -d)
  python3.12 -B "$preflight" linked-b "$receipts_dir" "$approved_a_input_tokens" \
    > "$review_dir/h84-B.create.json"
  wc -c "$review_dir/h84-B.create.json"
  shasum -a 256 "$review_dir/h84-B.create.json"
)
```

Give B its own export, supported count projection, count receipt, approval,
and exclusive attempt. The Stage A approval covers Stage A only.
