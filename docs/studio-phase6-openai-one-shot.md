# Studio Phase 6 OpenAI one-shot trial

The launcher is prepared for offline validation. **Live dispatch is on hold.**
The first caller is the sealed synthetic m82 revision 1. The request is the exact
2,914-byte reviewed body at SHA-256
`ca82ce718189b2d7ba48137b0220391b09038fa6bbf2d794d825e6b72121085b`.
It names `gpt-5.4-mini-2026-03-17`, standard service tier, `store=false`, zero
tools and a 512-token output maximum. The launcher verifies both the frozen
body and its contained logical projection before any approval or credential
access. [Single-call preflight](studio-phase6-live-trial-preflight.md)

## Callable boundary

`benchmarks/phase6-offline-fixture-freeze/openai_responses_adapter.py` exposes
`complete_responses_once`. The caller owns an authenticated approval, a pinned
body digest and model, an approved input-token ceiling and durable replay
prevention. Pass those values and a centrally managed credential supplier.
Each invocation performs at most one POST to the fixed Responses endpoint.
The provider-neutral Investigator checker runs locally on the returned
`Draft`. The standalone m82 caller wraps the parsed draft in the existing
`ScriptedProvider` solely for local checking. Its report identifies the
Responses model and provider-reported usage separately. The trial produces
private research output and leaves Scout history untouched.

A caller supplies exact UTF-8 JSON bytes with a text input, instructions,
`text.format` strict JSON Schema, expected model, standard tier, storage
disabled and tools disabled. The reusable adapter accepts requests up to
12,000 bytes. It supervises credential supply, connection, request and
bounded body read with a monotonic deadline of at most ten seconds. The
response read requests at most 16,385 bytes to detect overflow of the
16,384-byte body limit. The complete draft may use up to 4,096 UTF-8 bytes
and must pass the existing strict `Draft` model. A completed response
must match the expected model, tier, retention flag and usage limits.
Non-200 HTTP responses, redirects, encoded or oversized bodies, incomplete
or malformed replies, refusals, tool outputs and missing or inconsistent
usage fail closed as `Refused`. The returned record includes response ID,
draft, digests and token usage. That usage is still subject to billing
reconciliation. The deadline rejects late results locally. Remote
cancellation and remote billing remain separate.

Use the same callable with an injected local connection fake:

```python
reply = complete_responses_once(
    reviewed_body_bytes, body_sha256=reviewed_digest, model=approved_model,
    input_token_limit=approved_bound, credential_reader=lambda: "fake-token-local-only",
    connection_factory=FakeConnection,
)
assert reply.draft.proposed_outcome == "unaffected"
```

The normal `investigate` and `OfflineHandoff.consume` entry points retain
their exact-type gates. The new adapter lives with the local benchmark.
Other agent call sites remain inactive.

## Test and safe invocation

Use a local CPython 3.12 environment with the reviewed dependencies and pytest.
Run from the candidate worktree. Extract only the pinned fixture artifact and
point to the existing reviewed request:

```sh
fixture=$(mktemp)
git show aec2456:benchmarks/studio-offline-citation-support/unseen-holdout-39d580a/seal/inputs.json > "$fixture"
body="$HOME/.aegis-phase6-request-review/m82-ca82ce718189.json"
base=benchmarks/phase6-offline-fixture-freeze
PYTHONPATH=src python3.12 -B "$base/openai_one_shot.py" check "$body" "$fixture"
AEGIS_TEST_M82_INPUTS="$fixture" AEGIS_TEST_REVIEW_BODY="$body" \
    PYTHONPATH=src python3.12 -B -m pytest -q -p no:cacheprovider \
    "$base/test_openai_one_shot.py" tests/test_phase5a_investigator.py tests/test_offline_research_handoff.py
```

The `check` mode verifies and prints public fixture metadata with zero
credential access or dispatch. Future `dispatch` requires a centrally
supplied credential pipe, Jack's unexpired Ed25519-signed approval and an
enrolled, independently administered verifier key. Its trust anchor is
`/private/etc/aegis/phase6-openai-operator.pub` on macOS or
`/etc/aegis/phase6-openai-operator.pub` on Linux. Enrollment must confirm the
root-owned path and key are writable only by the administrator, including
effective ACLs, and scope the enrollment to the designated Studio host.
The key file contains the raw 32-byte public key. The envelope has
`statement` and a hex `signature` over the sorted compact statement without
a trailing newline. The statement binds the exact `plan` emitted by
`check`, `operator_uid`, `expires_at`, `max_billed_input_tokens`,
`max_charge_usd`, `retention_evidence_sha256` and
`charge_evidence_sha256`. The evidence hashes identify reviewed material
held by the approver. The code verifies the signature and cap arithmetic.
The approver must verify the substance of the charge and retention evidence.

The program creates and syncs a fixed, exclusive marker under the signed
operator UID's OS account home before a credential is read or a dispatch is
attempted. One marker covers concurrent calls and later invocations in that
enrolled host and account. An ambiguous failure or timeout consumes the
attempt. The marker's durability assumes continued custody of that home
and marker. Copying enrollment to another host or restoring earlier local
state falls outside the tested one-attempt scope. The program has no
Keychain lookup. Activation still needs Jack's approval, independent
approval-key enrollment, a verified charge ceiling including applicable
fees, accepted outbound/retention scope and the centrally managed credential
handoff. No trusted key or approval was provisioned for these tests.

## Token-count evidence for the one-cent cap

OpenAI documents `POST /v1/responses/input_tokens` as free and outside the
ordinary inference quota. Its accepted body fields include the model,
instructions, exact input and `text.format` with the full strict JSON schema,
plus the two tool fields. The count API reference does not list the create
body's `max_output_tokens`, `service_tier` or `store`. The proposed count
body projects the six supported fields only and keeps all schema content.
The sorted compact projection is 1,958 bytes with SHA-256
`bc320ef005cafeae439d0eb80dc5411a9b4e50248a8a46fa5ce25afef0184d3b`.
Approve its own outbound bytes and retention treatment before any count.
[Count API reference](https://developers.openai.com/api/reference/resources/responses/subresources/input_tokens/methods/count) · [OpenAI token-count guide](https://developers.openai.com/api/docs/guides/token-counting) · [OpenAI Help Center on counting fees](https://help.openai.com/en/articles/4936856-understanding-and-counting-tokens)

At the published standard rates of $0.75 per million uncached input tokens
and $4.50 per million output tokens, 512 output tokens cost at most
$0.002304. With no other charges, 10,261 billed input tokens plus that output
ceiling total $0.00999975. At 10,262 input tokens the total is $0.01000050.
The documented output cap includes non-visible tokens. One separately
authorized count can establish the provider-reported processed input for
the supported projection. The docs do not bind that measurement to later
billing for the create request. Treat it as cost evidence with pinned
equivalence, rates and fee checks. A hard one-cent guarantee still needs
an independently accepted binding upper bound. No count or inference
request was made. [Snapshot pricing](https://developers.openai.com/api/docs/models/gpt-5.4-mini) · [Responses create reference](https://developers.openai.com/api/reference/resources/responses/methods/create)
