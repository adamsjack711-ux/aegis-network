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
receipt="$HOME/.aegis-phase6-request-review/m82-count-bc320ef005ca.replacement.receipt.json"
AEGIS_TEST_M82_INPUTS="$fixture" AEGIS_TEST_REVIEW_BODY="$body" AEGIS_TEST_COUNT_RECEIPT="$receipt" \
    PYTHONPATH=src python3.12 -B -m pytest -q -p no:cacheprovider \
    "$base/test_openai_one_shot.py" tests/test_phase5a_investigator.py tests/test_offline_research_handoff.py
```

The `check` mode verifies and prints public fixture metadata with zero
credential access or dispatch. The existing one-shot admission requires Jack's
signed envelope and the independently installed public verifier. It binds the
exact plan, operator UID, expiry, accepted estimate and retention record. The
launcher marks the attempt before reading the centrally supplied credential
pipe. Concurrent calls and later invocations share that marker in the enrolled
host and account. An ambiguous failure or timeout consumes the attempt.
The marker's durability assumes continued custody of the account home.
See the separate operator handoff for the approved estimate and exact offline
signing and verification commands. [Studio operator enrollment](studio-phase6-openai-owner-handoff.md)

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
equivalence, rates and fee checks. Jack accepted the count-based estimate for
the single m82 trial. The signed record expressly leaves the binding charge
ceiling unverified. The adapter's fake tests make no count or inference request. [Snapshot pricing](https://developers.openai.com/api/docs/models/gpt-5.4-mini) · [Responses create reference](https://developers.openai.com/api/reference/resources/responses/methods/create)
