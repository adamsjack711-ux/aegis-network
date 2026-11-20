# Phase 5C diagnostic records — proposed v1

**Status:** field-level design, not a deployed wire or implementation. These records are private to the proposed runner. They do not extend `Finding.schema_version="1.0"`, `SignedFinding`, `Revocation`, Evidence, Trust, Rapid plans or CLI `*-v2` outputs. All JSON examples below are illustrative, with fixed non-secret identifiers. A later implementation should publish JSON Schema 2020-12 files and golden canonical bytes before accepting input.

## Common rules

- UTF-8 JSON object only; maximum envelope 8 KiB, maximum nesting 6, duplicate keys rejected, unknown fields rejected, no floats or NaN. IDs are lowercase UUIDv4; hashes are lowercase SHA-256 hex. Timestamps are UTC RFC 3339 with `Z`, seconds precision. Parsing never performs an operation.
- Canonical digest: SHA-256 of UTF-8 JSON with sorted keys, compact separators, no insignificant whitespace, after strict validation. `schema_version` is included. Digest comparison uses exact bytes, not semantic fuzzy matching. Local-origin metadata is set by the trusted local adapter, never copied from an incoming proposal.
- Operation IDs are exactly `inspect_package/v1`, `check_service/v1`, `check_listening_ports/v1`. The registry is a compiled closed table with its own digest. Operation arguments are a discriminated union. `inspect_package` has exactly `package_name`; `check_service` exactly `unit_name`; `check_listening_ports` exactly `family`, `protocol`, `detail`. Unknown operation versions and extra arguments are errors.
- Semantic validation is required after schema validation: installed audience, local allowlists, permitted source, registry digest, consent scope, expiry, schedule slot, revocation generation and resource caps. A JSON Schema alone cannot prove local authorization or replay freshness.

The closed argument types are:

```text
InspectPackageArgs  = { package_name: ASCII /^[a-z0-9][a-z0-9+.-]{0,127}$/ }
CheckServiceArgs    = { unit_name: ASCII /^[a-z0-9][a-z0-9_.@-]{0,119}\.service$/ }
CheckPortsArgs      = { family: "inet" | "inet6" | "both",
                        protocol: "tcp" | "udp" | "both",
                        detail: "counts" | "ports" }
DiagnosticArgs      = discriminated by the exact operation ID; no other keys
```

The unit grammar is only a first filter; the exact name must also appear in a local operator-maintained allowlist. The package grammar is aligned with `local_observer.PACKAGE_RE`. `ports` is available only for a one-shot local-detail grant; a schedule and outbound result use `counts`.

## `DiagnosticRegistry/v1` — compiled local contract

The registry is a versioned, release-pinned manifest with literal `schema_version="diagnostic-registry/v1"`, `entries` sorted by exact operation ID, and a SHA-256 digest of its canonical bytes. Each entry has `operation` (closed ID), `argument_schema_id`, `backend_id` (closed local implementation identifier), `platform` (`debian-ubuntu-linux` or `linux`), `wall_ms`, `cpu_ms`, `memory_bytes`, `result_bytes`, `raw_output_bytes`, `privacy_tier` and `reader_limits`. Resource numbers are positive integers and may only be reduced by local policy. The compiled release must contain exactly the three entries in the [architecture registry](phase5c-diagnostic-runner.md#closed-operation-registry-v1); the installer verifies its manifest digest. A transport message cannot carry or replace this registry. A change in behavior, parser, argument shape or permission meaning requires a new `/vN` operation ID and fresh consent.

## `DiagnosticProposal/v1` — untrusted inbox data

| Field | Type and bound | Meaning |
| --- | --- | --- |
| `schema_version` | literal `diagnostic-proposal/v1` | Version discriminator |
| `proposal_id` | UUIDv4 | Remote correlation, never an authorization token |
| `operation` | closed operation ID | Suggested check only |
| `arguments` | operation-specific exact object | No command/path/URL/host field |
| `reason` | plain text ≤240 characters | Display escaped as untrusted text; never used in policy or result |
| `expires_at` | UTC timestamp, ≤24 h after local receipt | Inbox expiry is capped locally regardless of sender time |

The transport adapter may separately record authenticated transport identity, but that identity is not part of the proposal's authority. Repeated `proposal_id` with different digest is rejected; same bytes are displayed once. A proposal can be denied, expired or locally converted into a fresh request only after review.

```json
{"schema_version":"diagnostic-proposal/v1","proposal_id":"6bd31270-0fc0-441d-9c5a-d7b5c3589c10","operation":"check_service/v1","arguments":{"unit_name":"ssh.service"},"reason":"Check whether the enrolled service is active","expires_at":"2026-11-20T00:00:00Z"}
```

## `DiagnosticRequest/v1` — locally minted execution candidate

| Field | Type and bound | Meaning |
| --- | --- | --- |
| `schema_version` | literal `diagnostic-request/v1` | Version discriminator |
| `request_id` | locally generated UUIDv4 | One-time idempotency key |
| `install_id` | local random UUIDv4 | Binds to this runner installation; never accepted from remote data |
| `origin` | `manual`, `schedule`, `reviewed-proposal` | Set locally |
| `origin_ref` | UUIDv4 or null | Schedule/proposal ID; null only for manual |
| `operation`, `arguments` | closed union above | Exact work to authorize |
| `registry_sha256` | SHA-256 hex | Pins local registry revision |
| `created_at`, `expires_at` | UTC timestamps | Request valid ≤10 min; remote proposal cannot extend it |

The request has no `command`, `cwd`, `env`, `user`, `destination`, arbitrary path or caller-provided budget. A budget is selected from the registry and local policy. A schedule produces a new request for each due slot. A reviewed proposal's request uses a new local request ID and stores only a correlation reference to the proposal.

```json
{"schema_version":"diagnostic-request/v1","request_id":"02dc4772-e81d-439f-b25c-02a7d522001b","install_id":"2e20a705-4129-4cbb-b94b-e8b1d3a8b8c0","origin":"reviewed-proposal","origin_ref":"6bd31270-0fc0-441d-9c5a-d7b5c3589c10","operation":"check_service/v1","arguments":{"unit_name":"ssh.service"},"registry_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":"2026-11-19T23:50:00Z","expires_at":"2026-11-19T23:55:00Z"}
```

## `DiagnosticSchedule/v1` — local standing request template

| Field | Type and bound | Meaning |
| --- | --- | --- |
| `schema_version` | literal `diagnostic-schedule/v1` | Version discriminator |
| `schedule_id` | local UUIDv4 | Local template ID |
| `operation`, `arguments` | closed union | Exact future work; `check_listening_ports` must use `detail=counts` |
| `interval_seconds` | integer 3600–2592000 | Minimum hourly, maximum 30 days |
| `created_at`, `expires_at` | UTC timestamps | Maximum 30-day consent term |
| `purpose` | escaped text ≤120 chars | Operator-facing purpose only |
| `schedule_generation` | positive integer | Advances on edit or revoke |
| `enabled` | boolean | Disabled entries do not create requests |

No cron expression, user command or catch-up flag. The trusted scheduler calculates due slots, deterministic jitter and a one-run-per-slot key. Editing arguments, frequency, purpose, disclosure or term requires a new local approval. A stale timer firing alone is never permission.

```json
{"schema_version":"diagnostic-schedule/v1","schedule_id":"8761503a-8a85-4f8b-839f-b5b2774a61d8","operation":"inspect_package/v1","arguments":{"package_name":"openssl"},"interval_seconds":86400,"created_at":"2026-11-19T00:00:00Z","expires_at":"2026-12-19T00:00:00Z","purpose":"Local package presence check","schedule_generation":1,"enabled":true}
```

## `DiagnosticAuthorization/v1` — local private grant

| Field | Type and bound | Meaning |
| --- | --- | --- |
| `schema_version` | literal `diagnostic-authorization/v1` | Version discriminator |
| `authorization_id` | local UUIDv4 | Audit correlation only; not a transferable capability |
| `install_id` | local UUIDv4 | Same installation as request |
| `scope` | `one-request` or `schedule` | No generic remote grant in v1 |
| `subject_id` | request ID or schedule ID | Exact subject |
| `subject_sha256` | SHA-256 hex | Canonical request or schedule template bytes |
| `policy_generation` | positive integer | Rechecked at dispatch and before share |
| `approved_at`, `expires_at` | UTC timestamps | One request ≤10 min; schedule ≤30 days |
| `allowed_detail` | `counts` or `local-detail` | Upper data disclosure in local result |
| `sharing` | literal `local-only` in v1 | Outbound share requires a separately designed grant |

The local approval UI writes this record in a private atomic transaction after showing the exact digest and scope. Merely possessing a serialized grant is insufficient: the runner checks local owner, generation, subject, expiry and one-time use. A revoked schedule's old grant cannot be replayed. `local-detail` does not silently authorize outbound sharing.

```json
{"schema_version":"diagnostic-authorization/v1","authorization_id":"551f894e-1dd8-41d1-8e3b-049cd4fc0a9f","install_id":"2e20a705-4129-4cbb-b94b-e8b1d3a8b8c0","scope":"one-request","subject_id":"02dc4772-e81d-439f-b25c-02a7d522001b","subject_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","policy_generation":4,"approved_at":"2026-11-19T23:51:00Z","expires_at":"2026-11-19T23:55:00Z","allowed_detail":"counts","sharing":"local-only"}
```

## `DiagnosticResult/v1` — sanitized observation

| Field | Type and bound | Meaning |
| --- | --- | --- |
| `schema_version` | literal `diagnostic-result/v1` | Version discriminator |
| `result_id`, `request_id` | local UUIDv4 | Correlation, not stable machine identity |
| `request_sha256`, `registry_sha256` | SHA-256 hex | Exact request and registry provenance |
| `operation` | closed operation ID | Result shape discriminator |
| `started_at`, `finished_at` | UTC timestamps | Correlation only; monotonic durations live in audit |
| `status` | `complete`, `unknown`, `denied`, `timed-out`, `resource-limited`, `unsupported` | No implicit safe/healthy state |
| `scope` | `local-host`, `current-network-namespace`, `unknown` | What was actually observed |
| `data` | closed operation-specific object or null | Null unless complete; no raw streams |
| `reason_code` | fixed enum or null | Generic failure/uncertainty; no sensitive exception string |
| `truncated` | boolean | True means incomplete, never complete |

`inspect_package/v1` data is `{presence: installed|absent|unknown, version: string|null}`; version ≤128 and present only for installed local detail. `check_service/v1` data is `{state: active|inactive|failed|unknown}`. `check_listening_ports/v1` data is `{tcp_count: integer, udp_bound_count: integer, ports: array|null}`, with counts 0–65535 and at most 256 distinct integer port numbers when local detail is approved. Addresses, PID, process labels and socket IDs are forbidden. A `complete` package absence requires a complete supported inventory; a `complete` port result requires all selected tables to be readable without truncation. An `unknown` state is distinct from zero. There is no protection or vulnerability conclusion.

```json
{"schema_version":"diagnostic-result/v1","result_id":"6843e5e5-78e2-4bfe-a414-b00b31912c24","request_id":"02dc4772-e81d-439f-b25c-02a7d522001b","request_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","registry_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"check_service/v1","started_at":"2026-11-19T23:51:01Z","finished_at":"2026-11-19T23:51:01Z","status":"complete","scope":"local-host","data":{"state":"active"},"reason_code":null,"truncated":false}
```

## `DiagnosticAudit/v1` — private metadata ledger

One append-only record per proposal admission/denial, request admission, execution outcome, revocation, cleanup and share decision. Fields: literal schema version; sequential local counter; event UUID; UTC time and boot ID; event kind enum; operation/version or null; request/proposal/authorization IDs or null; request/registry digests or null; policy generation; fixed reason code; elapsed monotonic milliseconds or null; CPU milliseconds and peak memory bytes or null; result ID or null; disclosure tier; retention deadline; previous-record hash and current-record hash. The hash chain is local tamper evidence, not a remote attestation. Raw request text, reasons, stdout/stderr, versions, service names, ports and IPs are excluded from audit. A separate private result store holds permitted data; encryption at rest needs an explicit local key-management design before it is claimed. Audit reader versions are explicit and old rows remain readable during migration.

## Compatibility and migration

An old v1 reader rejects any v2 record. A v2 reader must explicitly parse v1 with frozen v1 semantics or reject it; it cannot fill missing authority fields with permissive defaults. Registry entry changes require a new operation ID such as `/v2`, a new digest and fresh consent. Upgrading the runner preserves denials, revocations, used request IDs and retention deadlines. Downgrade to a reader that cannot verify these floors disables schedules and remote approvals until local repair. Install ID rotation invalidates old requests and grants. None of these records are accepted by existing Mesh/Rapid parsers.
