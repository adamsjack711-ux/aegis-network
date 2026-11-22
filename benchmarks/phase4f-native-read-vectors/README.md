# Phase 4F read-only wire vectors v1

These golden vectors pin the proposed retrieval shapes from contract
`3f36c6ab39405bd1a10d5c905483abdab7204a0e` against the existing native
verification reference at `b09afcf830e9ac7273beaa08ec6b64e73add7a53`.
The authority, keys, clocks, target and observations in this directory are synthetic.
The fixture constructs and verifies bytes in memory. It has no network, native
state, broker, audit or dispatch adapter.

## Reproduce

Use Python 3.12 or newer in an environment with the project's declared runtime
dependencies already installed. Run from the repository root.

```sh
PYTHONPATH=src python -B benchmarks/phase4f-native-read-vectors/vectors.py
PYTHONPATH=src python -B benchmarks/phase4f-native-read-vectors/vectors.py --emit |
  cmp - benchmarks/phase4f-native-read-vectors/golden.json
```

On macOS the same checker can run with network access explicitly denied.

```sh
/usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network*)' \
  env PYTHONPATH=src python -B benchmarks/phase4f-native-read-vectors/vectors.py
```

`golden.json` indexes wire bytes by their lowercase SHA-256. Decode each
`wire_hex_by_sha256` value from hex to obtain the exact bytes, with no
trailing newline. `rounds` maps each saved request, response and expected
result to those bytes. `byte_budget` uses runs of byte `0x61` split at
the recorded `sizes` to exercise actual streaming lengths. Its
`body_sha256` covers the concatenated supplied chunks. Primitive caps
and arbitrary filler exercise framing limits separately from authenticated
appraisal rounds. The verifier compares explicit expected outcomes and
then compares the full regenerated catalog to the committed bytes.

## Framing and byte domains

T4 uses compact, sorted-member UTF-8 JSON via `journal.protocol.canonical`.
Each frame has a versioned `kind` and an exact member set. Duplicate and
unknown fields, alternate formatting and noncanonical encodings are
refusals. Roots, digests and nonces are 32 bytes in lowercase hex.
Signatures are 64 bytes in lowercase hex. A signed frame is
`{"body":…,"signature":"…"}`. Ed25519 signs the ASCII domain, one NUL,
and the exact canonical body. The four proposed domains are
`aegis-native-t4-obligation/v1`, `aegis-native-t4-anchor/v1`,
`aegis-native-t4-floor/v1` and `aegis-native-t4-view/v1`.
Native admission votes retain `aegis-journal-v1/admission` plus NUL and
their existing Admission bytes. Merkle leaf and parent hashes use the
existing native SHA-256 primitives over the separately scoped log.

- The floor request binds context, enrollment audience/workload/store,
  fresh nonce, protected reader baseline, and the UTC interval. The
  signed floor binds that request hash, global and four witness heads,
  append-consistency nodes, issue and expiry. The modeled protected
  current anchor pin comes from a separate fixture input.
- The common view request binds the challenge and first floor hashes.
  Each signed view binds the exact request and its enrolled slot, with
  explicit completeness and pending intake state. A pending refusal
  retains the signed original witness admission timestamp.
- Each page request pins the first challenge, floor, context and ordered
  start with one fixed page size for the round. Every response pins the
  exact request hash and carries the next ordinal, ordered entries and
  inclusion proofs. The witness obligation signs its exact entry and
  resulting witness head. The global leaf contains the original
  canonical signed Revocation 1.1 envelope and the obligation hash.
  The independent acceptance signs the leaf digest, ordinal and resulting
  global head. These signatures sit outside their corresponding Merkle leaves.
- SHA-256 of the whole retained Revocation envelope keys the native
  admission. The body pin uses `artifact.canonical_bytes(Revocation)`.
  The signed target pin uses `artifact.canonical_bytes(Finding)`.
  An alternate inbound formatting sample has a different transport hash
  and re-encodes to the retained canonical envelope. The scoped proof
  carries the target triple, original admission time, policy pins and
  references to the retained wire and its provenance.
- The native T5 challenge binds the signed Manifest wire SHA-256,
  Finding-claim byte SHA-256, material-scope digest, cohort, audience
  and T5 policy. The existing binder checks actual material bytes and
  the fixture environment. The offline carrier `t5-capture.v1` stores
  the exact native signed endorsement and complete native records in
  canonical padded base64. This carrier serves the fixture. Endorsements
  keep the native `AEGIS-EVIDENCE-STATUS/v1` / `endorsement` NUL-delimited
  domain and the archive has its existing separate domain. Each of the
  two operators supplies a complete ordered archive independently.
  Compare current pins to the modeled protected T5 prior set without
  updating it. The native pure Evidence appraisal provides the earliest
  supporting attestation expiry.

The second floor response uses a fresh challenge and must preserve the first
global and per-witness heads and the retained reader baseline. Observable pending
intake holds. The interposed-append vector measures the event at its original
eligible admission time between the signed views and confirmation. The
unchanged confirmation supports only an absence in the complete anchored
prefix. The pending append can become visible later without rewriting that clock.
Evidence-only withdrawal produces `evidence_hold`. A complete absence or a
hold carries no Mesh proof.

## Limits and refusals

Requests admit 1–16 obligations per page, at most 64 pages and 1,024
obligations. Ordinals follow the signed terminal and the JSON integer type,
and tree indices retain native bounds. Proofs carry at most 64 32-byte
nodes. The source envelope has a 256 KiB limit. Identity body limits are
64 KiB per floor/view, 512 KiB per page, and 3 MiB per T5 response.
Native T5 limits remain 256 records and 8,192 bytes per decoded record.
The aggregate ceilings are 8 MiB for T4 and 16 MiB for the entire round,
including the T5 carrier overhead and all bytes observed on failed attempts.
The reader rejects compression and checks actual chunks before accumulation
or parsing. Length declarations never forgive truncation or extra bytes.

One round has 72 logical read slots and at most 74 attempts. Reserve an
attempt before reading a body, including a zero-body transport failure.
A structurally bounded transport failure permits one retry of that exact
slot, up to two retries for the entire round. Replay after a received
response, an exceeded limit, or a malformed authenticated frame has no
retry entitlement. The 2,000 ms monotonic deadline is exclusive. The
conservative UTC validity uses the sampled lower bound plus remaining
monotonic time and the earliest required signed or native Evidence expiry.
It must still be ahead of the UTC upper bound. A missing or incomplete
proof produces a distinct refusal from a cap, authenticated conflict,
rollback or stale response.

The v1 pin leaves native routes, authenticated transport, independent
anchor custody, current T4 trust-cut and retained-floor lifecycle,
stateful T5 integration, canonical SQLite preclaim and physical ACK
fencing to later work. Native release remains **FAILED / NO-GO**.
Historical `78a5314a586ee40fbbb1f2d50281bb547a7c0656` submission misses
remain 30,659.599 and 30,648.004 ms. The native witness-admission origin
remains unmeasured. The frozen matrix remains 0/72 fault and 0/18
healthy observations, with zero new native observations here.
