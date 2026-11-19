# Phase 4E-B · Multi-host identity and durable fencing

The opt-in identity lab exercises two authenticated broker adapters and two separately writable synthetic targets. One ownership home allocates deployment generations. The home activates a replacement only after both target writers acknowledge the exact generation from their mutation transactions. A former owner's signed command and approval are denied at the target, including when delivered directly by the previously assigned broker.

The branch starts at the approved Phase 4E baseline `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f`. T1 specifies a stable UUID, exact workload enrollment, independent instance proof, a home and an all-writer barrier. T3 establishes the proof, approval, and mutation ordering inside one SQLite transaction and leaves transport peer identity to an adapter. Phase 4C finding 4C-02 and T6 identify the remaining broker admission, external recovery floor and independently hosted writer gates. This lab moves those three boundaries onto separate authenticated processes and files. [T1 research](../../../docs/research/aegis-trust-identity.md) · [T3](phase4d-t3-identity.md) · [4C-02](phase4c-adversarial.md#4c-02--high--broker-local-leases-cannot-establish-deployment-wide-identity) · [T6 dispositions](phase4d-security-review.md)

## Topology and authority

| Role | Boundary |
| --- | --- |
| Agent instances | One canonical deployment UUID spans broker assignments. Enrollment pins each instance's exact lab SPIFFE URI, TLS public key hashes and separate Ed25519 proof key. An agent signs a claim or command with the instance key. Its TLS credential authorizes only the scoped broker RPC. |
| Broker A and B | Each adapter authenticates the agent's URI and enrolled TLS key and checks the signed intent. The home derives the broker role from the broker's client certificate and checks the claim again. The broker derives credential expiry from the verified agent leaf. |
| Ownership home | A single SQLite primary serializes generation allocation. The home pins the writer inventory and dependency endpoints. Only the authenticated home can advance the separate continuity anchor. |
| Continuity anchor | A distinct SQLite store records a monotonic revision, generation and state digest. The home checks those fields for every authority-bearing operation. The anchor cannot admit an instance or grant a generation. |
| Target A and B | Each target owns a separate SQLite marker, fence and command receipt store. Exact TLS service identities scope fence delivery, home lookup and readback. The mutation applies to a synthetic marker. |
| Operator, observer and artifact signer | The test controller holds disposable keys in distinct roles. The operator can retire a generation and sign an exact action. The observer reads marker, effective serving state and command count. Workload keys lack artifact publisher and operator-approval authority. |

The lab uses OpenSSL through Python TLS 1.3 with mutual certificate verification, exact URI SAN checks, fresh handshakes and one request per connection. The fixtures issue short-lived leaf certificates from an in-memory, disposable lab CA. They test expired leaf denial and rotation to a separately enrolled TLS key without changing the instance or deployment identity. Automated Workload API renewal, attestation, revocation and issuer rotation require a SPIRE deployment and credential lifecycle integration. The compatible direction is SPIRE attestation with pinned workload selectors and exact URI authorization. [Python TLS](https://docs.python.org/3/library/ssl.html) · [SPIFFE X.509-SVID](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/) · [SPIRE registration](https://spiffe.io/docs/latest/deploying/registering/)

## Transfer and recovery

1. An eligible broker forwards an authenticated, signed claim naming the deployment, broker, prior generation and expiry. A live owner or competing pending assignment blocks the claim. Operator retirement or lease expiry makes the next claim eligible. Lease duration is capped by the claimant's credential expiry.
2. The home advances the anchor and commits a `preparing` assignment before contacting any writer. If the anchor committed and the home failed, comparisons fail closed. Retrying the same candidate against its original expected generation reuses the pending assignment and repeats the entire barrier.
3. The home sends `Fence(assignment, target)` over an authenticated connection to each pinned target. The writer verifies the exact pending assignment inside its SQLite mutation lock. It then commits the floor and the quarantine marker under that lock. The receipt follows durable commit. A target can repeat a receipt for its current boot and exact assignment. A missing receipt holds the transfer. A restart after receipt can leave the target quarantined even if the home finishes activation. Recover it through a fresh generation and barrier.
4. The home rechecks the pending state, claim and credential deadlines and seals `active` only after all receipts. It releases its lock before barrier network calls so a writer can consult the home while holding the local write lock. An in-flight old write that already obtained current authorization can finish before that writer's fence. The successor cannot activate until that write has released the lock and the new fence has committed.
5. Every target write checks the broker TLS role, signed instance command, exact operator approval, target version and nonce. It checks the durable fence and current home assignment inside the marker transaction, then commits the effect and receipt together. A retired generation gives zero effects even with a valid old key, command and approval. If a target observes loss of current authority, it durably latches quarantine. Restoring the dependency under the same assignment cannot reopen authority.
6. To recover a home snapshot, stop the home before restoring the file and retain the continuity anchor in its separate recovery domain. The home denies authorization while its stamp differs. The operator reads the current stamp from the anchor and submits it to `/recover` to allocate a higher vacant generation. The next claim repeats the full barrier. An anchor older than the readable home floor holds recovery. Each target restart generates a new boot identifier and requires a fence from an exact pending assignment. A target restored within the same generation therefore cannot reopen write authority for that generation. Restore of target effect history or consumed intents requires external audit custody if that history must survive the backup.

[Protocol records](../src/aegis/identity_lab/protocol.py) · [Transaction and service boundaries](../src/aegis/identity_lab/services.py) · [mTLS adapter](../src/aegis/identity_lab/transport.py)

## Adversarial coverage

| Scenario | Observed boundary |
| --- | --- |
| Simultaneous ownership at two brokers | One claim activates. Both target stores show its generation. |
| Former owner attempts a signed write after transfer | The prior broker sends a valid signed command and approval to the writer. Independent readback and durable receipts show zero subsequent old-generation writes. |
| Same URI from a separate host namespace | A CA-signed leaf with the same URI and an unpinned TLS key is denied. An eligible TLS key paired with the wrong instance proof is denied separately. |
| Credential expiry and rotation during recovery | The expired leaf fails both the client validity check and the broker's raw mTLS handshake. The separately enrolled replacement key reacquires the same instance identity through the other broker. |
| Broker partition and reconciliation | The current broker loses its network attachment. A competing claim is denied until retirement. After the new target fences and network reattachment, the former broker's session and write authority remain retired. |
| Old ownership or anchor snapshot | A restored home state behind the anchor holds ownership and writes. An older anchor cannot move back the newer home floor. Recovery through the intact anchor uses a higher generation. |
| Target restart during partial transfer | The first target keeps its committed floor. While the second is unavailable the candidate stays preparing. Both writers return durable fences before activation succeeds. |
| Old approval after reassignment | A current agent command coupled to a prior-generation approval is denied. Exact new approval succeeds. |
| Target restored within one generation | The restored store lacks a previously consumed nonce. Its new boot blocks the old command and requires a fresh home fence. |
| Anchor outage and same-generation return | One target observes loss via readback and the other via an attempted write. Both persist quarantine and reject the old approval after the same home generation becomes reachable. New approval in the successor generation succeeds. |

## Verification and measurements

The implementation pin `11ecb948de82ef094f4fc48261786ff7600d64de` passed **285 tests** with all local live modes enabled, including 13 Phase 4E cases. The same 13 cases passed in separate Docker network namespaces. The full suite emitted the inherited Starlette/httpx deprecation warning. The benchmark ran on 2026-11-19 on arm64 macOS with one Linux Docker VM. Both transport arms used the same target, TLS implementation and image. [Test evidence](../benchmarks/phase4e-identity-tests.json) · [Raw benchmark samples, environment and outcomes](../benchmarks/phase4e-identity.json)

| Measured span | Samples | p50 | p95 |
| --- | ---: | ---: | ---: |
| Operator retirement and successor activation, elapsed Docker harness time | 12 | 935.70 ms | 987.62 ms |
| Same transfer, summed anchor-stamp, retirement and claim RPC spans | 12 | 89.19 ms | 104.83 ms |
| Successor claim RPC, including both durable fence receipts | 12 | 63.97 ms | 79.36 ms |
| First writer's durable receipt, from start of barrier | 12 | 13.63 ms | 17.31 ms |
| Second writer's durable receipt, from start of barrier | 12 | 26.64 ms | 31.37 ms |
| Fresh authenticated session after activation | 12 | 12.99 ms | 13.64 ms |
| mTLS probe across the internal bridge | 60 | 2.20 ms | 2.56 ms |
| Same mTLS probe over target-namespace loopback | 60 | 1.90 ms | 2.21 ms |

The bridge added 0.30 ms at p50 and 0.35 ms at p95 on this VM. The fixture measures communication across network namespaces. Physical cross-host latency remains unmeasured. Transfer wall time includes Docker exec and controller scheduling. Each RPC and writer span uses its own monotonic clock. The transport arms each discard five recorded warmup probes and use the nearest-rank p95.

All 24 healthy session and write controls succeeded. The client rejected 12/12 expired credential attempts, and the separate test also exercised the broker's raw handshake. The broker denied 12/12 attempts with a trusted-CA leaf bearing the same URI and an unenrolled TLS key. All 12/12 sessions offered to a previous broker were denied. The raw sample records all 65 timed authorization and fault decisions and their expected outcomes.

In one network disconnect, the home activated generation 27 on both targets 1.547 s after the former broker lost its network attachment. Reattaching the old broker took 37.5 ms. Independent readback confirmed one approved successor write 3.315 s after disconnect and zero stale writes. The recovery interval includes the deliberate old-session and old-write probes and controller operations.

## Proposed shared-contract changes

These are proposals for main developer review. All implemented interfaces are private to the lab package.

| Proposed contract | Required contents and semantics |
| --- | --- |
| Versioned enrollment and assignment | Canonical deployment UUID, realm and ownership-home identity, inventory commitment, instance URI and separate proof key, exact broker, epoch and monotonic generation. Define credential and lease deadlines, trusted-time uncertainty, and conversion to conservative local monotonic cutoffs. Keep the T3 local monotonic proofs in their current scope. |
| Writer barrier and receipt | Exact assignment, immutable enrolled target identity, transfer identifier, writer incarnation and durable floor. Require a matched receipt from every protected writer and every authority-bearing audit or cursor writer. Hold on omissions, unknown writers, stale receipts and restore ambiguity. |
| Exact approval and writer input | Bind the assignment and target state version alongside the existing exact plan, Rapid decision, witnessed Mesh cut and independent Evidence status. The writer enforces the earliest applicable deadline and commits the effect, nonce and audit atomically. Require fresh approval after reassignment or recovery. |
| Delivery and replay | Keep signed Mesh bytes, logical deployment ID, journal position semantics and commit-before-confirmed-ACK ordering. Add reviewed generation scoping for physical consumers, ACKs and authoritative cursors. Prove that an old connection cannot advance a successor's state. |
| Recovery records | Keep an independently retained generation and authority state commitment for each restore domain. Define continuity for consumed intents, audit history and cursor state before allowing any restoration to reopen authority. |

## Terminal handoff

From the root of the requested worktree, use the repository Python environment with the project and test dependencies installed. Docker trials use a private internal bridge, no published ports, a locally available image with the project dependencies, and throwaway fixture material. The default image is the existing Phase 4 baseline image. Set `AEGIS_PHASE4E_IMAGE` to another local image built from this repo's Dockerfile if needed. Every service mounts only its own credentials and state. The Docker peer processes, files and network namespaces share one physical host, one Linux VM and one test controller.

```sh
cd .worktrees/phase4e-identity
git log -3 --oneline

AEGIS_PHASE4E_LIVE=1 PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  python -m pytest -q -p no:cacheprovider tests/identity_lab

AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_TOPOLOGY=docker PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  python -m pytest -q -p no:cacheprovider tests/identity_lab

AEGIS_PHASE4E_LIVE=1 PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  python scripts/benchmark_phase4e_identity.py --output /tmp/phase4e-identity.json
```

Use `src/aegis/identity_lab/__main__.py` for individually provisioned roles with an explicit config and data directory. The test harness owns disposable enrollment, certificate issuance, partition and restart operations, snapshots, and teardown. All test connections stay within localhost or the internal Docker bridge.

4C-02 stays open for a distributed enforcement release. Independent physical hosts and credential custody, real broker consumer/ACK and cursor fencing, SPIRE, clock uncertainty, resilient storage administration, combined status gates and real writer effects require separate acceptance. The anchor protects against a stale home restore while at least one intact recovery domain remains. Correlated rollback of every state domain and hot replacement of a running writer's database fall outside the model. An anchor outage holds authority. Broker recovery follows lease expiry or an explicit operator retirement.
