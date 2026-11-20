# Phase 4E architecture

## Approved baseline and authority boundary

The common integration baseline is Phase 4D `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f`, tree `60b9ee8d64f4e43857252dd9d79e6e4b44b95461`. The clean baseline combines the native T3–T5 controls at the disposable fixture writer. T6 independently failed the distributed enforcement gate. Phase 4E may exercise native trust and signed local denial in authorized lab fixtures. The distributed writer stays disabled through Phase 4E review. Research, Evidence, Mesh and any external attestation supply inputs. Only the enrolled local operator can approve the exact target plan. [Phase 4D security review](phase4d-security-review.md) · [Phase 4D release decision](phase4d-release-readiness.md)

```mermaid
flowchart LR
  Sources["Scoped signed withdrawals"] --> Fast["Reserved admission and denial propagation"]
  Sources --> W["Independent native witness intake"]
  W --> Gate["Rapid with current head, Evidence and local policy"]
  Fast --> Gate
  Mesh["Mesh delivery and durable audit"] --> Gate
  E["Separate Evidence status custodians"] --> Gate
  H["Authenticated home and writer barriers"] --> Target["Disposable writer"]
  Gate --> Review["Exact local approval"]
  Review --> Target
  Target --> Check["Independent audit and route readback"]
```

## Workstream interfaces and failure policy

| Owner | Responsibility and invariant |
| --- | --- |
| A · Withdrawal priority | Reserve bounded service capacity for authenticated scoped denials and preserve ordinary progress. Preserve atomic event, journal and outbox state, stable IDs and commit-before-ACK. An earlier same-publisher finding must retain its ordering dependency unless a new versioned signed denial lane has been approved. A fast withdrawal observation can only invalidate or hold. Broker acknowledgement is delivery telemetry. |
| B · Cross-broker identity | Authenticate the transport principal and broker context against local enrollment. Bind proof-of-possession, deployment, allowed broker, session and home generation. A successor receives active write authority only after all enrolled writers durably raise their fences and the home independently confirms the same barrier. Check exact intent, generation, target fence and expiry at each mutation. A storage restore or ambiguous owner remains unavailable. |
| C · Independent Trust | Admit original signed records across separately governed paths. Use the native witnessed history, independent Evidence status, retained scoped tombstones and monotonic continuity floors. Certify a requested native scope, checkpoint, audience and expiry. Missing records, stale content, contradictions, unreachable authorities or integrity failures remove eligibility. Protect source, proof and status services with scoped, authenticated, bounded interfaces. |
| D · Independent validation | Run healthy and fault controls against the exact integrated pin. Inspect writer fences and audit independently, and have a separate observer verify marker and benign responses. Record attempted, denied, committed, confirmed and safely recovered states explicitly, including censored or failed cases. |

## Chosen distributed fault model

Assume a compromised or unavailable coordinator, delayed, duplicated or withheld broker traffic, stale former agents, process crashes, independently restored application stores and network partitions. Reuse the T4 3-of-4 fixed witness roster with at most one faulty or Byzantine witness for post-cutoff coverage of quorum-admitted events. Coverage depends on independent intake and durability of witness obligations. T5 requires both pinned status operators on a current complete view and two eligible verifier organizations separate from local approval. Losing either status operator can deny availability. These policies and their evidence requirements stay distinct. Scope remains one cohort and its explicitly enrolled lab fixtures.

Trusted assumptions include a trustworthy enrollment root and local approver, an independently protected continuity anchor, target adapters that apply generation changes and exact plan checks in their mutation boundary, and a measured bound on clock uncertainty. Rotated or restored actors must prove continuity before rejoining. A hostile local writer, unsafe clock or anchor recovery, or collusion beyond the declared threshold invalidates the corresponding positive result. Repair or quarantine can restrict known paths, record uncertainty and require independent readback. Repair cannot infer renewed authority from a healthy endpoint.

## Safety and measurement

When status is unavailable, the writer denies new authority and unsafe rollback. Known denials survive broker loss and recovery. An in-flight plan is invalidated after observed interruption. An unknown withdrawal before a sealed/current view is bounded by the earliest applicable cutoff, status, ownership, approval and actuator deadline. The gate compares durable generation and exact immutable plan inputs before each protected commit. A receipt or fresh transport lease alone carries no authority.

Time withdrawal admission, delivery and confirmed denial independently. Admission starts when the relevant authority durably accepts a scoped withdrawal. Denial ends when the independent observer verifies the safety state for an eligible fixture. Measure an unreachable agent's lost-lease restrictive deadline separately from its process reclaim and eventual broker ACK. Track a still-valid prior cut's residual interval, backlog age, capacity rejections, service disruption, restart recovery, and greatest clock error on each host. The historical five-second threshold was a reporting threshold. Phase 4E must establish any denial bound separately in the declared lab topology. [Test ledger](phase4e-integration-plan.md)

## Implemented boundary in the local candidate

A's opt-in critical lane commits and observes exact negative state early. It preserves the ordered canonical cursor and leaves approval, witnessed history, independent Evidence, and target fencing in place. The native profile can observe its durable denial before broker acknowledgement, and the independent route observer sees quarantine. The separate lane has no positive authority.

B adds disposable mTLS broker adapters, an independently retained lab anchor, two durable writer stores and an all-writer barrier. A writer that detects loss of current ownership commits a held fence and quarantine. A same-generation reconnect cannot resume it. The next safely installed generation still needs new exact local approval. This namespace acts only on inert markers, outside native Mesh acknowledgements and the Phase 4D writer.

C adds a private-socket Trust experiment that combines witnessed native records and independently appraised scope at a common cut. It retains an independently hosted lab floor, seals quorum-receipted records and denies fresh status at its local exhaustion latch. The shared writer continues to require the original mandatory-two T5 Evidence appraisal and current T4 history. Enabling C at that writer would require an explicit compatibility and authority review for partial intake, epoch transitions, deadlines and loss of anchors.

The source and test suite combine these packages in one reviewable tree. The candidate provides no single live authority path joining B's broker ownership and C's common cut to the native staged writer. [Sequential intake](phase4e-integration-plan.md#sequential-intake-record) · [Independent challenge](phase4e-adversarial.md)

## Targeted follow-up boundary

The combined tree preserves native T4/T5 as the authority for the known native protected path. A's verified transport adapter is a reviewed contract with an exact native proof regression. It gives a future consumer independent inclusion and status signals in addition to ordinary transport delivery. Broker ACK, an HTTP receipt or a cursor alone carries no Trust authority. An old-generation native consumer session must be fenced before a future successor can own its authoritative ACK or cursor.

C's optional shadow profile uses the existing 3-of-4 history certificate and four independently authenticated withdrawal views before a positive appraisal. An exact, native-valid revoker record accepted and reported by an honest witness takes denial precedence before quorum inclusion. A missing or invalid view holds. Freshness checks run after the final potentially blocking authority read, and after signing on publication. Shadow status is outside the native writer.

B's explicit second marker writer uses the native appraisal and an exact operator-signed deployment, target, mutation, plan, and cut. Under the same writer transaction, it respects the current owner generation, installed fence and earliest accepted monotonic and wall-clock deadlines. Declining the protected commit rolls back the marker and receipt together. The target-owned watchdog separately persists an ownership-loss hold before any observation and requires a new generation and fresh exact approval to recover. These exercised marker and clock controls are local lab evidence. Native pre-observation holds, generation-bound native ACKs, administrative separation and external restore anchors remain distributed release gates. [Reviewed contracts](phase4e-contract-review.md) · [Readiness](phase4e-integration-plan.md#candidate-readiness)
