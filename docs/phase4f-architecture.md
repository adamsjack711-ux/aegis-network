# Phase 4F architecture and contract freeze

Baseline `ee739cacfaa3f81a0994b4d7802fd2943c067d86`. The Phase 4E full run remains a failed gate with 346 passes, one empty-log Trust fixture startup error and one key retirement admission failure. Both cases passed alone. Retain the original JUnit, the 30.479-second pre-intake withdrawal observation, and the native ownership-loss pre-observation failure as acceptance controls.

## Authority boundary

Native T4 witnessed history and T5 independent Evidence status remain the authority inputs for the disposable protected writer. Mesh delivery, broker ACK, a replay cursor, C shadow status, advisory text and model output convey no write authority. The target consumes one locally approved immutable plan containing the exact finding and Evidence digests, signed status and history cut, target and inventory identity, owner generation, expected fence, operation and earliest expiry. Unknown, expired, withdrawn, contradictory or unavailable status denies new writes. A restrictive hold survives restart and same-generation reconnection. Recovery requires a newer valid generation, complete target barriers, current native Trust and fresh exact local approval. The existing signed wire and native reason codes are frozen for this preparation period.

## Interfaces under review

| Surface | Owner | Proposed condition before adoption |
| --- | --- | --- |
| Native target state | 4F native enforcement | The target commits a restrictive hold before an independent observer can report a safe state. A serving-path denial alone cannot count as a durable hold. Preserve a known safe restriction during crash, partial rollback and restart. |
| Broker session, ACK and cursor | 4F native enforcement with integration review | Bind a durable owner generation and authenticated session to each authoritative decision, ACK and replay floor. Old-session ACK or cursor results cannot advance the successor. Lost ACK retries preserve one logical decision. Introduce a versioned protocol if old readers cannot enforce it. |
| Protected transaction | 4F native enforcement with Trust reviewer | Pin and recheck exact current T4/T5 cut, local approval, generation, fence and earliest deadline at the actual native mutation and audit commit. Admission after the last remote sample remains bounded by the accepted cut expiry and local hold path. A test-only B marker hook is a reference, not the native implementation. |
| Critical withdrawal delivery | 4F transport owner | Keep original signed scope, native witness inclusion and status distinct from broker intake. Reserve bounded capacity, maintain old publisher ordering, and measure every eligible agent from durable acceptance to independently read back denial. Report unavailable agents in the denominator. |
| Test harness | Independent validator | Preserve failing original pins and raw results. Record attempts, commitments, durable holds, ACKs and target probes as separate facts. Diagnose fixture startup and ten-second retirement under controlled resource and clock conditions before changing production timeouts. |

No shared contract or migration is adopted by this document. Any change needs field-level before/after semantics, old/new reader matrix, replay and restore policy, exact test vectors, and independent review. Unsupported versions fail closed.

## Acceptance criteria

1. A target with no observation traffic durably holds after native owner or Trust loss. The observer reads the hold later without causing it. Test process kill, broker partition, restart and unchanged-generation return. All declared protected routes remain restrictive.
2. Two authenticated broker contenders cannot commit or ACK under the same deployment as different current generations. A stale signed command, dropped ACK, copied cursor and restored owner snapshot leave zero stale target writes and zero successor cursor regression. Every enrolled writer acknowledges the new barrier before activation.
3. For every attempted native protected write, current T4/T5 status, exact locally signed plan, target, owner generation, fence and earliest deadline are checked at the same transaction boundary. An injected status or deadline change after staging rolls back the effect, receipt and success audit. No new authority is derived from C shadow or Mesh metadata.
4. A valid in-scope withdrawal cannot be starved by an admitted ordinary burst. In repeated matched local trials, every eligible connected agent records durable denial within five seconds of independently witnessed acceptance. Report offline and pre-intake-crash actors explicitly, with lower/upper time bounds and all-agent denominator. Keep this gate open while any case exceeds it.
5. Reproduce the original broad-suite startup and admission failures, identify a root cause supported by process logs, clock samples and resource traces, fix the cause at the correct layer, then run a clean full exact-pin suite and the independent adversarial suite. Preserve original failing XML and test assertions.
6. Report p50/p95/p99 withdrawal-to-denial, target hold, ownership transfer and native write cost, plus CPU, RSS, backlog and missed deadlines from repeated pinned trials. Local Docker results do not satisfy physical multi-host or independent custody gates.

Release remains NO-GO for distributed autonomous enforcement until the Phase 4E security gates and the criteria above pass under the declared fault model. [Frozen predecessor contracts](phase4e-contract-review.md) · [Raw failures](../benchmarks/phase4e/integrated-final-348.xml)
