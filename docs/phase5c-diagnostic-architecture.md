# Phase 5C-1 Diagnostic Runner architecture proposal

**Status: proposal only.** Reviewed integration reference `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`. This document changes no code, signed bytes, local approval, native T4/T5 status, or protected writer. No diagnostic execution, external connection, production target or model call was performed. Phase 5C is an explicitly invoked, observation-only local-lab capability. Its output is a lead for a human and independent verifier, never an authority input by itself.

## Why a separate runner

The current Linux CLI reads local dpkg state and signed Mesh files offline. The Evidence `runner.run` invokes one digest-pinned, stdlib-only worker for registered inert marker fixtures, with bounded input, a subprocess timeout, resource limits and a Python audit hook. That worker is not a general-purpose sandbox. Phase 5C must not broaden its accepted vocabulary or let a coordinator/advisory/model supply an executable recipe. A new private Diagnostic Runner may reuse the *pattern* of exact code/data pins and independent controls, but any probe beyond the existing fixed fixture requires OS-level containment review and an independent acceptance gate.

## Plane and trust boundaries

```text
operator, local lab enrollment
  → local request preflight and exact profile lookup
  → disposable restricted worker with pinned immutable inputs
  → bounded parser and control checks
  → provisional DiagnosticObservation to stdout
  → optional explicit operator capture and independent review

research/advisory/CLI suggestion ──> profile identifier only; no execution authority
Mesh/T4/T5/Rapid/protected writer  <── no direct input from DiagnosticObservation
```

The operator chooses the local target and profile for **one** run. There is no scheduler, daemon, broker subscriber, remote profile loader, public scan, crawler, arbitrary host or network address, generic shell, injected script, or automatic retry. No command line is taken from an artifact. A coordinator can at most provide untrusted context displayed as data; it cannot enroll a target or select a new executable. Default execution reads only a bounded immutable snapshot of an authorized disposable fixture, with the worker network namespace disabled. An optional future live local probe needs a separate target-enrollment and side-effect review; this proposal does not authorize one.

### Component ownership and interfaces

| Component | Proposed owner and behavior | Boundary |
| --- | --- | --- |
| Local profile registry | 5C-1, proposed `src/aegis/diagnostic/` only after design review. A fixed versioned mapping from profile ID to pinned worker/image digest, input grammar, expected controls and resource ceiling. | No arbitrary code, path, URL or command field in a request; registry changes require reviewed source commit and new negative tests. |
| Request preflight | 5C-1. Verify exact locally enrolled fixture identity, profile, immutable input digest, no symlink/device traversal, budget and operator invocation before any worker launch. | A research candidate or Mesh event does not enroll a target. Unknown or expired enrollment rejects. |
| Disposable worker | 5C-1 implementation proposal, independently reviewed by VAL-1. Read-only source/input binds, private empty tmpfs, unprivileged UID, no network, no capabilities, no new privileges, bounded CPU/wall/RSS/pids/files and blocked post-launch process execution. | Python audit hooks may supplement but cannot replace kernel/container controls or syscall evidence. No host mutation mount. |
| Result parser and recorder | 5C-1. Accept one bounded canonical result from pinned worker, verify exact input/profile/output digests and controls, report `observed`, `not-observed`, `inconclusive` or `rejected`. Emit structured stdout by default. | No `verified-vulnerability`, `safe`, `mitigated`, `approved` or target-write status. Do not log secrets or raw host files. |
| CLI presentation | 5B owners, only through a separately reviewed adapter or explicit future subcommand. The current `aegis` default commands stay offline/read-only and unchanged. | 5C cannot edit `src/aegis/cli.py` or package metadata. A diagnostic row cannot modify signed finding or inventory semantics. |
| Research suggestion | 5A owner may propose a profile ID and source span in private research output. | Suggestions are inert until an operator chooses an installed profile and enrolled target. No model tool call may run a probe. |
| Independent validation | VAL-1 freezes positive/negative cases and original evidence before reviewing implementation. | Owner self-tests do not grant acceptance. |

## Safety and audit path

Preflight fails closed before launch if the target is not an authorized disposable fixture, the enrollment or exact snapshot is stale, the profile is absent/changed, a resource ceiling is exceeded, a path escapes its root, or the output destination was not explicitly requested. A failed control, timeout, signal, partial output, parser error, policy ambiguity or missing source becomes `inconclusive` or `rejected`; neither absence nor a nonzero process exit means the target is safe. Only a locally installed allowlisted worker is executable. The launcher may start that pinned worker; the worker cannot exec a second program or open a socket.

The default command writes **no persistent host state**. It streams a bounded result and sanitized per-run transcript to stdout; an operator may explicitly choose an output file in a declared private local directory. A separate lab audit collector may hash and retain this transcript, but a local hash is integrity bookkeeping, not independent custody or a signature. The result records source/profile/input digests, controls, result, reason, resource use and clock method so an independent reviewer can reproduce it. Never include credentials, tokens, arbitrary environment variables, full package databases or private user files. Disposal of the worker and tmpfs is mandatory after every outcome, including cancellation.

No automatic bridge exists from a DiagnosticObservation to `SignedFinding 1.0`, native Evidence, T4/T5 status, Rapid local approval, mitigation templates or protected writers. A future evidence adapter would need a versioned proposal, independent verifier organizations, registered environment/check/oracle pins, negative semantic tests, old/new reader compatibility, and explicit integration approval. A valid worker signature or digest alone would not prove the claim true. The current 4F five-second all-agent withdrawal gate and distributed-enforcement NO-GO remain unchanged.

## Integration sequence

1. VAL-1 freezes a local target/profile/output oracle and retains the current failure corpus. Review this architecture and the [provisional contracts](phase5c-diagnostic-contract-proposal.md) with the integration lead, 5B owners and native Trust reviewer.
2. Prototype one inert registered-marker profile with immutable inputs in an isolated worktree. Exercise OS containment, bounds, controls and no-write behavior. Keep the proposal output private and incompatible with signed authority schemas.
3. Have VAL-1 challenge an exact clean source pin, including malicious inputs, process crashes, escapes, timeouts and false observations. Integrate only reviewed files into an isolated candidate, then run the complete regression suite and focused cross-component rejection tests.
4. Decide separately whether the diagnostic tool is suitable for a local-lab preview. No observation can close CLI alpha, AI release, five-second withdrawal, or distributed-enforcement gates without its own evidence.
