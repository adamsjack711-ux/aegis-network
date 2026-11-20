# Independent exact-pin review: Scout, Investigator, and local Diagnostic Runner

**Validator branch:** `test/phase5-alpha-freeze-third`; frozen acceptance `f5da1814162c821e0491b7591837b6623113294a` (reconciled with external `68f9fd8fc84e8d92673c43ad20e3230a714ddac2`). **Owner base:** `8292e531194216a578c32c912d066f98cdbce9ea`. All three owner worktrees were clean, direct descendants of that base; `git diff --check` passed. No owner source or worktree was edited. Tests and benchmarks used only offline local fixtures. No model, feed, download, production target or external network was used.

## Exact-pin decisions

| Lane and clean pin | Source/evidence intake | Release / authority decision |
| --- | --- | --- |
| Scout `54c7ec4d90e612c667d9cd5f217a5e2f18e38d54` | **GO, isolated offline research source only.** Private `scout-advisory-input-v1`, explicit unverified archive provenance, SQLite dedup/cursor, contradiction retention and no feed fetch or authority bridge. Eight of eight canonical body digests independently recomputed. | **NO-GO** live feed, authenticated provenance, advisory accuracy, Investigator connection, Finding/Evidence/approval or CLI release. Labels are author synthetic. |
| Investigator `97265de36a67de4a7ae6f374fb8cd64362fcb6fe` | **HOLD source intake; GO docs and offline test/raw evidence only.** Offline claim checking is separable, but the same source exposes a live HTTP adapter whose authorization is caller-constructible. | **NO-GO** real model, AI benefit, live inference or authority bridge. Split/hard-disable live transport and review a versioned Scout adapter before source intake. |
| Runner `6c7714688f4efe1b3dd25bd358ce0a9eb09196f9` | **HOLD source intake to shared candidate; GO isolated prototype docs/test evidence.** It reads local snapshots in process, beyond the frozen initial inert request-validation lane. | **NO-GO** diagnostic preview, CLI integration, live inspection, execution, Evidence/Trust/approval or protected write. |

## Contract and security findings

1. Scout's `AdvisoryInput` is `scout-advisory-input-v1` with source kind, source ID/URI, content digest, acquisition/provenance, normalized claims and priority. Investigator's different `AdvisoryInput` is `advisory-input-v1` with asset plus `SourceSnapshot[]`. Neither branch includes a reviewed converter. A Scout priority is triage metadata, not an affected or authorization claim. **No direct intake connection is approved.** A versioned adapter must preserve raw bytes/digest, source identity and unverified provenance, withdrawals, conflicts and unknown applicability; tests must reject claims lost or silently strengthened by conversion.
2. `OpenAIProvider.complete()` checks only its optional `Authorization.model` and the process environment API key. The `Authorization` and `SpendLedger` objects can be created by the caller; direct `complete()` bypasses `investigate()`'s reservation and corpus check. The `httpx.Client` call has `follow_redirects=False` but retains default environment proxy trust. The source therefore lacks the frozen out-of-band, one-use operator capability, reviewed exported corpus and actual billed-cost oracle. No real call was made. **Acceptable remediation:** move offline ScriptedProvider, deterministic baseline, exact-source checks and records to an offline-only module; remove or make the live adapter unimportable/unusable pending a separate capability and transport review. Do not promote quotes to semantic truth, SignedFinding, Evidence or local approval.
3. Investigator's source-quote check verifies exact contiguous bytes and rechecks the pinned source. This is a useful citation integrity check, not independent semantic support. Its visible offline report covers only 12 author cases, with 12/12 baseline and 12/12 investigator outcomes and zero false affected. It does not run the frozen 24+12 research cases, independent semantic adjudication or 72-per-arm real-model experiment. Model accuracy, cost, latency and benefit remain **unverified**.
4. Runner uses fixed typed operations and descriptor-relative, no-follow reads of operator-owned snapshot files; source imports no subprocess or networking library. It has no CLI or authority bridge, and `independent_status` is literally `unknown`. However `authorize()` accepts a caller-supplied `tty_fd`, so a same-UID process can supply a pseudo-terminal and mint its own one-use grant. The grant is request-bound and in-memory, but operator identity and out-of-band authorization are unproven. It has no pinned worker, seccomp, cgroup-owned service, broker custody or syscall tracing. The frozen initial lane permits inert validation/registry tests, whereas this branch performs snapshot inspection. Main must explicitly review scope before source intake. No executable worker is approved.

## Independent execution and denominators

| Check | Planned | Attempted | Passed | Failed | Skipped/unverified |
| --- | ---: | ---: | ---: | ---: | ---: |
| Scout focused pytest plus Phase 5A compatibility/claim tests | 36 | 36 | 36 | 0 | 0 |
| Scout fixture canonical SHA-256 | 8 | 8 | 8 | 0 | 0 |
| Scout offline microbenchmark | 1 | 1 | 1 | 0 | 0 |
| Investigator focused pytest plus Phase 5A tests | 30 | 30 | 30 | 0 | 0 |
| Investigator offline visible evaluation | 12 | 12 | 12 visible outcomes | 0 | independent truth not tested |
| Runner focused host pytest | 14 | 14 | 14 | 0 | 0 |
| Frozen independently adjudicated research | 24+12 cases | 0 new exact-pin adjudications | 0 | 0 | all |
| Frozen conditional real model | 72 deterministic + 72 model case-attempts | 0 real calls | 0 | 0 | 72 model attempts; authorization absent |
| Frozen Runner safety | 72 fresh contained trials | 0 | 0 | 0 | 72; no worker/tracer |
| Frozen Runner resources | 30 fresh baseline + 30 candidate processes | 0 | 0 | 0 | 60; owner 30 calls in one process is different |

Independent Scout microbenchmark on macOS arm64/Python 3.15.2: 800 fresh intakes and 800 duplicate replays over 100 single-process rounds; fresh median/p95 **0.599/0.749 ms**, replay median/p95 **0.431/0.565 ms**, process CPU **0.886 s**, high-water RSS **40,681,472 bytes**, seven durable events before/after restart. It excludes interpreter startup, live acquisition, model, distribution and multi-process contention. Runner owner-reported 30 same-process Linux calls, p50/p95/max **1.028/1.287/1.368 ms**, RSS **24,352 KiB**; not independently repeated here and not the frozen experiment.

Raw independent outputs: `benchmarks/phase5-alpha-validation/scout-54c-focused.txt` (SHA-256 `9c76e6aa47cffc45e279b65657b575c8a975b9bc6ef23928d08c82ad9dafc50a`), `scout-54c-benchmark.json` (`d0c3979d91070a72809d3640bddd34dc790e23d6efb7305b3a844b69ac65bd56`), `investigator-972-focused.txt` (`175e2c7f25a2b6732e49828c2a65ec9075e250319e34201a8ccec41eb57c55d8`), `investigator-972-offline.json` (`58112895a5c242ba90fa44b41ecd841fcaddd6ce8cd6e504e5b3e84d970a772c`), `investigator-972-eval.txt` (`b2a0cf895122fd7eca39cc4718ed357b844bf3092005705604892436f01e9b32`), `runner-6c7-focused.txt` (`dcc038a247e132a5b20c58e4c095d4429c5deb23a841d4b4bb011a364a6b7dfe`).

The concurrent external validator's baseline review at `e4e7262` does not validate these exact new source pins. Installed CLI alpha, AI live evaluation, Diagnostic Runner security preview and distributed autonomous enforcement remain **NO-GO**. Preserve SignedFinding 1.0, exact InventoryItem matching, native T4/T5 authority and all historical failures.
