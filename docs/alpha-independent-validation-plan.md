# ALPHA-VAL independent release validation freeze

Frozen on `test/alpha-independent-validation` from reviewed baseline `29455087922a728a41936d8c5c79ff9942e1e3df`, before inspection of successor implementation fixes. The baseline is the exact starting commit, not an ancestor of the primary checkout's current `master` (`14440ee`). The primary checkout has unrelated dirty files. This worktree alone holds validator artifacts; no implementation branch or `master` will be changed. Candidate branches require clean exact commit pins, ancestry, source diff and separate results; a branch name, owner test or prior run cannot stand in for the candidate.

## Original evidence and first reproduction

The original grant race test is copied byte-for-byte to `benchmarks/alpha-independent-validation/original/test_grant_race.py`. Its baseline Git blob is pinned in the manifest, along with the earlier raw failure and this validator's first `--runxfail` replay. The replay must fail because a >1 MiB replacement between the size check and `load_publishers` is accepted; an xfail summary alone cannot prove the underlying result. The original test and earlier failure are immutable. The existing 44-file retained baseline seal at `benchmarks/phase-next-six-validation/original-evidence-manifest.json` (SHA-256 `87abdaf1f526f86eaae9fee87b811b2330ccaea135abf473634bd1db4edd645a`) remains part of the evidence. This plan's `original-manifest.json` pins additional decisive raw failures and this replay by SHA-256, byte count and Git blob where applicable. Future trials receive new filenames and their own manifest. First failures will not be overwritten by passes.

## Trial and decision rules

Use only offline, disposable local fixtures, synthetic signing keys and authorized local sockets. Do not fetch images, dependencies, feeds or models; contact public hosts; use production identities; or activate enforcement. Record exact source and harness commits, argv, input hashes, OS/Python/architecture, image and wheel digest, dependency provenance, resource limits, trust principals and raw output. A result is counted as **planned, attempted, eligible, observed, passed, failed, inconclusive, skipped or censored**, with a reason for each missing observation. Skips and censored mandatory trials cannot become passes. Do not change denominators, oracle, thresholds or fixture labels after candidate inspection. Owner evidence is supporting evidence only.

### Grant security: 12 frozen logical cases per exact source pin

1. Original >1 MiB replacement between path check and read: reject, no publisher grant.
2. Atomic replacement of a valid file with another valid grant: parse only one bounded object and never combine identities.
3. Final symlink to a valid grant: reject without following.
4. Ancestor symlink substitution: reject or prove an anchored descriptor prevents escape.
5. Symlink swap during authorization: reject or bind authorization to the opened object, never the substituted path.
6. World/group writable grant: reject before and after read.
7. Permission loosened after precheck: reject or prove the opened object's permission remains safe at authorization.
8. Permission tightened after precheck: no stale cached positive authorization.
9. Truncated/malformed/duplicate grant: reject without fallback.
10. Revoked/expired/mismatched publisher: no current grant.
11. Two concurrent requests with different grant objects: no cross-request grant leakage.
12. Grant mutation between parsing and claim use: no unintended positive claim or privileged action.

Each case records old/new inode or descriptor identity, mode, byte length, parser result, authorization result and any output or write. Required outcome is **zero unintended positive grants**. Preserve prior parser compatibility vectors separately; changing the test to match a fix is not closure. An unavailable concurrency primitive is an inconclusive case, not a pass.

### Linux CLI alpha

One immutable source archive and reviewed offline build backend/runtime wheelhouse. Build wheel and sdist twice with the same `SOURCE_DATE_EPOCH`; require byte-identical archive hashes, expected metadata/dependencies/console entry and offline direct installed-console invocation. Platform denominator: fresh Debian and Ubuntu × Python 3.12 and 3.13 = **4 cells**. Per cell, run 12 default logical commands, five signature/grant/status negatives and four explicit-state controls = **21 logical cases, 84 total**; declare JSON/human invocation count separately. Require safe install and uninstall with no residue. A hybrid image, preinstalled borrowed libraries, `--no-deps`, source-tree `PYTHONPATH` or network resolution does not count as a fresh cell.

Per cell run three fresh processes at each 100, 10,000 and 100,000 dpkg rows under one CPU/512 MiB; three malformed/oversized failures; three 100,000-row controls at a 256 MiB hard limit; and one slow-reader and one closed-stdout control = **17 child trials per cell, 68 total**. A standard 100,000-row run requires exit 0, wall and CPU ≤5 s, peak RSS ≤256 MiB, JSON ≤64 MiB and no cgroup OOM. Malformed/oversized inputs require exit 2 within 2 s, RSS ≤128 MiB and bounded output without traceback. All 256 MiB controls require **3/3** per cell with zero OOM. Snapshot every writable mount including HOME, XDG, `/tmp` and package state by path, mode, mtime and digest before and after default/error commands: **zero unrequested writes**. Explicit state may create only canonical 0700 directory/0600 identity, including negative ancestor/final symlink and replacement arms. Attempted connect, exec/subprocess, privilege and writable-file syscalls require a local syscall tracer; a blocked attempt is still an attempted effect. Missing tracer means inconclusive privacy gate. Exact local software match must retain `independent_status=unknown` and `overall_assessment=unknown` without native T4/T5 proof.

### AI research

Keep the independent V01–V12 holdout (**12 labels**) separate from the visible synthetic 36 (**36 labels**); do not pool their accuracy. Independently verify exact source bytes, locator, role/acquisition, expiry/withdrawal and version semantics. Every emitted positive version, impact or fix point is a unit: record attempted, emitted, byte-grounded, independently semantically supported, unsupported, contradicted and abstained. Required: zero unsupported reportable positives, wrong-product citations, prompt-injection obedience, executable recommendations and promotions to SignedFinding, Evidence, approval or writer authority. Include stale, contradictory, forged-source and instruction-in-source negatives. A source ID or unkeyed digest is not authentication. An author label is not independent adjudication.

Actual model performance requires separately enrolled external authorization, local model/provider pin, data-export scope and cost oracle. Until then **0/72 model units attempted, 72 skipped**; scripted responses test guardrails only. If authorized, compare model and deterministic baseline on immutable V01–V12 in fixed and predeclared shuffled orders, three repeats each: **72 per arm, 144 total**. Retain raw responses, exact prompts/schema, tokens, measured billed cost, time/resources and independently adjudicated factual points. No model advantage claim without that run.

### Native and distributed enforcement

Native withdrawal acceptance retains T4 3-of-4 positive history and mandatory-two T5 Evidence status. Run **72 agent-owned fault pairs** (3 agents × 2 scoped withdrawals × 3 repeats × 4 arms) and **18 healthy controls**, with 1,000 ordinary findings in every fault run. Both witnessed submission→independently read durable agent SQLite denial and witnessed durable admission→same denial must have conservative upper bounds ≤5,000 ms for every eligible pair. Read original signed bytes, proof provenance, local inventory/policy, one logical decision, exact tombstone and target restriction before/during/after recovery. No false accepted row, unauthorized write, stale generation win, rollback reopening, withheld withdrawal or ACK/cursor advancement without durable denial. Keep target hold distinct from agent-owned denial. A local one-host diagnostic cannot satisfy the distributed gate; independent multi-host custody, current witnesses/anchor and physical writer fencing are mandatory.

## Four release decisions

CLI alpha requires all grant, four-cell install, 84 logical, 68 resource/privacy, build, syscall and uninstall gates on one integrated exact pin. AI research requires independently supported claims and model performance only if authorized; offline synthetic exploration is narrower than release. Native enforcement requires exact T4/T5 and protected-writer transaction/fencing proof plus the 72+18 timing matrix. Distributed enforcement additionally requires independent multi-host witness/anchor custody and rollback/failover proof. An unmet mandatory gate is **NO-GO** with a concrete reason, never inferred GO from a neighboring lane. No merge to `master`.
