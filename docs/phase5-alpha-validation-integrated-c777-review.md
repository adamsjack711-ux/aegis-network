# Independent integrated candidate review: `c777ce8`

**Exact candidate:** `integration/phase5-alpha-orchestration` at `c777ce8562248b3bc1dbc7200575162c6c300852`; **baseline:** `8292e531194216a578c32c912d066f98cdbce9ea`; **independent freeze:** `f5da1814162c821e0491b7591837b6623113294a`, reconciled with external `68f9fd8fc84e8d92673c43ad20e3230a714ddac2`. Candidate worktree was clean. I inspected only the exact candidate and wrote raw results in this validator branch; no candidate/owner source was edited, and no network, model, Docker or production target was used.

## Decision

**GO for isolated source/evidence intake of this exact candidate; HOLD CLI alpha and all other release or authority claims.** Its only product-source addition since the baseline is `src/aegis/intelligence/scout.py`, identical Git blob `a34419824747c98ca29e9fde8a06b28c285e7583` to the independently reviewed Scout owner pin `54c7ec4d90e612c667d9cd5f217a5e2f18e38d54`. Scout accepts caller-supplied bytes, labels HTTPS archives unverified, retains revisions/conflicts and has no live fetch, model, SignedFinding/Evidence/approval or writer bridge. The integration imported the earlier independent 4F/5B and Scout/Investigator/Runner reviews byte-for-byte (`git rev-parse` document blobs matched validator commits `2cb9243` and `80da230`). No Investigator or Runner product source was integrated. The 4F proposal is an inert fault model, not a recovery implementation.

The frozen `SignedFinding 1.0`, exact InventoryItem/local observer, native Trust/T4/T5, mitigation store, adapter and relevant gate docs have **9/9 identical SHA-256 hashes** against both `8292e53` and the freeze manifest. Full per-file hashes are in `benchmarks/phase5-alpha-validation/integrated-c777-audit.json`. `git diff --check 8292e53..c777ce8` passed. This inspection supports contract preservation for this candidate; it does not prove the distributed security properties under unrun fault arms.

## Staged regression evidence

I independently parsed all four exact-candidate JUnit XML files, counted every `testcase`, `skipped`, `failure` and `error`, and preserved XML SHA-256 in the raw audit. The requested three intake JUnits are shown alongside the frozen starting run for chronology.

| Stage | Tests | Passed | Skipped | Historical xfail within skips | Failed | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Frozen integration start | 462 | 424 | 38 | 1 | 0 | 0 |
| After 5B docs/raw intake | 462 | 424 | 38 | 1 | 0 | 0 |
| After inert 4F fault model | 468 | 430 | 38 | 1 | 0 | 0 |
| After offline Scout | 479 | 441 | 38 | 1 | 0 | 0 |

The other 37 skips comprise 30 credentialed disposable mTLS cases and seven opt-in loopback/Docker fault cases. The historical grant stat/read race remains an **xfail**, not a demonstrated fix. These JUnit files are retained integration run artifacts; I independently inspected them but did not rerun the full suite. On this exact candidate I reran **36/36** focused Scout/Phase 5A tests and **6/6** inert 4F fault-model tests, with zero failures and zero skips. Their raw stdout is `benchmarks/phase5-alpha-validation/integrated-c777-scout-focused.txt` and `integrated-c777-4f-focused.txt`.

The integration chronology from `git log --ancestry-path 8292e53..c777ce8` shows the acceptance freeze before the 5B evidence intake, a regression artifact after each 5B/4F/Scout intake, then imported independent review reports. This does not turn specialist self-tests or copied raw results into new independent release trials.

## Gates still open

- **CLI alpha NO-GO:** 0/4 frozen installed Linux cells, 0/84 installed console cases, 0/68 installed resource/privacy children on this candidate. Offline wheelhouse provenance, fresh Ubuntu/Python 3.13 install and syscall tracing remain open. The prior source-only CLI grant custody caveat and historical xfail remain.
- **AI research/model NO-GO:** Scout alone is offline triage with author synthetic labels; no reviewed Scout→Investigator adapter, source authenticity or independent claim adjudication. Investigator `97265de` live-capable source is held and absent. The frozen 72-per-arm real-model experiment has zero authorized external calls and no billed-cost oracle.
- **Diagnostic Runner NO-GO:** held owner source is absent; frozen 0/72 safety and 0/30+30 fresh-process trials remain. No worker, containment or syscall tracer is approved.
- **Distributed enforcement NO-GO:** 4F fault model preserves the retained ~30.6 s pre-intake crash failure; it does not satisfy the unchanged five-second all-agent durable-denial gate. The frozen 72 fault +18 healthy pairs with 1,000 ordinary backlog are unrun; multi-host custody and rollback anchors remain open. Native T4/T5 stays authoritative.

**Next independent review:** any later Investigator offline-only revision or other source change needs its own exact-pin assessment and staged regression. This decision is only for `c777ce8562248b3bc1dbc7200575162c6c300852`.
