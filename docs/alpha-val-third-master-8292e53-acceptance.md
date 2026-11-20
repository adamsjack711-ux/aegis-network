# Final independent Alpha master exact-pin acceptance

**Integrated pin:** clean `integration/alpha-master-astra` at `8292e531194216a578c32c912d066f98cdbce9ea`. **Common implementation baseline:** `29455087922a728a41936d8c5c79ff9942e1e3df`; **frozen independent oracle:** `ff69241e87ae36916a25489191aa27674a046ecb`; **prior reviewed docs/evidence candidate:** `e6e58edb02c68797dc6e23a36a3c0fd1d443cfd9`. This review changed no integration or owner worktree. It did not call a network service, download a dependency, invoke a model or exercise a protected writer.

## Exact source and authority scope

`git diff 2945508..8292e53 -- src/aegis` lists **only `config.py` and `intelligence_adapter.py`**. Both files and `tests/alpha_grant/test_grant_reader.py` are byte-identical at integration and the independently reviewed clean grant owner pin `888b2e1cedaf2d62e34eb6c91fbce46526d6e1a5`. The diff to baseline for `artifact.py`, `inventory.py`, `trust.py`, `src/aegis/mitigation/` and `src/aegis/evidence/` is empty. Thus SignedFinding 1.0 bytes, exact InventoryItem matching, native T4/T5 and protected-writer source were not changed by this candidate. `git diff --check` for the product-source delta passed. The imported grant reader is the conditional Alpha v1 one-descriptor repair; the stricter custody-v2 proposal remains inactive. The operator's protection of the local grant file and ancestors is an **unverified precondition**. World-writable paths, ambiguous ACLs and same-UID mutation block release assurance. A local signature has no independent Evidence or enforcement authority.

## Independent focused rerun and original failure

- Integrated R00–R04 actual FD seams: **10 passed, 32 deselected** from the combined selection, zero failed/skipped. The test subset checks post-open path replacement, in-place growth and rewrite, injected OS/parse failures with FD cleanup, and concurrent readers.
- Integrated grant reader plus local CLI/state regression: **42 passed, 1 historical xfailed**, zero failed/skipped. This includes the full 28-case new grant test file, signed fixture digests and old/new parser checks.
- Integrated original `--runxfail`: **1 failed** with `DID NOT RAISE ObservationError`. At the frozen baseline the same old test also failed because the `stat()` then second path read accepted the swapped oversized file; on this candidate its monkeypatch is inert because the pathname loader is no longer used. The historical candidate xfail is retained but **not counted as repair proof**. Actual FD tests are the operative repair oracle.
- Raw independent command outputs are in `benchmarks/alpha-val-third/integrated-8292-*.txt`. All runs used the repository's existing local Python environment, disabled bytecode/cache writes to owner worktrees and accessed no external host.

## Five retained JUnit records and chronology

The XML files were parsed independently. Each has zero `<failure>` and zero `<error>` elements. JUnit records the historical strict xfail as one `<skipped type="pytest.xfail">`; the other **37** skips are opt-in infrastructure cases, including credentialed disposable mTLS controls. The following counts are artifact inspection, **not an independent rerun of each full suite**:

| Intake, raw JUnit committed at | XML tests | Passed inferred | Failed | Errors | Opt-in skipped | Historical xfail |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Packaging `3b34892` (parent `0b66175`) | 434 | 396 | 0 | 0 | 37 | 1 |
| Grant `6cd14a9` (parent `7ac1e45`) | 462 | 424 | 0 | 0 | 37 | 1 |
| Privacy `1899b04` (parent `28c562b`) | 462 | 424 | 0 | 0 | 37 | 1 |
| Offline AI `d65b42e` (parent `1729ffc`) | 462 | 424 | 0 | 0 | 37 | 1 |
| Historical QA `b7ffe4e` (parent `2b371af`) | 462 | 424 | 0 | 0 | 37 | 1 |

The parent relation verifies that each JUnit artifact was committed immediately after its stated intake commit. It does not cryptographically attest that an unseen runner executed that exact tree; the exact-commit test assertion remains the integration operator's evidence. The integration worktree is clean at `8292e53`. The source-owner full suite at `888b2e1` reported 417/37/one xfail separately and is not substituted for the integrated JUnits.

## Retained evidence integrity and release denominators

The integrated original-evidence verifier passed **44 original +10 additional** exact Git-blob records (`prior-evidence-manifest.json`, SHA-256 `03f356012fcdc599c8cb423c57126482a639b3b2bf92e7a33d775e84376f4434`). Independent SHA-256 and byte-size checks passed **123/123** external CLI privacy files and **16/16** external packaging files. The prepared synthetic model bundle has 36 cases and canonical SHA-256 `c9677d431a736abd10323a7c0bc2ab6cc298572d029548f51a848c6dedcc1598`, matching the integrated report; model status is `authorization-pending`, **0 calls**, actual billed cost `null`. These checks establish retained-byte integrity, not supplier provenance, source authenticity or semantic truth.

Packaging still lacks reviewed original Hatchling/runtime wheel archives and a complete offline Ubuntu/Python 3.13 image; two cached diagnostic wheel/sdist builds are not release eligible. The required fresh installed Debian/Ubuntu × Python 3.12/3.13 matrix is **0/4 attempted**, installed logical CLI cases **0/84 attempted**, and installed resource/privacy children **0/68 attempted**. Source-only Kali and Debian/Python3.13 resource/trace results are diagnostic and do not fill these denominators. The prior 256 MiB cgroup OOM and grant race remain retained historical evidence. Privacy trace classification does not yet prove all attempted effects or every writable mount. Alpha v1 grant custody, ACL behavior, no-follow Linux platform behavior and same-UID mutation resistance remain unverified. The distributed five-second all-agent durable withdrawal gate remains failed/open. Model V12 real-arm **0/72 attempted**; no authenticated advisories, independent semantic point adjudication, actual bill or model benefit. Diagnostic Runner has a reviewed architecture proposal only, without the frozen safety/performance implementation trials.

## Separate GO/NO-GO decisions

| Capability | Decision at `8292e53` |
| --- | --- |
| Isolated, observation-only **source candidate** with the bounded grant reader | **Conditional GO** for continued local-lab appraisal under Main's explicit Alpha v1 operator-custody precondition. The focused FD oracle and retained JUnits support this narrow result. No distribution or custody assurance follows. |
| Installable Debian/Ubuntu Linux CLI alpha | **NO-GO**: 0/4 fresh installed cells, 0/84 logical cases, 0/68 installed resource/privacy children, original archive provenance and full attempted-effect tracing absent. |
| Offline AI research records and deterministic synthetic baseline | **GO for read-only fixture research only**; no Finding/Evidence/approval promotion. Real-model evaluation and AI benefit/release **NO-GO**: 0/72 calls, no independent semantic adjudication, authorization or billed-cost oracle. |
| Diagnostic Runner | **NO-GO for implementation or release**: design only; terminal execution disabled; independent security and frozen 72 safety/30-per-arm performance gates unrun. |
| Distributed autonomous enforcement | **NO-GO**: five-second durable all-agent withdrawal gate and distributed trust/custody/fencing acceptance remain open. Native T4/T5 remains authoritative. |

Master was not merged or modified. This exact integration pin is a laboratory source candidate, **not production ready**.
