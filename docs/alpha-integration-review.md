# Alpha master integration review

## Baseline and custody

The common implementation ancestor is `29455087922a728a41936d8c5c79ff9942e1e3df`. Independent historical QA `b3cf551e00f0a8eaf13218fdd7169338cad08ca4` tested only `0fd24dbf31a1fcc5acb17495004800dbc5ad3b61`. The latest reviewed Alpha Readiness evidence candidate is `e6e58edb02c68797dc6e23a36a3c0fd1d443cfd9`, a descendant of both references. This dedicated candidate is `integration/alpha-master-astra` in `.worktrees/alpha-master-astra`, created from `e6e58ed`; it does not change master or any owner worktree. The Alpha Readiness descendant added documents, raw data, scripts and three tests only: `git diff 2945508 e6e58ed -- src pyproject.toml` is empty. The prior exact-commit source suite passed 392/37/one historical xfail with local lab sockets. The grant race remains open in that implementation.

All five external owner branches were clean when inspected. Each commit below is a direct child of `2945508`, except historical QA, which is a direct child of `0fd24db`. Their reported tests are owner evidence until exact-pin independent review is recorded. Frozen release denominators, original failures, signed bytes and native T4/T5 remain unchanged.

| Lane | Exact owner pin | Changed scope | Main review boundary |
| --- | --- | --- | --- |
| Grant Security | `8c9c31952740f9fd218011b7d9bb15097a1ab617` | `config.py`, `intelligence_adapter.py`, grant race tests and raw baseline. | **HOLD source.** It overlaps unaccepted unique Grant candidate `644a184`; it adds owner/mode checks without an accepted compatibility contract. Original race and actual descriptor seam need independent exact-pin proof. |
| Linux Packaging | `b4f42a44ee96748e5ab6bc155700133d2f828fd4` | Offline release harness, tests, unreviewed diagnostic build archives and provenance report. No package metadata or runtime source change. | **HOLD release; review tooling separately.** Byte equality of locally cached builds does not establish reviewed original Hatchling/cryptography archives or four fresh installed cells. |
| CLI Privacy & Performance | `b4976e1e5ca4fcc6f34dbe4c24fb723113add3d3` | Source-only Docker harness, raw resource and syscall traces, report. No application source change. | **HOLD release; review diagnostic evidence separately.** The disposable image build fetched packages outside the reviewed offline wheelhouse; all installed-console cells remain unrun. |
| OpenAI Evaluation | `94c25558684442ceeaa375ca49f02c0b866c8619` | Offline evaluator, prepared bundle, tests and optional network-capable run path. No model call. | **HOLD runtime intake.** A caller-written authorization JSON is not an out-of-band capability; endpoint, billing oracle and semantic adjudication need separate approval. Offline report may be retained as historical evidence. |
| Independent QA | `b3cf551e00f0a8eaf13218fdd7169338cad08ca4` | QA document and source inventory script on old `0fd24db`. | **ACCEPT as historical evidence only.** Its 20 focused passes/one grant xfail and socket-restricted broad failure do not certify newer owner pins or the current candidate. |

The unique assigned Grant candidate `644a1841fab56c641ba0a25cdcbdd19ae6eec519` is also **HOLD** after independent exact-pin `b2b07e319bf6dc3efd5521eb964bb9d30c94c549`: 27 passed, one R03 test failure, one historical xfail. Its owner-reported 417/37/one xfail does not supersede that failure. The Grant owner is correcting the isolated R03 test and proposing a separate local file-custody policy; no grant implementation is integrated.

## Integration order and conflicts

1. Retain the older QA report and accepted source-only diagnostics as evidence, with exact source pins, provenance and skipped denominators.
2. Independently validate the grant reader against the original baseline failure, R00–R04 actual descriptor seams, old/new grant semantics, path and mode compatibility and supported Linux/macOS filesystems. Choose **one** reviewed implementation; the two grant branches both edit the same shared files and must not be merged together.
3. Review the offline packaging harness against original archive provenance and pinned SHA-256 before tooling intake. Resolve the missing Hatchling, cryptography, Python 3.12/3.13 and Ubuntu cell prerequisites through a separately approved offline provisioning workflow. No implicit download.
4. Run privacy and resource instrumentation on the exact installed alpha artifact, then complete the frozen four-cell/84-case/68-child acceptance. Source-only performance and traces remain diagnostic.
5. Retain offline AI research separately from signed Evidence and protected writers. Do not import a network-capable adapter until an out-of-band experiment authorization and independent semantic review exist.

After every accepted implementation intake, run the full source regression on its exact integration commit and retain raw JUnit. Do not merge master. Release decisions remain separate for CLI alpha, AI research, Diagnostic Runner and distributed enforcement.

## Completed sequential intake

Independent external five-pin review `a664a27f7042e017837575185f0adade6a79dc74` gave exact scoped decisions. The external `8c9c319` grant source is **REVISE/HOLD**: it replaced the original strict xfail, left ancestor/ACL custody unresolved and lacked the frozen actual-seam matrix. Its 14/14 focused pass and socket-restricted broad failure cannot approve source. The unique owner `888b2e1cedaf2d62e34eb6c91fbce46526d6e1a5` kept the historical test, corrected R03, and received independent `4c65d887c19e403ca86b943e3f75c0084a96d8fa` plus custody addendum `27c72bec06acf8e260f6ef14441ced61fdc80af3`: **conditional GO for isolated source intake only**, 10/10 R00–R04 and 42 local grant/CLI passes with one historical xfail. Main explicitly retains OS-readable Alpha v1 modes and treats operator protection of grant file and ancestors as an **unverified precondition**, not a guarantee; world-writable custody, ACL ambiguity, Linux installed behavior and same-UID mutation block release. No v2 tightening was activated.

| Sequential intake | Candidate commit | Selected changes | Full exact-commit source regression |
| --- | --- | --- | --- |
| External packaging | `0b66175` | `b4f42a4` offline harness, docs and diagnostic archives; independent review/raw. No package metadata or runtime source. | **396 passed, 37 skipped, one historical xfail**, 134.34 s; `benchmarks/alpha-readiness-validation/alpha-master-packaging-junit.xml`. |
| Grant reader | `7ac1e45` | Unique `888b2e1` bounded descriptor reader and tests, exact independent review; **external `8c9c319` source excluded**. | **424 passed, 37 skipped, one historical xfail**, 129.59 s; `alpha-master-grant-junit.xml`. |
| Privacy evidence | `28c562b` | `b4976e1` report and raw traces only; Docker provisioning scripts excluded. | **424 passed, 37 skipped, one historical xfail**, 133.47 s; `alpha-master-privacy-junit.xml`. |
| Offline AI evidence | `1729ffc` | `94c2555` sealed synthetic bundle, baseline and report only; network script excluded. | **424 passed, 37 skipped, one historical xfail**, 128.54 s; `alpha-master-model-junit.xml`. |
| Historical QA | `2b371af` | `b3cf551` older-pin QA document only. | **424 passed, 37 skipped, one historical xfail**, 131.67 s; `alpha-master-qa-junit.xml`. |

The JUnit records were committed after each run; they add no product source. The only product source delta from `2945508` is the selected bounded grant reader in `config.py` and `intelligence_adapter.py`. The frozen SignedFinding, exact InventoryItem, native T4/T5 and protected-writer code have no Alpha delta. On the integrated tree, the original historical grant `--runxfail` still reports `DID NOT RAISE ObservationError` because its old monkeypatch seam is inert; it remains retained and is **not counted as repair proof**. The new actual-descriptor focused test file passed **28/28**. Raw focused outputs are `benchmarks/alpha-readiness-validation/alpha-master-historical-runxfail.txt` and `alpha-master-descriptor-focused.txt`.
