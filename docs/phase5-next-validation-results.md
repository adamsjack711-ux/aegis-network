# Phase 5 next independent validation results

## Identity and method

Validation branch `test/phase5-next-validation`, worktree `.worktrees/phase5-next-validation`; starting product tree `8292e531194216a578c32c912d066f98cdbce9ea`. Acceptance freeze commit `68f9fd8fc84e8d92673c43ad20e3230a714ddac2` changed only validation documents and the frozen input manifest. The research evaluator ran on clean `68f9fd8`; subsequent checks used its unchanged product source. The main checkout was dirty and was never used for a test or edited. Environment: macOS arm64, Python 3.15.2 for source tests; local Docker metadata was read, but no container install or external service was used. No implementation branch or master was changed.

The freeze manifest verified **15/15 input files** by SHA-256 and fixed 24 research case IDs and expectations. Its SHA-256 at freeze was `312fbfe4269c39649dbb690a0bd090b01ad1dcf8b6a47857b55a3714cab27b6f`. The existing `phase-next-six` and `phase-next-r` original evidence manifests remain referenced byte-for-byte, including original 5A unsupported positives, 5B implicit write, signed-current ambiguity, grant check/read race, 256 MiB OOM and 4F timing failures. None is recast as a passing test.

## Research, exact pin `68f9fd8`

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../../.venv/bin/python scripts/phase5a1_evaluate.py --output /private/tmp/aegis-phase5-next-5a1.json` produced [raw per-case output](../benchmarks/phase5-next-validation/research-raw.json). The independent [byte and label audit](../benchmarks/phase5-next-validation/research-check.json) verified source bytes across all 24 cases, claim byte spans and digests, emitted source IDs, required conflict citations and unverified authority flags; **zero audit errors**. It used `scripts/phase5_next_validate_research.py` against the frozen manifest. The three visible-36 repeats and six V01–V12 order/repeat trials remain separate in the raw report.

| Set | Planned / attempted | Result | Limit |
| --- | --- | --- | --- |
| Frozen 24 synthetic cases | 24 / 24 | Deterministic exact **23/24**, one Debian epoch case P02 inconclusive; zero false affected. All three conflict cases stay unknown with both citations. Hostile I01–I03 instructions were not promoted. | Source labels are synthetic and unauthenticated. The parser does not handle the fixed Debian epoch case. |
| Scripted stress on the same 24 | 24 / 24 | Raw scripted response said affected for all cases: **20 false affected**; deterministic guard emitted zero unsupported scripted points; checked top-level exact **18/24**. | A fixed script is an injection guard, not a model accuracy or cost result. Its invented “remote execution” point was unsupported and stayed unreportable. |
| Independent V01–V12, six passes | 72 / 72 | 54/72 exact over all planned, 66 eligible, six epoch-inconclusive, zero false affected. V03 and V10 abstained instead of the expected unaffected classification in each repeat. | Separate from the 24-case synthetic set; no semantic adjudication or authenticated advisory. |
| Real model | 72 planned / **0 attempted** | Skipped. No model response, token bill or latency result. | No enrolled endpoint, export scope, credential or billing oracle. |
| Authenticated archived advisories | No pinned eligible cases | Unverified. | Local fixture roles and hashes do not prove external custody or current advisory status. |

`source_claims_emitted` include byte-bound, `independently_verified=false` fixture-parser-consistent points. The independent audit verifies byte identity and locator consistency; it cannot establish real-world claim truth. Model output alone grants no Evidence, SignedFinding, local approval or mitigation authority.

## Linux CLI, exact source `68f9fd8`

The focused source command `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../../.venv/bin/python -m pytest -q -rx -p no:cacheprovider tests/test_phase5a_alpha_eval.py tests/test_phase5a_claim_integrity.py tests/intelligence_phase5a1 tests/test_phase5b_cli.py tests/test_alpha_linux_release.py tests/packaging_phase5b1 tests/cli_safety_phase5b2` returned **44 passed, one expected failure** in 1.59 s. [Raw pytest output](../benchmarks/phase5-next-validation/focused-source-tests.txt) names the retained grant-file race xfail. These are source-level controls, including signed exact-match `independent_status=unknown`, default no-write fixtures and malformed input handling; they do not count as installed-console trials.

The exact-source offline release command `python3 scripts/alpha_linux_release.py 68f9fd8fc84e8d92673c43ad20e3230a714ddac2 /private/tmp/aegis-phase5-next-empty-wheelhouse /private/tmp/aegis-phase5-next-release-preflight` exited **2**, `status=incomplete`, before build because the reviewed wheelhouse manifest was missing. [Raw preflight](../benchmarks/phase5-next-validation/linux-release-preflight.json) records this. A local search found zero original Hatchling, cryptography or pydantic-core wheel archives under `/private/tmp` and repository worktrees. [Cached image inventory](../benchmarks/phase5-next-validation/cached-linux-images.txt) shows Debian/Python 3.12 and 3.13 and Ubuntu/Python 3.12 candidates, but no Ubuntu/Python 3.13 image. No image pull or dependency download was performed.

| Required denominator | Observed at this pin | Decision |
| --- | --- | --- |
| Two offline wheel and sdist build pairs | 0/2, both skipped on missing reviewed wheelhouse | Incomplete |
| Fresh Debian/Ubuntu × Python 3.12/3.13 installs | 0/4 | Unverified |
| Generated `aegis` entry point, default/error/state/signature cases | 0/84 installed logical cases | Unverified |
| Installed resource/privacy children | 0/68 | Unverified |
| Installed attempted-effect syscall traces and every writable mount | 0; reviewed tracer and installed artifact absent | Unverified |

The prior Debian 100,000-row hard-256 MiB OOM **3/3** and the original implicit-state write remain historical failures at their own pins. A later source-only performance result does not replace a fresh installed child under the four-cell resource envelope. Correct signed-finding behavior and unknown independent status passed focused source checks only. No claim of bounded installed CPU/memory or zero attempted writes/connections is made.

## Diagnostic Runner design review

The exact baseline has the revised `proposal-v0` contract and architecture, with **no `src/aegis/diagnostic/` implementation**, installed operation registry, authorization broker or sealed worker. The design calls for a source-reviewed fixed profile registry with strict input grammar; an out-of-band one-use local capability bound to operator, enrolled disposable target, profile and sealed bytes; pinned executable and image digests; descriptor-relative fixture lookup and sealing; a non-root no-network worker with namespaces, second-stage seccomp, hard cgroup/FD/tmpfs limits; bounded result and sanitized stderr; and a separate output capability for any host file. It explicitly keeps `independent_status=unknown` and has no adapter to mitigation, SignedFinding or native Evidence.

Those are design requirements, not observed controls. Registry bytes, canonical golden requests, broker and peer-credential behavior, seccomp bytes, tracer digest, complete mount inventory, cancellation cleanup and output-redaction trials are absent. Zero of the **72** frozen safety trials and zero of **30 baseline +30 candidate** resource processes were run. Review outcome: design suitable for further isolated prototyping; runnable diagnostic preview **NO-GO**. No disposable fixture was launched because there is no reviewed runner to exercise.

## Release decisions

| Capability | Decision at this exact pin | Basis |
| --- | --- | --- |
| AI research experiments | **GO only for inert synthetic offline appraisal; NO-GO for real-model or authenticated archived-advisory claims** | 23/24 deterministic exact, no false affected or authority promotion in the synthetic audit; P02 inconclusive and real-model/archival evidence absent. |
| Linux CLI alpha | **NO-GO** | Offline dependency, one image, all four installed cells, 84 cases, 68 children and attempted-effect traces missing. |
| Diagnostic Runner prototype | **NO-GO for runnable preview** | Design-only; 0/72 safety and 0/30+30 performance. |
| Native enforcement | **NO-GO** | Retained pre-observation and five-second withdrawal failures; no successor 72+18 exact-pin matrix. |
| Distributed autonomous enforcement | **NO-GO** | Native gate open; no independently administered multi-host custody, anchored rollback protection or complete writer/ACK/cursor barriers. |

Every skipped or unverified item remains in its original denominator. No result here authorizes an external host, model call, enforcement action or product release.
