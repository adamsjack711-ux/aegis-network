# Linux CLI alpha installed validation

**GO for observation-only virtual-environment installs in the four frozen Linux arm64 configurations.** All four installs and uninstalls, 84 logical console cases in both human and JSON modes, and 68 resource cases passed. The [machine-readable matrix](matrix.json) identifies each immutable image, wheel receipt, count and measured hard-limit maximum.

## Source and supply

The original failure evidence remains at b909957c180ee26b8e38a8a78be1a3f39413713d. The launcher fix at fa8272b507a9b86168b4dd4d85e75a48d9b1699b replaces the generated Python stub with a same-process POSIX launcher. It starts the installation's adjacent interpreter with -B before startup imports and -P to exclude the working directory from the initial module search. The final candidate at 7f9f2a23909ad4f3aee7a5860ea1d5bed8e57730 also updates the development wheel inspector and its configuration test. Its complete archived build inputs (pyproject.toml and src/aegis) are identical to the launcher-fix commit. The new inspector supports both the historical generated entry point and the new executable script, selecting the expected layout from the pinned source.

The approved 32 dependency archives, tracer and local images came from preparation 4b270926d3d8125946d854fbfea4d0076a913fd6 and independent review c4cd31a4c7c243c52928b076d1573fd270747ece. The original supply binding remains under supply-prep. The reviewer checked the new candidate binding before matrix execution. Host issuer and custodian UID 501 generated disposable public grant files, mounted read-only for consumer UID/GID 65534. Each console cell retains the issuer manifest, ancestor ACL listing, mount records and effective consumer checks. Private signing material remained in memory.

## First installed command and artifact identity

The [smoke archive](smoke/results.tar.gz) contains the uncensored startup trace and outputs. A fresh venv installed the wheel and dependencies offline with --no-compile. The package cache list was empty before the first Aegis invocation. From /tmp with its venv on PATH, the non-root caller ran bare aegis status, with no caller-supplied Python settings. It returned the expected 2 and reported observation-only mode and unknown independent Evidence status. Among 177 syscalls referencing cache paths the trace showed zero bytecode-cache write attempts. Base image standard-library caches were as supplied in the immutable Debian image. [Smoke script](smoke/run.sh) · [Oracle](smoke/check.py).

After that trace, two clean offline builds produced identical wheel and source artifacts. The two final-commit builds independently reproduced both byte sequences. The exact packages and all four build reports are in [builds](builds/).

| Artifact | SHA-256 |
|---|---|
| aegis_network-0.1.0-py3-none-any.whl | d537263a4e15e56dd2ffc940b2ad99c3b4e78486d09b21e52fd69383eb64f50b |
| aegis_network-0.1.0.tar.gz | 8bf568725cc7f39b291a531b4cbd6018cef171e56a546e2bbb0e1d5f41e45ed2 |

## Installed effects and limits

Each cell ran from /tmp, offline, outside the checkout, with a read-only root and disposable writable mounts. The unchanged [console worker](console/worker.py) captured stdout, stderr, exit, full syscall trace and content-addressed tree snapshots for each invocation. The independent reviewer used the original trace analyzer and inspected all 32 opt-in or unsafe-state-path controls. All 136 default/error invocations had zero attempted writes. Across 168 invocations, the launcher produced zero cache-write attempts, down from 11,928 in the original evidence. Grant fixtures and explicit state belong only to their cell.

The 12 hard-limit trials each checked 100,000 exact rows and emitted 43,889,275 JSON bytes. The highest child RSS was 154.410 MiB under a 256 MiB cgroup, the longest wall time was 2.436180 s, and the highest CPU time was 1.677261 s. No OOM kill occurred. Per-cell limits, output hashes, stderr, compressed output and scoring are in [resource/results](resource/results/). All 68 resource cases used ordinary launcher defaults.

## Reproduction

Use a new evidence checkout so launchers can create empty result directories. Populate its sibling alpha-bytecode-inputs directory with the reviewed wheels and tracer. Build twice using scripts/phase5b1_build_offline.py from the final candidate, with the full source pin, canonical wheelhouse path and a distinct empty output directory each time. The [console driver](console/launch.py) records its original launcher pin and checks every pip receipt against the reviewed input manifest. Execute it with the fixture-generating host interpreter and PYTHONPATH=src:scripts. That host variable is absent from the installed console. Reproduce the resource runs with [the separate driver](resource/run.py). Recheck stored evidence with smoke/check.py, the frozen validation/privacy/analyze.py, resource/verify_results.py and matrix.py. Apply the independent explicit-state assessment to the traces flagged for manual review.

The first broad source run retained one failure in the source test that specifically asserted the superseded generated-stub configuration. [Original source-suite log](regression.log) · [Final source-suite log](final-regression.log). The frozen installed privacy and resource acceptance criteria remained in force.

The validated layout has the launcher and its Python interpreter in the same venv bin directory. Relocated standalone launchers, arbitrary user-install layouts, other platforms and host-writable grant directories fall outside this decision. Publication and merging require separate decisions.

The full final source suite passed 452 tests and five subtests, with 37 optional skips and one historical expected failure. The installed release matrix had zero skipped or unrun cases. The [independent review](independent/) retains the per-invocation adjudication and the traces used for the decision.

An additional independent source-suite attempt omitted a required import path and stopped at collection. A second, socket-restricted run recorded 372 passes, 55 failures, 25 errors, 37 skips and one expected failure. Its logs retain local socket permission errors. The final complete run with fixture sockets available is recorded in [JUnit](final-regression.xml). These diagnostic source runs used different permissions from the four installed acceptance cells.
