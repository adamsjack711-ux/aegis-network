# Phase 5B recipient install gap

**PASS for one private recipient cell.** The exact `50ba781` wheel passed
an observation-only console and uninstall smoke on Ubuntu 24.04.5 LTS
arm64 with CPython 3.12.13. This is the same cell that already installed
the wheel for the packaged history tests.
[Linux transcript](../benchmarks/studio-5b-recipient-install/console.log) ·
[Wrapper exit](../benchmarks/studio-5b-recipient-install/console.exit)

## Retained evidence

| Exact wheel | Recorded Linux coverage |
| --- | --- |
| Launcher candidate `7f9f2a2`, SHA-256 `d537263a4e15e56dd2ffc940b2ad99c3b4e78486d09b21e52fd69383eb64f50b` | Four arm64 venv cells passed install, 168 console invocations, 68 resource cases, and uninstall. The independent review retained syscall traces and verified the launcher cache-write fix. See `26a5e26:new-run/README.md` and `new-run/matrix.json` at that pin. |
| Combined private tester `9ba94a8`, SHA-256 `4afa7a6669b5f4b719be75bc53367cd4a52877ee59b831b056fb4a61072665b8` | Debian 13 arm64 passed on CPython 3.12.16 and 3.13.18. Ubuntu 24.04 arm64 passed on 3.12.13 and 3.13.14. Each cell passed install, 42 console invocations and uninstall. The private record also passed all 68 resource cases. The fresh Studio walkthrough separately passed the Ubuntu 3.12.13 install, status and uninstall. See `c495a8c:private-validation/packaging/summary.json` and `c495a8c:private-tester-bundles/aegis-tester-9ba94a8-walkthrough.log`. |
| `9ba94a8` Studio grant custody | The first approved sequential run in the Debian 13.7 arm64 / CPython 3.12.13 job image returned exit 2 with unknown Evidence status and zero claims. That run attested the stable approved bytes under separate publisher and reader principals. See `8f02e74:benchmarks/studio-5b-first-approved-run/README.md`. |
| Current private recipient `50ba781`, SHA-256 `549a4048bdb2f3034f9c4d26a82f6806a9d52ee7d64a112d015e1294f535d68d` | A fresh Ubuntu arm64 / CPython 3.12.13 venv passed offline install, dependency checks, ordered history, and missing and unreadable database diagnostics. The retained packaged checks cover the history API. See `79cd709:benchmarks/history-open-50ba781/README.md` and the archive's `metadata/packaged-checks.json`. |

Comparing the `9ba94a8` and `50ba781` tester archives verified all 26
dependency wheels byte for byte. Comparing application wheel members found
changes in `aegis/intelligence/handoff.py`,
`aegis/intelligence/investigator.py`, and wheel `RECORD`. The installed
launcher and CLI modules matched byte for byte. This makes a console
packaging smoke on the existing recipient wheel the smallest useful
follow-up. Four-cell validation remains pinned to the older exact wheels.
A future recipient artifact from the Phase 6 integration pin `056b7d4`,
which additionally ships `aegis/intelligence/report.py`, needs its own
artifact receipt.

## Reproduce the single cell

| Input | Pin |
| --- | --- |
| Recipient source | `50ba7818b2a143a7ff4308e6b96c94dc322b9b03` |
| Observed local archive `aegis-tester-50ba781-recipient.tar.gz` | `d4745deb7eb9524092f42a430eaa32682d3b18d4c93af6d0dae7f25076bd306c` |
| Ubuntu 24.04 arm64 / CPython 3.12.13 Studio image | `sha256:6d620701a04f97b737f115f6e750d1fc3b8084d56acd801decfe781893c7443d` |

The runner verifies a private copy of the archive, all 37 manifest members and
the exact application wheel. It uses the pinned image already on Studio,
with pulls disabled, a read-only root and bundle, no network, UID 65534,
and a fresh tmpfs venv. It installs offline and checks dependencies. It
then runs plain and empty-feed `aegis status --json` and checks exit 2,
`status-v2`, observation-only mode, unknown independent and overall status,
and zero claims for the empty feed. It checks the fresh status home and
implicit state path, compares the grant and feed hashes before and after, and
verifies that uninstall removes the launcher, import and distribution.
[Runner](../scripts/phase5b_recipient_install_check.sh)

From the candidate checkout on Studio, set `archive` to the path of the
existing private recipient archive. Retain the full Linux transcript and
exit status together.

```sh
sh scripts/phase5b_recipient_install_check.sh "$archive" --verify-only
rc=0
sh scripts/phase5b_recipient_install_check.sh "$archive" > phase5b-50ba781-console.log 2>&1 || rc=$?
printf '%s\n' "$rc" > phase5b-50ba781-console.exit
```

## Observed result

Colima Docker 29.5.2 ran the pinned image locally with kernel
`6.8.0-117-generic`. Both status commands returned 2 with observation-only
mode, unknown independent and overall status, and empty stderr. The
empty-feed command returned zero claims. The state, fixture, and uninstall
checks all passed. The wrapper exited 0. Transcript SHA-256 is
`e5c78048afee6a75c7fa67f42d17e161b5e324187420008fad74650693becab5`.

The other three frozen cells and the full syscall and resource matrix have
coverage on `9ba94a8`. They remain unrun on the exact `50ba781` recipient
wheel. Concurrent grant rotation, rollback and freshness remain open.
Publication and broader platform support require separate release decisions.
