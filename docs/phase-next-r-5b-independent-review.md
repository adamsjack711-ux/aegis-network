# Phase 5B-R independent source serializer review

**Narrow decision:** GO to review the isolated `cli._emit` streaming change for source-level integration; **NO-GO** for installable Linux CLI alpha. Candidate source/harness pin `9b69c486b1dd6dff1d7eaa0f7a3858c711385d41`, owner raw-only final pin `4ad4d8daa28e6d511324514b67ad915b25b43afe`, baseline `d15a3a756b8066c5cb2d98665662220e52f4a7d6`. The feature worktree was clean. The source diff changes `src/aegis/cli.py` only for incremental JSON emission and bounded closed-stdout handling; it does not change the signed Finding, grants, package identity, observation schema or writer interfaces. The candidate's own resource and negative harnesses were reviewed and run independently, with new raw stored here, not in the owner branch.

## Independent offline results

The 18 focused streaming/CLI tests passed (18/18, no skips). An independent fixed 100,000-package object was sent to the baseline and candidate `_emit` functions inside the same Linux fixture; both output **8,989,025 bytes with identical SHA-256** `aefdd02352ed206629c241a8380c73751b3c3269a2f1ab82cadbf00aa3816b52`. Both exited 0 and created no implicit state. A preliminary comparison of two live `inventory` commands had equal byte counts but different hashes because their `captured_at` values differed; its raw is retained as a harness-control failure, not a serializer regression.

The resource trials used cached `lab-kali:latest` at image ID `sha256:f4d96476e0c78b0a45c25acaed6cfc770e469058d23c888ae0e14047f89eebab`, Linux arm64/Python 3.14.6, Docker 29.5.2. A **read-only synthetic `ID=debian` `/etc/os-release` bind** enabled the Debian code path; this is a serialization diagnostic, not an actual Debian install. All runs were `--pull never --network none --read-only --cpus 1 --cap-drop ALL --security-opt no-new-privileges --user 1000:1000`, with `/tmp` and `/var/lib/dpkg` disposable tmpfs and source/scripts bind-mounted read-only. The same owner resource harness generated 100,000 dpkg rows and launched fresh child CLI processes. Wall uses `perf_counter_ns`; child CPU and peak RSS use `wait4`; OOM comes from cgroup `memory.events`. The three trials per main arm are descriptive and do not establish tail capacity.

| Source and hard cgroup | Completed | Wall p50/p95/p99 ms | Peak RSS MiB | CPU max ms | Output bytes/run | OOM kills |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline, 512 MiB | 3/3 | 846.143 / 855.345 / 856.163 | 190.762 | 831.100 | 43,889,275 | 0 |
| Candidate, 512 MiB | 3/3 | 1198.759 / 1200.348 / 1200.490 | 107.027 | 1176.680 | 43,889,275 | 0 |
| Candidate, 256 MiB | 3/3 | 1213.464 / 1227.590 / 1228.845 | 107.219 | 1209.846 | 43,889,275 | 0 |

On this exact fixture, candidate peak RSS is about **44% lower** than baseline at the same 512 MiB limit, while median wall is about **42% higher**. The owner reported a different Debian/Python 3.12 fixture with 298.602→106.328 MiB and 1175.667→1328.522 ms; that is retained as owner evidence and is not substituted for this independent run. The difference in baseline RSS underscores runtime dependence. The independent 256 MiB 100,000-row arm finished 3/3 with zero cgroup OOM kills and no implicit state. The prior 3/3 256 MiB OOM baseline remains retained unchanged.

One slow-reader trial at 2 ms per 64 KiB finished in 2341.669 ms, 107.461 MiB peak RSS, exit 0, 43,889,275 bytes. One immediately closed-stdout trial exited 2 in 710.757 ms, 106.566 MiB peak RSS, zero output bytes and no traceback. Three negative children (malformed feed, >8 MiB feed, duplicate inventory) each exited 2 in 107.396–112.549 ms at 36.816–44.695 MiB peak RSS; no changed paths under the declared `/tmp` or `/var/lib/dpkg` writable mounts and no implicit state. The source CLI's grant and import boundaries were not changed by the serializer diff; their prior acceptance still requires integrated regression.

## Scope and remaining gates

The frozen alpha matrix requires an installed offline wheel and direct console on **real Debian and Ubuntu** for Python 3.12 and 3.13, 24 default logical cases plus eight explicit-state controls per version pair, negative signature/grant cases, syscall tracing of attempted network/subprocess/privilege/write effects, and 100/10,000/100,000-row resource arms per claimed runtime. None of those install/platform/syscall gates was independently completed at this source pin. Kali plus a read-only Debian identity file is not a distribution substitute. The local host focused run used Python 3.14; it establishes only test behavior at that interpreter. The console/package boundary remains **NO-GO**, regardless of the narrow serializer result. No production or enforcement capability is enabled.

## Reproduction and raw hashes

All container commands used the flags above, `lab-kali:latest`, and `PYTHONPATH=/work/src`; source bind was baseline or candidate, and the candidate's `phase5b_release_r_resource.py` or `phase5b_release_r_negatives.py` script was mounted read-only. Main invocation: `python3 /work/scripts/phase5b_release_r_resource.py --packages 100000 --repetitions 3`. Slow and closed added `--repetitions 1 --reader-delay-ms 2` and `--repetitions 1 --closed`. Fixed byte comparison: `python3 /work/compare.py`, with both source trees mounted. Raw files record individual exit/CPU/RSS/wall/output/OOM outcomes.

| Raw file under `benchmarks/phase-next-r-validation/5b-r/` | SHA-256 |
| --- | --- |
| `focused-tests.txt` | `02c1acdc6740172dfd1937809b3ad6218d942ff92d47d16341609d72852e2ced` |
| `baseline-512m-100k-kali-debian-fixture.json` | `8dfd6c480cc7037ab467d9ac079fd882108f568cd64a4af4d2cf0e81d53aeccf` |
| `candidate-512m-100k-kali-debian-fixture.json` | `2b87233ef899ff01157bb5d74940030c84a3d443c73729bf2446a87a1ced3a98` |
| `candidate-256m-100k-kali-debian-fixture.json` | `4698412a011462ee316f4c145cfdc535bdd7ed39e6d065ddb062e0d6930909d5` |
| `candidate-slow-kali-debian-fixture.json` | `8164dc9692016a195ff62afa18d428bfb23310a4eb5abb5956fb973a933c7b88` |
| `candidate-closed-kali-debian-fixture.json` | `38fdebd92496b03fcd89044aa90e888d00c8203759ec7c9ab7d4ff0b7af90629` |
| `candidate-negatives-kali-debian-fixture.json` | `ad58c585cde693a661dad3066acb9eb3e5c63c753bab8a12458a31a31636980f` |
| `byte-equivalence-kali-fixed-fixture.json` | `66be9f6582abcfc93da2e69b820062924c87b7ae1a23d9bf9c923cc287aabad8` |
| `live-command-dynamic-comparison.json` | `e7d3cc2c7924dee4d5fc38d050f27f01c0248b4146eb0a957754b3f0ebc3a41f` |
| `debian-os-release.fixture` | `9b448eceae8dce8a671055278d10daf29118420837e06a3854e389c02df0caae` |
| `scripts/phase_next_r_5b_compare.py` | `04d67a90ac62772e3af4a7e66d008522eedba89643cc7b79d5e551170e5f556d` |

Original 256 MiB OOM, Ubuntu hybrid, Python 3.13 and syscall gaps remain in the frozen manifest; none was overwritten.
