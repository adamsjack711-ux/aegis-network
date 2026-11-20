# Phase 5B-2 CLI resource and privacy report

Source baseline: `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`. This branch changes only the resource probe, tests, raw results, and this report. It does not alter the CLI serializer, Trust or signing contracts, or packaging interfaces. The tested path is the integrated **source CLI**. The container is cached Kali Linux arm64 with Python 3.14.6 and a read-only `ID=debian` fixture; it is not an installed Debian or Ubuntu console validation.

## Workload and results

The frozen input is 100,000 unique installed dpkg rows named `package000000` through `package099999`, versions `1:0.0-1` through `1:99999.0-1`, architecture `amd64`. The input is 9,388,890 bytes, SHA-256 `3bc8226479aeb287021fd6ae2cd58c30067b83e3c6692bbe84c4d8acc7f39482`. The independent verifier checks the output envelope and each row's name, version, architecture, and purl by position. It rejects dropped, duplicated, altered, or reordered rows. The JSON output was 43,889,275 bytes per run, below the 64 MiB bound.

| Rows / hard cap | Completed | Wall p50 / p95 / p99 / max ms | Child CPU range ms | Child peak RSS range MiB | OOM kills | Exact output and no implicit writes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 100 / 512 MiB | 3/3 | 114.599 / 117.863 / 118.153 / 118.226 | 109.818–114.584 | 36.230–36.965 | 0 | 3/3 |
| 10,000 / 512 MiB | 3/3 | 212.320 / 212.329 / 212.330 / 212.330 | 207.948–208.505 | 42.598–43.086 | 0 | 3/3 |
| 100,000 / 512 MiB | 3/3 | 1203.552 / 1213.127 / 1213.978 / 1214.191 | 1181.359–1205.186 | 105.672–106.449 | 0 | 3/3 |
| 100,000 / 256 MiB | 3/3 | 1219.245 / 1219.989 / 1220.055 / 1220.072 | 1211.336–1215.425 | 105.801–107.480 | 0 | 3/3 |

Fresh `python3 -m aegis.cli --help` process wall time, which includes Python startup and CLI imports, was p50/p95 116.490/116.539 ms in the 256 MiB arm. This is a startup proxy, not first output byte latency. Wall percentiles interpolate three observations and are descriptive, not tail capacity estimates. Every 100,000-row run met the frozen ≤5 s wall/CPU, <256 MiB process RSS and 256 MiB no-OOM controls.

The 2 ms per 64 KiB slow reader completed with 43,889,275 output bytes, 2,400.614 ms wall, 107.012 MiB RSS, and no OOM. The immediately closed reader exited 2 without a traceback, at 737.790 ms wall and 106.621 MiB RSS. Raw data is in `benchmarks/phase5b-performance-safety/`.

## Filesystem, network, and failure evidence

All Linux trials used `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000`, read-only source/script/identity binds, and disposable `/tmp` and `/var/lib/dpkg` tmpfs. The probe hashed both writable trees immediately before and after each CLI child, excluding only its own stdout capture file. All 12 inventory children left those trees unchanged, preserved the input hash, and created no implicit XDG state. There were no cgroup OOM kills. Malformed feed, oversized feed, and duplicate inventory each exited 2 in 116.913–123.294 ms at 35.379–44.254 MiB RSS, with bounded JSON, empty stderr, and no changed paths. These filesystem observations cannot reveal a write attempt that failed or an unobserved writable mount.

Explicit `--state-dir` behavior was checked through two fresh CLI processes on the same non-root read-only-root image: the asset ID persisted, only `identity.json` was created, and modes were 0700/0600. A separate Linux identity probe rejected symlinked parent/final paths. The 20 focused tests passed, including independent Evidence status staying `unknown` for signed local matches and a Python-level guard against socket, connection, process, and shell APIs in default observation.

The container had neither `strace` nor `perf` (`trace-availability.txt`). **Syscall-level tracing and the attempted network/write/exec/privilege-call acceptance item are unverified.** Network namespace isolation blocked external networking, and the Python API guard observed no calls in its exercised path; these do not establish that no socket syscall was attempted. No privileged terminal access or image download was used.

## Reproduction

From this worktree, with the already cached `lab-kali:latest` image ID `sha256:f4d96476e0c78b0a45c25acaed6cfc770e469058d23c888ae0e14047f89eebab`:

```sh
docker run --rm --pull never --network none --read-only --cpus 1 --memory 256m \
  --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
  --mount type=bind,src="$PWD/src",dst=/work/src,readonly \
  --mount type=bind,src="$PWD/scripts",dst=/work/scripts,readonly \
  --mount type=bind,src="$PWD/benchmarks/phase-next-r-validation/5b-r/debian-os-release.fixture",dst=/etc/os-release,readonly \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=128m \
  --tmpfs /var/lib/dpkg:rw,nosuid,nodev,uid=1000,gid=1000,size=64m \
  --env PYTHONPATH=/work/src --env PYTHONDONTWRITEBYTECODE=1 \
  lab-kali:latest python3 /work/scripts/phase5b_performance_safety.py --rows 100000
```

Use `--memory 512m` for the three 512 MiB arms and `--rows 100` or `--rows 10000` for the smaller inputs. In the same container pattern, invoke `phase5b_release_r_negatives.py`, `phase5b_explicit_cli_probe.py`, `phase_next_5b_linux_state_probe.py`, or `phase5b_release_r_resource.py --packages 100000 --repetitions 1 --reader-delay-ms 2` (`--closed` for closed output). Host focused tests: `PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 pytest -q tests/test_phase5b_streaming.py tests/test_phase5b_cli.py tests/test_phase5b_performance_safety.py`.

## Handoff

The integrated source serializer meets this one-image resource and output-integrity exercise. The installed console on actual Debian and Ubuntu, Python 3.12/3.13 matrix, and syscall trace remain outside this result. Do not merge or release on this report alone.
