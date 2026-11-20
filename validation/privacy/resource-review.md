# Independent installed resource and release appraisal

Owner raw evidence pin: `test/linux-alpha-installed-matrix` at `819c142125f6292288d0ae9958c6221e34979f40`. Exact installed source candidate: `fc4a17bc6f9f0c289a645c4fb7006c999ba90e99`; launch review pin: `ad830ada4bb13e45b9f192bc54c165281e8d9b50`. I read the committed resource and console raw files without editing their owner files or running another container.

## Resource gate: GO for the isolated measured workload

The frozen resource denominator is **68/68 passed, 0 failed, 0 unattempted**: 36 normal inventory children (100, 10,000, 100,000 rows; three trials per size and cell), 12 hard 256 MiB children, 12 conservative negative children, four slow-reader children, and four closed-consumer children. Four arm64 distro/interpreter cells were represented: Debian 13 and Ubuntu 24.04, each with Python 3.12 and 3.13. I checked all 68 individual JSON records against their summary records and recomputed every available stdout byte count and SHA-256. I independently streamed and checked the exact name, version, architecture, purl, source, envelope and order of all **2,400,000 rows** in the 24 normal/hard 100,000-row outputs. Each full output was 43,889,275 bytes. Twelve malformed, oversized, and duplicate negative outputs were independently decoded and confirmed conservative with exit 2, no implicit identity or tree changes. The four supplementary closed-consumer controls each retained exactly 4,096 bytes, whose SHA-256 matched the record; exit 2 had no traceback, OOM, or timeout.

| Cell | 512 MiB children | 256 MiB children | Peak 100k normal RSS | Peak 100k hard RSS |
| --- | ---: | ---: | ---: | ---: |
| Debian 13 / Python 3.12 | 14/14 | 3/3 | 156.523 MiB | 148.973 MiB |
| Debian 13 / Python 3.13 | 14/14 | 3/3 | 159.664 MiB | 152.031 MiB |
| Ubuntu 24.04 / Python 3.12 | 14/14 | 3/3 | 160.746 MiB | 153.219 MiB |
| Ubuntu 24.04 / Python 3.13 | 14/14 | 3/3 | 161.562 MiB | 154.023 MiB |

The maximum recorded child RSS across all 68 was 161.668 MiB (closed consumer); all normal/hard 100,000-row runs were below the 256 MiB ceiling. The 24 normal/hard 100,000-row runs took 1.901–2.229 seconds wall time and 1.350–1.547 seconds child CPU time. All eight resource containers exited zero. The recorded cgroup readbacks matched their 512/256 MiB limits, zero swap, one CPU and 64 process cap; all child OOM deltas and timeouts were zero. Input and feed digests, writable-tree snapshots, and implicit-state checks were unchanged/absent for all 68. The 512 MiB workload includes three conservative negatives and a slow reader; the 256 MiB workload exercises three independent 100,000-row hard runs per cell.

The resource harness sets `PYTHONDONTWRITEBYTECODE=1` and excludes the installed venv and named output sink from its tree snapshot. This is suitable for a bounded resource measurement; it **does not** clear the default-invocation privacy failure recorded in `validation/privacy/review.md` (CPython cache write attempts in 168/168 traced console invocations). The closed-consumer correction is supplementary evidence to the original 68-case matrix, which initially did not retain the 4,096-byte prefix. Retain both records. `ru_maxrss` is per child and does not prove peak total container usage, although the 256 MiB cgroup bound and zero OOM are independent controls. This is four disposable local fixtures and a fixed corpus, not a broad distribution guarantee.

## Installed package and removal gate: GO for the four local fixtures

The scored console matrix records **4/4 offline installs and 4/4 uninstalls** with Docker exit 0, no worker failure, and `uninstall.exit` 0. I independently checked all four pip install reports: each contains 24 unique `file://` archives with recorded hashes matching the immutable wheel manifest and candidate wheel digest `28943894bfe543338a353a538fac3a26e9fd552df730e4cb83921953503727e5`. The resource matrix also completed eight separate offline installs (four cells × two cgroup limits), each with 24 matching archives and pip check. The console harness verifies that the entrypoint and package are absent after uninstall. This establishes installation/removal in the pinned disposable images, not a host-wide deployment claim.

## Release disposition

**CLI alpha NO-GO.** The resource and local install/uninstall gates pass on the exact candidate, but the frozen privacy gate fails: all 168 default installed invocations made denied, unrequested bytecode-cache write attempts; the 68 logical default/error privacy cases score 0/68. The grant custody observations remain local-fixture evidence, with host same-UID and ACL questions unresolved. No production or distributed-enforcement readiness follows from these results.

Evidence anchors: `validation/resource/results/overall.json` SHA-256 `6f3d6c387d7fbe2b1bdbf586dc1734dd9f0bb51a1b6fd193f1a5bbf7365b83b2`; `validation/resource/results/verification.json` SHA-256 `22a83daa0e16fc8f3081cb72fe86804a5b42e87e02671348e70dafaad49d3148`; `validation/matrix.json` SHA-256 `9d1db346b08fe2d849455a0d184ac0e9be3744e287c45873676799ee3832294b`. Raw per-child JSON and compressed stdout remain under `validation/resource/results/<cell>/{512m,256m}/`; corrected closed-consumer records are under `512m-closed-correction/`.
