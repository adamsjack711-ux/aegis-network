# Phase 5B-R owner serializer evidence

These are **owner-reported source-CLI measurements**, pending independent
VAL-R reproduction. The candidate source/harness pin is
`9b69c486b1dd6dff1d7eaa0f7a3858c711385d41`; the serializer change is
`f86ca372eabfb806af71c814099dd75e9d38491a`. The baseline was archived
from `d15a3a756b8066c5cb2d98665662220e52f4a7d6` and run through the
same resource harness. `SHA256-manifest.json` hashes each raw file.

## Method and exact scope

The cached Debian arm64/Python 3.12.16 image was run with `--pull never`,
`--network none`, `--read-only`, UID/GID 1000, no capabilities or new
privileges, one CPU, 512 MiB or 256 MiB cgroup memory, and disposable tmpfs
for `/tmp` and `/var/lib/dpkg`. The `src` tree and scripts were mounted
read-only, with `PYTHONPATH=/work/src`; this tests **source invocation**, not
an installed wheel or generated console. No external host, image pull,
credential, or production integration was used.

The resource command in the container was:

```sh
python /work/scripts/phase5b_release_r_resource.py --packages 100000 --repetitions 3
```

The harness writes 100,000 synthetic installed `dpkg` rows to tmpfs, starts
three fresh `python -m aegis.cli inventory --json` child processes, reads
their stdout in 64 KiB chunks, and records child wall time, CPU, peak RSS,
output bytes, exit status and cgroup memory-event deltas. Slow output added
`--repetitions 1 --reader-delay-ms 2`; closed output added
`--repetitions 1 --closed`. The negative command was
`python /work/scripts/phase5b_release_r_negatives.py`, testing malformed
feed, oversized feed and duplicate inventory with before/after tree hashes.

| Arm | Completed | Wall p50 / max | Peak RSS | OOM kills | Output |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline, 512 MiB | 3/3 | 1,175.667 / 1,198.741 ms | 298.602 MiB | 0 | 43,889,275 bytes/run |
| Candidate, 512 MiB | 3/3 | 1,328.522 / 1,427.511 ms | 106.328 MiB | 0 | 43,889,275 bytes/run |
| Candidate, 256 MiB | 3/3 | 1,289.300 / 1,292.464 ms | 106.332 MiB | 0 | 43,889,275 bytes/run |
| Candidate, 256 MiB, slow reader | 1/1 | 2,593.325 ms | 106.312 MiB | 0 | 43,889,275 bytes |
| Candidate, 256 MiB, closed reader | 1/1, exit 2 | 665.994 ms | 106.090 MiB | 0 | 0 bytes |

The same-harness comparison reduces observed peak RSS by about 64% and raises
median wall time by about 13%. Three trials are descriptive. They do not
establish p99 capacity, installed-wheel behavior, Ubuntu behavior or a
general performance improvement. All candidate standard runs were under the
frozen ≤5 s, ≤5 s CPU, ≤256 MiB RSS and ≤64 MiB output bounds. The 256 MiB
control had 3/3 exits 0 and zero cgroup OOM events. No implicit XDG state
was created in any resource arm.

The three negative children exited 2 in 118–133 ms at 36.8–44.8 MiB RSS,
with ≤408 bytes of output, no stderr traceback, no changed paths under the
declared `/tmp` or `/var/lib/dpkg` writable mounts, and no implicit XDG
state. Fixed fixture tests compared all five JSON command outputs byte for
byte with the previous `json.dumps(..., sort_keys=True, indent=2) + "\n"`
contract. The host Python 3.14 focused CLI/streaming/Rapid suite passed
29/29. A closed stdout consumer receives exit 2 without a traceback.

## Open and skipped gates

This pin **does not clear installable Linux alpha**. A clean offline wheel and
direct installed-console matrix from this source pin were not attempted.
Fresh Ubuntu dependency resolution, Python 3.13, syscall-level attempted
effect tracing, concurrent state-path replacement and the full integrated
regression suite were not attempted. The baseline's retained 256 MiB OOM
failure remains the comparison control; it was not rewritten or erased.
The original 5B signature, grant, exact package and independent Evidence
status contracts remain unchanged. Production distribution and enforcement
remain disabled.
