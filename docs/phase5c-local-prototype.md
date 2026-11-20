# Phase 5C local diagnostic prototype handoff

**Scope:** source-only, explicitly invoked library prototype. It is not connected to the `aegis` CLI, a listener, a scheduler, SignedFinding, Evidence, Trust, Rapid approval, or mitigation. It has no deployment path. This implementation is a restricted experiment following the Phase 5C architecture, provisional contracts, and threat/acceptance proposal. It does **not** satisfy their Linux containment or independent preview gates.

## Interface and observations

`src/aegis/diagnostic/local.py` exposes `LocalDiagnosticService` and three fixed typed requests: `InspectPackage`, `CheckService`, and `CheckListeningPorts`. The caller creates a service over an operator-owned disposable snapshot directory, constructs a `DiagnosticRequest`, and obtains a one-use in-memory grant through `authorize()`. Authorization prompts on a local TTY and accepts only the literal `yes`; the grant binds the exact request digest, process ID, UID, service instance and a 30-second expiry. Every operation, including port inspection, needs this consent. The service has no socket, HTTP route, background worker or remote invocation channel. Root and setuid-style callers are rejected.

The only readable files relative to the preopened snapshot root are `dpkg/status`, `systemd/units.json`, `proc/net/tcp`, and `proc/net/tcp6`. Path components are fixed in source. `openat`-style descriptor-relative access with `O_NOFOLLOW` rejects symlinks. Source directories and regular files must be operator-owned and not group/other writable; files have a 1 MiB cap and identity/metadata checks across the read. An incomplete or malformed snapshot is inconclusive. No subprocess, shell, network library or external diagnostic command is used. This also avoids subprocess output, execution and child cleanup risk in this prototype. Parsing is bounded by 4,096 rows, 128 listening ports, an 8 KiB result ceiling, deadline checks and cancellation checks.

Each `DiagnosticResult.local-prototype-v0` carries an operation, provisional outcome/reason, opaque target ID, request and source SHA-256 digests, implementation digest, UTC start/finish times, monotonic elapsed time, bounded data and literal `independent_status="unknown"`. It never emits raw socket addresses, package descriptions, command lines, environment variables or fixture paths. `observed` and `not-observed` refer solely to these snapshot checks. A hash is correlation metadata, not an authenticated signature or evidence of a true vulnerability claim.

## Verification and preliminary measurements

Host test command, from this worktree: `PYTHONPATH=src /Users/jackadams-lovell/aegis-network/.venv/bin/python -m pytest -q tests/diagnostic/test_local.py`. The 14 tests cover valid results, malformed/unsupported arguments, denied, wrong and replayed grants, source symlinks and size, duplicates, partial snapshots, output flood, cancellation, timeout, privacy, no-write behavior and rejection by SignedFinding/native Evidence schemas.

The offline Linux smoke script is `scripts/phase5c_linux_smoke.py`. It ran in cached image `sha256:798501b964cccbe9af725dbde4ce784aefd56deb46b8cb331f1d4ebe63d61741` (Python 3.11.16, Linux 6.8.0-117-generic, ARM64) as UID 65534 with `--pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --cpus 1 --memory 256m --memory-swap 256m`, a 32-PID limit, private 16 MiB `/tmp` tmpfs, and the source worktree mounted read-only. No network fetch was made. It exercises all three operations and eight adverse checks. The fixture tree's bytes, mode, owner, mtime and paths were identical before/after every measured diagnostic. The fake credential canary and socket address were absent from all results.

| Preliminary sample, 30 requests in one Linux process | Measured |
| --- | ---: |
| Request-to-result p50 / p95 / max | 1.028 / 1.287 / 1.368 ms |
| User / system CPU, all 30 requests | 47.502 / 8.071 ms |
| Peak process RSS / Python tracked allocation | 24,352 KiB / 93,072 bytes |
| Largest serialized result | 776 bytes |
| Fixture writes during diagnostic calls / canary disclosures | 0 / 0 |

The timing sample includes local pseudo-terminal consent, parsing and serialization; it uses repeated calls in one process and is **not** the proposed 30 fresh process per arm experiment. The memory number is a process high-water mark, not aggregate cgroup accounting. The read-only mount and `--network none` contain the smoke fixture, not a future host invocation. No syscall tracer was used, so attempted effects are not independently observed. The local pytest suite ran on macOS; the Linux smoke uses only the standard library because the cached image has no pytest.

## Security limits and release status

This library reads operator-owned snapshot files; it does not inspect live host package, service or socket state. There is no administrator-owned enrollment registry, peer-credential broker, sealed memfd, pinned worker image, namespace/seccomp profile, cgroup owned by the service, independent syscall tracing or output-capability implementation. A same-UID process with a pseudo-terminal can impersonate local operator consent. In-process deadline checks cannot preempt an arbitrary blocking host operation, and the service has no hard kernel memory ceiling. Concurrent source mutation is checked by metadata before/after read, but a malicious same-UID writer can still race it. Source hashes and local transcripts cannot establish independent custody.

Accordingly this is **NO-GO for a local-lab security preview, live inspection, CLI integration, production deployment or any authority bridge**. VAL-1's 24-case × three-repeat independent safety matrix, pinned seccomp and tracer, 30 fresh process per arm resource experiment, and separate security approval remain outstanding. There is no master merge.
