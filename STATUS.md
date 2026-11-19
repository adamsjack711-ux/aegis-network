# Aegis Network status

## Phase 2 release candidate

The verified local dry-run candidate is `ffe5c322b144ab3fb40d2ee29b1486b917d339f1` on `integration/phase2-release-candidate` in `.worktrees/phase2-release-candidate`. Its runtime was built and benchmarked at `db90aa0`. Independent release approval is pending. The worktree is separate from master and both Phase 2 source worktrees.

The RC starts from Phase 2C `65ebb3a` and adds Phase 2D's post-commit outbox wakeup while retaining periodic fallback. It preserves scoped revocation, UUIDv4 broker leases, ordered journal replay, durable local denial, and broker-confirmed acknowledgment after SQLite audit. A separately measured worker trial regressed tail latency and CPU on the combined path. The candidate retains synchronous local evaluation.

**Verified on 2026-11-19.** All 40 unit and regression tests passed with one third-party deprecation warning. Live checks passed for signed broadcast, duplicate suppression, invalid signatures, lease collision, scoped withdrawals, broker purge and journal replay, malformed input, agent and coordinator crashes, network partition, slow consumer, and a 40-event broker backlog. The backlog drained with 80/80 decisions in 2.161 s. The agent SIGKILL check recovered in 30.650 s, including lease expiry.

At 3, 10, and 100 agents, all final runs recorded 60/60, 200/200, and 2,000/2,000 decisions respectively with no duplicate logical rows. Median run p95 was 33.685, 32.396, and 876.545 ms, compared with 307.429, 312.558, and 936.173 ms in the fresh Phase 2C baseline. At 100 agents the observed latency ranges overlapped and median throughput fell 5.5%. The candidate demonstrated a consistent low-agent improvement.

See [the release-candidate report](docs/phase2-release-candidate.md) for exact stages, image IDs, commands and recorded results. Replay completeness, broker identity and authentication, historical trust, audit integrity, and sustained overload remain open. Use remains local and dry-run. No master merge, production access, autonomous mitigation, or Phase 3 implementation occurred. The local RC containers are stopped.
