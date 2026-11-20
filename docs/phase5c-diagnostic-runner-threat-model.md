# Phase 5C Diagnostic Runner threat model

**Scope:** proposed unprivileged local diagnostics only. Review baseline `ec939e14a5acd438ff0d5fa562ed61a70b68f3c9`. See [architecture](phase5c-diagnostic-runner.md) and [record design](phase5c-diagnostic-runner-schemas.md). There is no executable runner in this change.

## Assets, actors and trust assumptions

Assets are the host's package/service/socket metadata; local consent and schedule state; replay and revocation floors; private results/audit; and the integrity of the Phase 5B, Rapid, Trust, Evidence and protected-writer boundaries. A local operator controls installation, consent, revocation and export. Remote AI, its transport, advisory text, Mesh payloads, inbox metadata and local files supplied as proposals are untrusted for execution authority. An ordinary same-host user may try to read another user's state or saturate the scheduler. A compromised process under the runner's own UID can modify its state and is a serious residual risk; an administrator or compromised kernel is outside the proposed protection boundary. The scheduler, local approval UI, installed registry and OS isolation primitives are trusted components that need independent validation.

The runner needs read access only to the selected `dpkg` database, limited systemd status or selected `/proc/self/net` tables, and its private state. It needs no root, Linux capability, target writer, broker credential, publisher private key, T4/T5 trust key or general network access. Remote suggestion intake and optional outbound sharing are separate processes/adapters with narrower interfaces. A signed remote message, if ever added, would authenticate origin only; it would still carry no local run permission.

## Attack paths and required controls

| Attack | Boundary crossed | Required prevention or detection | Residual or failure state |
| --- | --- | --- | --- |
| Prompt injection asks AI to run `curl`, shell, Python or a fabricated operation | Model text → runner | Strict proposal schema, closed compiled registry and no command field; no shell or dynamic plugin | Reject and audit fixed reason; never transform prose into argv |
| Argument injection through a package/unit name, leading hyphen, template expansion or Unicode lookalike | Untrusted argument → OS interface | Exact ASCII grammar, length, local service allowlist, fixed argv, `--` where reviewed; no user paths or variable environment | Reject before worker launch |
| Spoofed transport identity or forged `origin=manual` | Remote inbox → local consent | Local adapter mints request and origin; consent stored by local UI only; transport auth is metadata | Inert proposal even if transport authenticates |
| Replayed request, approval, schedule tick or old install snapshot | Persistent state → admission | Request ID plus digest, atomic used ledger, due-slot key, install ID, policy generation, expiry, rollback floor; fail closed on corrupt/rolled-back state | Unknown/needs local re-enrollment; no automatic run |
| Revocation races active worker or outbound share | Local consent → execution/share | Generation check before dispatch and release; cancel queue, kill worker, invalidate pending share; atomic audit | A share already completed cannot be recalled |
| Scheduler burst after downtime or wall-clock jump | Timer → resource use | `Persistent=false`, skip missed slots, one run per slot, min interval, jitter, per-hour/day caps, suspend on backward clock | Missed observations recorded, never caught up in a burst |
| Package database symlink or changed file during read | Local FS → parser | Bounded reads, `O_NOFOLLOW`/descriptor stat and stable metadata check in implementation, private test fixtures, partial/unknown on race | Non-atomic external package updates may yield unknown |
| systemd or `/proc` output contains hostile text/large lines | OS read → result parser | Fixed property allowlist, byte/line/entry caps, strict state enum and no raw output persistence | Truncated/parse error produces unknown |
| Worker loops, forks, consumes memory or writes enormous output | Worker → host availability | One active job, cgroup group limits and wall watchdog; bounded concurrent stdout/stderr read; kill/reap whole group; no core dumps | Isolation unsupported means operation unavailable |
| Worker uses inherited credential, fd, writable path or network | Worker → other resources | Ordinary UID, no capabilities/new privileges, close inherited fds, fixed env/cwd, read-only view and operation-specific syscall/network restrictions; syscall-trace validation | Same-UID compromise remains in scope for further hardening, not claimed solved |
| Port check sees only a new private namespace and reports zero | Sandbox → observation validity | Pin intended namespace, do not use `PrivateNetwork` for port worker, report scope and unknown on mismatch | Namespace may differ in containers; no host-wide claim |
| UDP bound socket misreported as listening/reachable | OS data → interpretation | Name `udp_bound_count`; no reachability claim or probe | Firewall/route reachability remains unmeasured |
| Exact version, service name, port list or stable asset ID leaks through remote response/log | Result → network/log | Default local-only; separate share approval/destination; coarse redaction; metadata-only journal; no raw streams or hostname | Aggregate counts may still fingerprint; UI states disclosure |
| Diagnostic observation promoted to signed claim or protected write | Runner → Rapid/Trust/writer | Separate schemas, imports, credentials and process roles; result has no approval API; negative integration tests | Any future adapter requires separate authority review |
| Uninstall leaves active timer or stale consent | Package removal → background execution | Explicit stop/disable/revoke and owned-path cleanup; no post-remove execution; test interrupted cleanup | State on snapshots/SSD may persist; report leftovers |

## Security invariants

1. A remote proposal alone causes zero diagnostic subprocesses, local observations, writes outside its bounded inbox, outbound result sends or protected-writer calls. Its sender, signature and model confidence do not change this rule.
2. Only a current local authorization for exact request or schedule bytes can start a worker. Registry ID/version, arguments, install audience, policy generation and resource ceilings are checked every run. An unsupported or contradictory state denies.
3. Every operation is observational. It neither installs packages nor changes services, firewall, routes, sockets, kernel settings, Trust roots, Rapid decisions or targets. `check_listening_ports` reads local kernel tables and sends no packet.
4. No raw child output is a result. The result is schema-validated, bounded and privacy filtered. Failure is explicitly unknown/denied/limited, never silently represented as zero or healthy.
5. A revoked or expired grant cannot authorize a future dispatch or pending share. Durable replay and revocation floors survive normal restart. Corrupt or rolled-back state suspends automatic work.
6. Installation, enabling scheduling, approving remote suggestions, increasing detail and outbound sharing are separate local acts. Uninstall stops all runner-owned work and reports incomplete cleanup.

## Open security decisions for implementation review

- Demonstrate the actual unprivileged user-service sandbox on pinned Debian and Ubuntu. systemd warns that some namespacing controls may be unavailable in user managers; do not assume a hardening directive was applied merely because it parsed ([systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec)).
- Select a protected rollback marker and define its backup/restore behavior. A hash chain in the same writable directory detects ordinary corruption but cannot defeat a same-UID attacker who replaces the entire chain and head. Without a stronger anchor, restored state must require local re-enrollment.
- Determine whether the read-only systemd D-Bus adapter can be confined more tightly than a fixed `systemctl show` subprocess, and validate real bus access without granting control methods. `systemctl` supports both viewing and state-changing commands, so a fixed read-only call must be audited as exact argv, not treated as a general binary allowlist ([systemctl manual](https://www.freedesktop.org/software/systemd/man/latest/systemctl)).
- Prove that the port reader reports the intended namespace and bounds every selected table. `/proc/net` points to `/proc/self/net` and reflects the caller's network namespace ([Linux proc network manual](https://www.man7.org/linux/man-pages/man5/proc_pid_net.5.html)).
- Define an outbound sharing schema and destination allowlist in a later phase. No outbound implementation is authorized by this architecture.
