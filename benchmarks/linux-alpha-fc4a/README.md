# Linux CLI alpha validation — NO-GO

Candidate aegis-network 0.1.0 at fc4a17bc6f9f0c289a645c4fb7006c999ba90e99. The adjacent frozen-plan.md was copied from the candidate before testing. The SHA-256 of git archive --format=tar for this pin is f5788032c2322be8c83b6e03159f5cfc70d8ca9d9f51556fcf8177bebcbb44ee. The release wheel and sdist have no available digest. No package was built or changed.

Run from the dedicated worktree. The following preflight exited 2 before building or installing. Use a fresh output directory on replay.

    python3 scripts/alpha_linux_release.py fc4a17bc6f9f0c289a645c4fb7006c999ba90e99 /private/tmp/aegis-alpha-reviewed-wheelhouse benchmarks/linux-alpha-fc4a/preflight
    python3 benchmarks/linux-alpha-fc4a/probe.py

The designated wheelhouse was absent. A local filename search under .worktrees and /private/tmp found no Aegis provenance.json for a replacement supply. No offline dependency was consumed. Origins, exact versions, archive digests, licenses and custody are unresolved for the build backend and its dependencies and the direct/transitive runtime closure listed in ../phase5b-release-acceptance/prerequisites.json. Obtain the reviewed original archives with their independently reviewed manifest, including Hatchling 1.33.0 and compatible cryptography and pydantic-core wheels. Then reproduce both wheel and sdist twice.

| Cell | Environment observation | Wheel SHA-256 | Installation / console / trace | Decision |
|---|---|---|---|---|
| Debian 13 / 3.12 | Fresh non-root container, 3.12.16 | unavailable | blocked / unrun / none | BLOCKED |
| Debian 13 / 3.13 | Fresh non-root container, 3.13.18 | unavailable | blocked / unrun / none | BLOCKED |
| Ubuntu 24.04 / 3.12 | Fresh non-root container, 3.12.3 | unavailable | blocked / unrun / none | BLOCKED |
| Ubuntu 24.04 / 3.13 | No reviewed image ID supplied | unavailable | blocked / unrun / none | BLOCKED |

cells.json records commands, immutable image IDs and exit codes for the independent environment probes. No probe located strace on PATH. Supply a reviewed Ubuntu/Python 3.13 image and an independent tracer for all four cells. No validation grants were issued, held or used during preflight. For installed testing record the disposable issuer, custodian, consumer and effective file/ancestor permissions and ACLs without recording grant secrets.

After provisioning, run all four fresh non-root installs, invoke the generated CLI outside checkout and uninstall. Outstanding totals are 0/2 build rounds, 0/4 installs and uninstalls, 0/84 console checks, 0/68 resource/privacy children and zero installed traces. Verify the 100,000 exact output rows, hard 256 MiB ceiling, wall and CPU limits, output size, attempted effects, explicit state opt-in, signature checks and unknown independent Evidence behavior against frozen-plan.md. No installation failed at runtime because none reached installation.
