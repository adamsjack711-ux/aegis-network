# Project status — 2026-11-19, Phase 2A worktree

Phase 2A is in the isolated `/Users/jackadams-lovell/aegis-mesh` worktree on `feat/mesh-reliability`, based on commit `14440ee`. The canonical checkout is `/Users/jackadams-lovell/aegis-network` on `master`. Phase 2A changes are local and have not been merged.

Phase 0 reuse assessment and Phase 1 architecture, threat model, decisions, contracts, acceptance criteria, and roadmap are documented. The signed-finding to audited dry-run slice and Phase 2A mesh reliability changes are implemented. Two agents have independent durable consumers and audit volumes. Findings and signed revocations use stable event IDs, a transactional PostgreSQL outbox, JetStream acknowledgements, and local deduplication. No enforcement, vulnerable lab apps, verification workers, rollback, benchmarks, or LLM investigator have been implemented.

Baseline verification on 2026-11-19:

- Python 3.15 local environment: `pytest -q` passed 8 tests. One third-party Starlette/httpx deprecation warning.
- Python bytecode compilation passed; Compose config parsed.
- Docker Compose with PostgreSQL 16 and NATS 2.10 built and ran. Synthetic signed finding `87bae51f-d743-49e9-ac86-575d8d4c74cd` returned HTTP 202 with `accepted: true`; duplicate returned `accepted: false`. PostgreSQL contained one finding and one sent outbox row. The local agent printed `allow_dry_run` and its SQLite audit contained one decision.
- Temporary Compose containers were stopped with `docker compose down`; named lab volumes remain for inspection or reuse.

These results show the path works for one synthetic lab finding. They do not demonstrate 30-second mitigation, 10x compute savings, safe enforcement, or resilience to a compromised coordinator in a deployed system.

Phase 2A verification on 2026-11-19: 16 local tests passed, including broker and audit failure injection, replay, independent agent recovery, invalid signatures, role checks, and revocation ordering. An isolated local Compose project showed two agents receiving a synthetic finding, an outbox row remaining pending during a broker outage, both agents catching up after broker and agent restart, and both receiving a signed revocation. Duplicate HTTP submissions returned `accepted: false`. See [integration review](docs/phase2a-integration.md) for exact commands, shared interface changes, and remaining limits.

Next: review the changed mesh contracts with the Rapid owner, then specify independent verifier attestations before adding any executor. Preserve the local policy boundary and never enable production actions from this proof of concept.
