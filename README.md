# Aegis Network

Lab-only proof of concept for independently verified, signed defensive findings and local dry-run decisions. The current slice has no enforcement path and makes no claims about response latency or compute savings.

## Current path

`POST /v1/findings` → Ed25519 validation → PostgreSQL plus transactional outbox → NATS JetStream → independent agent signature recheck → exact local inventory match → separate SQLite audits and dry-run decisions. `POST /v1/revocations` carries signed withdrawals to the same agents.

Read [architecture.md](architecture.md), [threat-model.md](threat-model.md), [docs/phase0.md](docs/phase0.md), [docs/contracts.md](docs/contracts.md), [docs/phase2c-integration.md](docs/phase2c-integration.md), [docs/phase2c-hardening.md](docs/phase2c-hardening.md), [docs/phase2c-risk-register.md](docs/phase2c-risk-register.md), [docs/acceptance.md](docs/acceptance.md), and [docs/roadmap.md](docs/roadmap.md).

## Local setup

Requires Python 3.12+. Install with `python -m pip install -e '.[test]'`, then run `pytest -q`. To run the containers, generate a lab key and configs with `python scripts/setup_lab.py`, set `AEGIS_DB_PASSWORD` in `.env`, and run `docker compose up --build`. The coordinator is bound to `127.0.0.1:8000`; Postgres and NATS have no host ports. The setup script creates a fresh sample signed finding in `lab-config/finding.json` and reuses the lab key on subsequent runs. Submit it with `curl -H 'content-type: application/json' --data-binary @lab-config/finding.json http://127.0.0.1:8000/v1/findings`. Inspect both agents' JSON decisions in `docker compose logs agent agent_b`.

The sample inventory represents a simulated lab package. The sample private key and configuration are ignored by Git. Use only the generated lab key for this demo. No application or host policy is changed.
