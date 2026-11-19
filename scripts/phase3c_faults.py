"""Check live scoped withdrawal and broker loss in the Phase 3C Compose lab."""

import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
import time

import httpx
import nats
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phase2c_live import revocation
from phase3c_lab import episode


def compose(*operation):
    subprocess.run(["docker", "compose", "-p", "aegis_phase3c",
                    "-f", "compose.yaml", "-f", "compose.hardening.yaml",
                    *operation], check=True)


async def main(args):
    nc = await nats.connect("nats://127.0.0.1:14222", connect_timeout=2)
    results = {}
    revoker = Ed25519PrivateKey.from_private_bytes(Path("lab-config/revoker.key").read_bytes())
    try:
        async with httpx.AsyncClient(base_url="http://127.0.0.1:18080",
                                    trust_env=False, timeout=5) as client:
            async def after_confirmed(defense, plan, fault):
                start = time.monotonic_ns()
                if fault == "signed_mesh_revocation":
                    target = defense.gate.envelope
                    withdrawal = revocation(revoker, target, time.time_ns() // 1000)
                    response = await client.post("/v1/revocations", json=withdrawal.model_dump(mode="json"))
                    response.raise_for_status()
                    assert response.json()["accepted"]
                try:
                    if fault == "broker_loss":
                        await asyncio.to_thread(compose, "stop", "nats")
                    async with asyncio.timeout(5):
                        status = await defense.monitor(plan)
                    assert status == "safe_hold"
                    elapsed = (time.monotonic_ns() - start) / 1e6
                    _, states = defense.lab.store.inventory()
                    fences = tuple((target, states[target].fence) for target in plan.targets)
                    observed = await asyncio.to_thread(defense.lab.observer.observe, "quarantined", fences)
                    if fault == "signed_mesh_revocation":
                        key = str(defense.gate.envelope.finding.artifact_id)
                        assert defense.gate.receiver.agent.audit.get(key).reason_code == "FINDING_REVOKED"
                    assert not any(state.mode != "quarantined" for state in states.values())
                    results[fault] = {"safe_hold_ms": elapsed, "probes": observed.requests,
                                      "status": status, "marker_escapes": 0}
                finally:
                    if fault == "broker_loss":
                        await asyncio.to_thread(compose, "start", "nats")
                        async with asyncio.timeout(15):
                            while not nc.is_connected:
                                await asyncio.sleep(.1)

            for fault in ("signed_mesh_revocation", "broker_loss"):
                async def probe(defense, plan):
                    await after_confirmed(defense, plan, fault)

                path = Path(tempfile.mkdtemp(prefix=fault + "-", dir=args.directory))
                await episode(args, nc.jetstream(), client, path, 3, 1, after_confirmed=probe)
    finally:
        await nc.close()
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.scripted_approval = True
    args.lease_ms = 10_000
    asyncio.run(main(args))
