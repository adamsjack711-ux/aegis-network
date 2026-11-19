"""Measure ordinary, authorized traffic through disposable loopback services."""

import asyncio
from contextlib import closing
import json
import os
import sqlite3
import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import psycopg
import pytest

from aegis.artifact import event_id, parse_event
from phase4a_bench import Lab, STREAM, local_docker, revocation


def agent_readback(path, finding, withdrawal=None):
    if not path.exists():
        return None, None
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        initial = db.execute("SELECT outcome, authenticated FROM decisions WHERE artifact_id = ?",
                             (finding,)).fetchone()
        denial = db.execute(
            "SELECT rd.outcome, rd.authenticated, rt.revocation_id FROM decisions AS d "
            "JOIN revoked_targets AS rt ON rt.artifact_id = d.artifact_id AND rt.digest = d.digest "
            "AND rt.target_publisher_id = d.publisher_id "
            "JOIN revocation_decisions AS rd ON rd.event_id = rt.revocation_id "
            "WHERE d.artifact_id = ? AND rd.event_id = ?", (finding, withdrawal),
        ).fetchone()
    return initial, denial


async def observe_until(read, ready, timeout=15):
    async with asyncio.timeout(timeout):
        while True:
            value = await asyncio.to_thread(read)
            if ready(value):
                return value
            await asyncio.sleep(0.025)


@pytest.mark.skipif(os.getenv("AEGIS_PHASE4E_LIVE") != "1", reason="requires isolated local Docker")
def test_W01_W02_queued_withdrawal_after_broker_restart(tmp_path, record_property):
    async def run(docker_env):
        lab = Lab(SimpleNamespace(coordinators=1, sample_interval=0.5), tmp_path, docker_env)
        async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
            try:
                await lab.start_services(client)
                agent_id = str(uuid4())
                _, worker = lab.fleet.start(agent_id, 2)
                audit = tmp_path / agent_id / "audit.db"
                await observe_until(worker.read, lambda rows: any(row["kind"] == "ready" for row in rows))

                async def submit(event):
                    route = "/v1/findings" if event.kind == "finding" else "/v1/revocations"
                    url = f"http://127.0.0.1:{lab.coordinator_ports[0]}{route}"
                    response = await client.post(url, content=event.model_dump_json(),
                                                 headers={"Content-Type": "application/json"})
                    assert response.status_code in (200, 201, 202)
                    return event_id(event)

                def queue():
                    with psycopg.connect(lab.dsn) as db:
                        db.execute("SET TRANSACTION READ ONLY")
                        return db.execute("SELECT j.position, o.event_id::text, o.sent_at IS NOT NULL "
                                          "FROM mesh_outbox o JOIN mesh_journal j USING(event_id) "
                                          "ORDER BY j.position").fetchall()

                finding = lab.make_finding(lab.publishers[0], 1)
                finding_id = await submit(finding)
                await observe_until(lambda: agent_readback(audit, finding_id),
                                    lambda rows: rows[0] == ("allow_dry_run", 1))
                await observe_until(queue, lambda rows: rows == [(1, finding_id, True)])
                stream_before = (await lab.js.stream_info(STREAM)).state.last_seq
                await asyncio.to_thread(lab.compose, "stop", "-t", "0", "nats")
                ordinary = [await submit(lab.make_finding(lab.publishers[0], seq)) for seq in range(2, 6)]
                withdrawal_id = await submit(revocation(lab.revoker, finding, 1))
                backlog = await asyncio.to_thread(queue)
                record_property("queued_before_restart", json.dumps(backlog))
                assert backlog == [(1, finding_id, True)] + [
                    (i, eid, False) for i, eid in enumerate([*ordinary, withdrawal_id], start=2)
                ]
                record_property("docker_images", json.dumps(lab.images))

                # The restart request precedes connectivity restoration, so this
                # duration is a conservative upper bound for recovery-to-denial.
                restart_ns = time.monotonic_ns()
                started = asyncio.create_task(asyncio.to_thread(lab.compose, "start", "nats"))
                try:
                    _, denial = await observe_until(lambda: agent_readback(audit, finding_id, withdrawal_id),
                                                    lambda rows: rows[1] is not None)
                    recovery_ms = (time.monotonic_ns() - restart_ns) / 1_000_000
                finally:
                    await started
                record_property("durable_denial", json.dumps({"row": denial, "recovery_upper_ms": recovery_ms}))
                assert denial == ("revoked_dry_run", 1, withdrawal_id)
                await observe_until(queue, lambda rows: len(rows) == 6 and all(row[2] for row in rows))
                publication = []
                for seq in range(stream_before + 1, stream_before + 6):
                    message = await lab.js.get_msg(STREAM, seq=seq)
                    publication.append((seq, event_id(parse_event(message.data))))
                record_property("broker_publication", json.dumps(publication))
                assert {eid for _, eid in publication} == {*ordinary, withdrawal_id}
                assert recovery_ms <= 5_000
                assert publication[0][1] == withdrawal_id, "ordinary lab finding overtook a queued withdrawal"
            finally:
                await lab.stop()

    with local_docker() as docker_env:
        asyncio.run(run(docker_env))
