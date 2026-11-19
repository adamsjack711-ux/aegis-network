"""Measure ordinary, authorized traffic through disposable loopback services."""

import asyncio
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
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


def withdrawal_delivery(tmp_path, record_property, *, priority):
    async def run(docker_env, path):
        lab = Lab(SimpleNamespace(coordinators=1, sample_interval=0.5), path, docker_env)
        async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
            try:
                await lab.start_services(client)
                agent_id = str(uuid4())
                _, worker = lab.fleet.start(agent_id, 2)
                audit = path / agent_id / "audit.db"
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
                ordinary_state = await lab.js.stream_info(STREAM)
                stream_before = ordinary_state.state.last_seq
                if priority:
                    from aegis.mesh import CRITICAL_STREAM

                    critical_before = (await lab.js.stream_info(CRITICAL_STREAM)).state.last_seq
                    capped = (await lab.js.stream_info(STREAM)).config
                    capped.max_bytes = ordinary_state.state.bytes
                    assert capped.max_bytes > 0 and capped.discard == "new"
                    await lab.js.update_stream(capped)
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
                if priority:
                    held = await lab.js.stream_info(STREAM)
                    pending = await observe_until(
                        queue, lambda rows: any(row[1:] == (withdrawal_id, True) for row in rows),
                    )
                    critical = await lab.js.get_msg(CRITICAL_STREAM, seq=critical_before + 1)
                    critical_event = event_id(parse_event(critical.data))
                    record_property("priority_before_release", json.dumps({
                        "ordinary_before": stream_before,
                        "ordinary_held": held.state.last_seq,
                        "ordinary_max_bytes": held.config.max_bytes,
                        "ordinary_pending_ids": [eid for _, eid, sent in pending if not sent],
                        "critical_event_id": critical_event,
                        "observed_ms_from_restart": (time.monotonic_ns() - restart_ns) / 1_000_000,
                    }))
                    assert held.state.last_seq == stream_before and held.config.max_bytes == capped.max_bytes
                    assert {eid for _, eid, sent in pending if not sent} == set(ordinary)
                    assert critical_event == withdrawal_id
                    assert recovery_ms <= 5_000
                    release_ns = time.monotonic_ns()
                    await lab.js.update_stream(ordinary_state.config)

                await observe_until(queue, lambda rows: len(rows) == 6 and all(row[2] for row in rows))
                publication = []
                count = len(ordinary) if priority else len(ordinary) + 1
                for seq in range(stream_before + 1, stream_before + count + 1):
                    message = await lab.js.get_msg(STREAM, seq=seq)
                    publication.append((seq, event_id(parse_event(message.data))))
                record_property("broker_publication", json.dumps(publication))
                if priority:
                    assert {eid for _, eid in publication} == set(ordinary)

                    def ordinary_readback():
                        with closing(sqlite3.connect(f"{audit.resolve().as_uri()}?mode=ro", uri=True)) as db:
                            return db.execute("SELECT artifact_id, outcome FROM decisions").fetchall()

                    decisions = await observe_until(
                        ordinary_readback, lambda rows: set(ordinary) <= {eid for eid, _ in rows},
                    )
                    record_property("ordinary_after_release", json.dumps({
                        "decisions": decisions, "release_ms_from_restart": (release_ns - restart_ns) / 1_000_000,
                        "drain_ms_from_release": (time.monotonic_ns() - release_ns) / 1_000_000,
                    }))
                else:
                    assert {eid for _, eid in publication} == {*ordinary, withdrawal_id}
                    assert recovery_ms <= 5_000
                    assert publication[0][1] == withdrawal_id, "ordinary lab finding overtook a queued withdrawal"
            finally:
                await lab.stop()

    with TemporaryDirectory(prefix="broker-", dir=tmp_path) as scratch, local_docker() as docker_env:
        asyncio.run(run(docker_env, Path(scratch)))


@pytest.mark.skipif(os.getenv("AEGIS_PHASE4E_LIVE") != "1" or os.getenv("AEGIS_PHASE4E_PRIORITY") == "1",
                    reason="requires the legacy loopback single-stream profile")
def test_W01_W02_queued_withdrawal_after_broker_restart(tmp_path, record_property):
    withdrawal_delivery(tmp_path, record_property, priority=False)


@pytest.mark.skipif(os.getenv("AEGIS_PHASE4E_LIVE") != "1" or os.getenv("AEGIS_PHASE4E_PRIORITY") != "1",
                    reason="requires the Phase 4E loopback priority profile")
def test_W01_W02_critical_lane_progress_while_ordinary_stream_is_full(tmp_path, record_property):
    withdrawal_delivery(tmp_path, record_property, priority=True)
