"""Bench instrumentation and opt-in live process reliability acceptance."""

import argparse
import asyncio
from contextlib import closing
import importlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.agent_runtime import consume, durable_name
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.storage import SqliteAudit

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def harness(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("phase4a_bench")


def test_observers_follow_durable_commit_and_confirmed_ack(tmp_path, harness):
    key = Ed25519PrivateKey.generate()
    envelope = harness.finding(key, 1)
    identity = str(uuid4())
    path = tmp_path / "agent.sqlite"
    timeline = []

    class Finished(BaseException):
        pass

    class Message:
        data = envelope.model_dump_json().encode()

        async def ack_sync(self):
            # The reader sees the committed row through a separate connection.
            with closing(sqlite3.connect(path)) as reader:
                assert reader.execute("SELECT count(*) FROM decisions").fetchone() == (1,)
            timeline.append("broker_ack")

    async def run(audit):
        local = LocalAgent(
            LocalPolicy({"lab-publisher": key.public_key()}, frozenset({"observe-only"}), True),
            [InventoryItem("pkg:generic/aegis-demo", "1.0.0")], audit)
        message = Message()

        async def fetch(*args, **kwargs):
            if timeline[-1] == "confirmed":
                raise Finished
            return [message]

        async def subscribe(*args, **kwargs):
            assert kwargs["durable"] == durable_name(identity)
            return SimpleNamespace(fetch=fetch)

        async def stream_info(name):
            assert name == harness.STREAM

        async def fence():
            timeline.append("lease_check")

        async def before_message(incoming):
            assert incoming is message
            timeline.append("before_receive")

        def reconciled(count, start, end):
            assert count == 0 and start <= end
            timeline.append("reconciled")

        def confirmed(incoming, decision, received, leased, committed, acked):
            assert incoming is message
            assert decision.reason_code == "EXACT_MATCH_ALLOWED"
            assert received <= leased <= committed <= acked
            timeline.append("confirmed")

        transport = httpx.MockTransport(lambda _: httpx.Response(200, json={"head": 0, "events": []}))
        async with httpx.AsyncClient(base_url="http://127.0.0.1", transport=transport) as client:
            with pytest.raises(Finished):
                await consume(local, audit, SimpleNamespace(stream_info=stream_info, pull_subscribe=subscribe),
                              SimpleNamespace(lost=False, ensure=fence), SimpleNamespace(done=lambda: False),
                              client, durable_name(identity), on_reconcile=reconciled,
                              before_message=before_message, on_ack=confirmed)

    audit = SqliteAudit(path, identity)
    try:
        asyncio.run(run(audit))
    finally:
        audit.db.close()
    assert timeline == ["reconciled", "before_receive", "lease_check", "broker_ack", "confirmed"]


def test_trace_reader_only_advances_after_complete_record(tmp_path, harness):
    path = tmp_path / "trace.jsonl"
    trace = harness.Log(path)
    path.write_text('{"ns":1}\n{"ns":')
    assert trace.read() == [{"ns": 1}]
    assert trace.read() == []
    with path.open("a") as stream:
        stream.write("2}\n")
    assert trace.read() == [{"ns": 2}]
    assert trace.rows == [{"ns": 1}, {"ns": 2}]
    assert harness.observed({"ns": 3, "controller_observed_ns": 9}) == 9


def test_peer_proxy_uses_only_loopback_and_private_unix_socket(tmp_path, harness):
    peer = importlib.import_module("phase4a_peer")
    for invalid in ("example=0", "-oProxyCommand=1", "host name=5", "host=2;", "lab@8.8.8.8=5"):
        with pytest.raises(argparse.ArgumentTypeError):
            peer.peer_spec(invalid)
    assert peer.peer_spec("lab-user@192.168.77.20=5") == ("lab-user@192.168.77.20", 5)
    # macOS allows a limited length for Unix socket paths.
    short_path = Path("/tmp") / f"p4a-test-{uuid4().hex}.sock"

    async def echo(reader, writer):
        writer.write(await reader.readexactly(8))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def run():
        back = await asyncio.start_unix_server(echo, short_path)
        local = await peer.proxy("127.0.0.1", short_path)
        async with back, local:
            host, port = local.sockets[0].getsockname()
            assert host == "127.0.0.1"
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"lab-test")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(8), 2) == b"lab-test"
            assert await asyncio.wait_for(reader.read(), 2) == b""
            writer.close()
            await writer.wait_closed()

    try:
        asyncio.run(run())
    finally:
        short_path.unlink(missing_ok=True)


@pytest.mark.skipif(os.getenv("AEGIS_PHASE4A_LIVE") != "1",
                    reason="set AEGIS_PHASE4A_LIVE=1 to authorize disposable Docker and fault tests")
def test_live_distinct_processes_and_fault_recovery(tmp_path):
    raw = tmp_path / "result.json"
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/phase4a_bench.py"), "--authorize-local-lab",
         "--agents", "10", "--steady", "3", "--burst", "2", "--faults",
         "--protection", "1", "--directory", str(tmp_path), "--output", str(raw)],
        cwd=ROOT, env=os.environ | {"PYTHONPATH": str(ROOT / "src")}, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
    assert result.returncode == 0, result.stdout
    report = json.loads(raw.read_text())
    assert report["topology"]["agent_ids_started"] == 10
    first_pids = {next(row["pid"] for row in agent["trace"] if row["kind"] == "ready")
                  for agent in report["agent_traces"].values()}
    assert len(first_pids) == 10
    metrics = report["metrics"]
    assert metrics["confirmed_acks"] + 1 == metrics["observed_first_audit_commits"]
    assert metrics["audits"]["missed_revocations"] == metrics["audits"]["duplicate_logical_decisions"] == 0
    assert metrics["audits"]["incorrect_decisions"] == 0
    burst = report["scenarios"]["burst"]
    assert burst["paused_backlog"]["pending"] + burst["paused_backlog"]["ack_pending"] >= 8
    assert burst["drained_backlog"]["pending"] == burst["drained_backlog"]["ack_pending"] == 0
    faults = report["scenarios"]["faults"]
    assert faults["sigkill"]["old_pid"] != faults["sigkill"]["new_pid"]
    assert faults["journal_repair"]["pending_before_purge"] >= 1
    assert faults["broker_restart"]["outbox_pending_during_stop"] >= 1
    assert report["scenarios"]["capacity_backpressure"]["outbox_pending_during_limit"] >= 1
    fixture = report["scenarios"]["protection"]["runs"][0]["deployments"][0]
    assert fixture["status"] == "confirmed"
    assert fixture["marker_escapes"] == 0 and fixture["recovery"] == "safe_hold"
