"""Matched Phase 4D/4E experiments against private loopback PostgreSQL and JetStream."""

import argparse
import asyncio
from contextlib import closing, suppress
import json
import logging
import os
from pathlib import Path
import platform
import signal
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import httpx
import psycopg
from nats.js.api import DiscardPolicy

import phase4a_bench as harness
from aegis.artifact import event_id
from aegis.mesh import CRITICAL_STREAM, STREAM
from aegis.postgres import AdmissionFull, OUTBOX_LIMITS, PostgresRepository
from phase2c_live import revocation


ROOT = Path(__file__).resolve().parents[1]
BASELINE = "ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f"
OBSERVATION_POLL = 0.025
METRICS = (
    "intake_to_local_denial_ms", "intake_to_ack_ms", "intake_to_report_ms",
    "crash_to_local_denial_ms", "crash_to_ready_ms", "crash_to_ack_ms", "backlog_drain_ms",
    "worker_cpu_ms", "worker_peak_rss_bytes", "coordinator_cpu_ms", "coordinator_peak_rss_bytes",
)


def read_denial(path, withdrawal):
    rev = withdrawal.revocation
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.05)) as db:
        count, = db.execute(
            "SELECT count(*) FROM revocation_decisions WHERE event_id=? AND authenticated=1 "
            "AND outcome='revoked_dry_run'",
            (str(rev.revocation_id),),
        ).fetchone()
        denied = db.execute(
            "SELECT 1 FROM revoked_targets WHERE target_publisher_id=? AND artifact_id=? AND digest=?",
            (rev.target_publisher_id, str(rev.target_artifact_id), rev.target_sha256),
        ).fetchone()
    return bool(denied), count


async def observe_denial(lab, agent_id, withdrawal):
    audit = lab.path / agent_id / "audit.db"
    async with asyncio.timeout(50):
        while True:
            try:
                denied, count = await asyncio.to_thread(read_denial, audit, withdrawal)
                if denied and count == 1:
                    detected = harness.now()
                    # This is the external benchmark report milestone. ACK coverage
                    # is read separately from the worker's post-confirmation trace.
                    print(json.dumps({"status": "local-denial-observed", "agent_id": agent_id,
                                      "event_id": event_id(withdrawal)}), flush=True)
                    return detected, harness.now()
            except sqlite3.OperationalError:
                pass
            await asyncio.sleep(OBSERVATION_POLL)


async def ready(lab, log):
    await lab.wait(lambda: any(row["kind"] == "ready" for row in log.rows), "worker ready")


async def burst(lab, client, count, delay, priority):
    ident = str(uuid4())
    _, log = lab.fleet.start(ident, 2, delay=delay)
    await ready(lab, log)
    target = lab.make_finding(lab.publishers[0], 1)
    await lab.wait_acks([await lab.post(client, target, "target")])

    await asyncio.to_thread(lab.compose, "stop", "-t", "0", "nats")
    async def submit_publisher(index):
        return [await lab.post(client, lab.make_finding(lab.publishers[index], 2 + i), "ordinary")
                for i in range(index, count, len(lab.publishers))]

    groups = await asyncio.gather(*(submit_publisher(i) for i in range(len(lab.publishers))))
    ordinary = [eid for group in groups for eid in group]
    withdrawal = revocation(lab.revoker, target, 1)
    observer = asyncio.create_task(observe_denial(lab, ident, withdrawal))
    try:
        eid = await lab.post(client, withdrawal, "withdrawal-restart")
        pending = await asyncio.to_thread(lab.outbox_rows)
        unsent = {row["event_id"] for row in pending if row["sent_at"] is None}
        assert set(ordinary) | {eid} <= unsent
        # Keep the broker unavailable through at least one dispatcher attempt.
        await asyncio.sleep(0.55)
        restored = harness.now()
        await asyncio.to_thread(lab.compose, "start", "nats")
        await lab.wait_acks([eid], timeout=50)
        denied, reported = await observer
        await lab.wait_acks(ordinary, timeout=90)
    finally:
        observer.cancel()
        await asyncio.gather(observer, return_exceptions=True)

    first = lab.fleet.acks[eid][ident]
    ordinary_acks = [lab.fleet.acks[item][ident] for item in ordinary]
    drained = max(row["acked"] for row in ordinary_acks)
    ordinary_broker = await lab.js.consumer_info(STREAM, f"aegis-{ident}")
    critical = await lab.js.stream_info(CRITICAL_STREAM) if priority else None
    assert ordinary_broker.num_pending == ordinary_broker.num_ack_pending == 0
    assert read_denial(lab.path / ident / "audit.db", withdrawal) == (True, 1)
    if priority:
        assert first["lane"] == "withdrawal"
        assert first["acked"] < drained
        assert critical.state.messages == 1
    else:
        assert first["sequence"] > max(row["sequence"] for row in ordinary_acks)
    ack_order = sum(row["acked"] < first["acked"] for row in ordinary_acks)
    intake = lab.events[eid]["start"]
    return {
        "event_id": eid, "agent_id": ident, "outbox_unsent_at_cut": len(unsent),
        "ordinary_acked_before_withdrawal": ack_order,
        "intake_to_http_accept_ms": harness.ms(intake, lab.events[eid]["http_end"]),
        "intake_to_worker_receipt_ms": harness.ms(intake, first["received"]),
        "intake_to_local_denial_ms": harness.ms(intake, denied),
        "intake_to_ack_ms": harness.ms(intake, first["acked"]),
        "intake_to_report_ms": harness.ms(intake, reported),
        "backlog_drain_ms": harness.ms(restored, drained),
        "clock_ns": {"intake": intake, "denied": denied, "reported": reported,
                     "received": first["received"], "acked": first["acked"], "drained": drained,
                     "restart_requested": restored},
        "withdrawal_ack": first,
        "ordinary_pending_at_end": ordinary_broker.num_pending,
        "ordinary_ack_pending_at_end": ordinary_broker.num_ack_pending,
        "critical_messages_at_end": critical.state.messages if critical else None,
    }


class BrokerLink:
    """A private TCP proxy with an independently switchable link for one worker."""

    def __init__(self, broker_port):
        self.broker_port = broker_port
        self.open = True
        self.clients = set()

    def partition(self):
        self.open = False
        for writer in self.clients:
            writer.close()

    async def connect(self, reader, writer):
        self.clients.add(writer)
        upstream = None

        async def forward(source, target):
            while data := await source.read(65_536):
                target.write(data)
                await target.drain()

        try:
            if not self.open:
                return
            broker, upstream = await asyncio.open_connection("127.0.0.1", self.broker_port)
            tasks = (asyncio.create_task(forward(reader, upstream)),
                     asyncio.create_task(forward(broker, writer)))
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self.clients.remove(writer)
            writer.close()
            if upstream is not None:
                upstream.close()
                with suppress(OSError):
                    await upstream.wait_closed()
            with suppress(OSError):
                await writer.wait_closed()


async def partition_and_pressure(lab, client):
    # Try bootstrapping an incompatible coordinator over the shared live repository.
    try:
        await asyncio.to_thread(PostgresRepository, lab.dsn, priority=False)
    except ValueError as exc:
        assert "pinned Mesh delivery profile" in str(exc)
    else:
        raise AssertionError("mixed-profile coordinator was admitted")

    # An active canonical reader would block an ALTER or other exclusive DDL.
    # A second coordinator on the pinned profile must avoid DDL altogether.
    with psycopg.connect(lab.dsn) as held:
        held.execute("LOCK TABLE mesh_journal IN ACCESS SHARE MODE")
        repo = await asyncio.wait_for(
            asyncio.to_thread(PostgresRepository, lab.dsn, priority=True), timeout=5,
        )

    link = BrokerLink(lab.broker_port)
    async with await asyncio.start_server(link.connect, "127.0.0.1", 0) as proxy:
        ident = str(uuid4())
        port = lab.broker_port
        try:
            lab.broker_port = proxy.sockets[0].getsockname()[1]
            _, log = lab.fleet.start(ident, 2)
        finally:
            lab.broker_port = port
        await ready(lab, log)
        target = lab.make_finding(lab.publishers[0], 1)
        await lab.wait_acks([await lab.post(client, target, "target")])

        limited = (await lab.js.stream_info(STREAM)).config
        old_limit = limited.max_bytes
        limited.max_bytes = 1
        assert limited.discard == DiscardPolicy.NEW
        await lab.js.update_stream(limited)
        ordinary = await lab.post(client, lab.make_finding(lab.publishers[0], 2), "full-ordinary-stream")
        refused = lab.make_finding(lab.publishers[0], 3)
        with patch.dict(OUTBOX_LIMITS, finding=1):
            try:
                await asyncio.to_thread(repo.add, refused)
            except AdmissionFull:
                pass
            else:
                raise AssertionError("full ordinary outbox admitted another finding")
        pending = await asyncio.to_thread(lab.outbox_rows)
        assert all(row["event_id"] != event_id(refused) for row in pending)
        with psycopg.connect(lab.dsn) as db:
            assert db.execute("SELECT 1 FROM mesh_events WHERE event_id=%s",
                              (event_id(refused),)).fetchone() is None

        link.partition()
        await lab.wait(lambda: any(row["kind"] == "disconnected" for row in log.rows), "worker link cut")
        withdrawal = revocation(lab.revoker, target, 1)
        observer = asyncio.create_task(observe_denial(lab, ident, withdrawal))
        try:
            eid = await lab.post(client, withdrawal, "partition-and-pressure")

            async with asyncio.timeout(10):
                while (await lab.js.stream_info(CRITICAL_STREAM)).state.messages != 1:
                    await asyncio.sleep(0.05)
            assert read_denial(lab.path / ident / "audit.db", withdrawal) == (False, 0)
            assert ident not in lab.fleet.acks[eid]
            rejoined = harness.now()
            link.open = True
            await lab.wait_acks([eid])
            denied, reported = await observer
            pending = await asyncio.to_thread(lab.outbox_rows)
            assert any(row["event_id"] == ordinary and row["sent_at"] is None for row in pending)
            limited.max_bytes = old_limit
            await lab.js.update_stream(limited)
            await lab.wait_acks([ordinary])
        finally:
            link.partition()
            observer.cancel()
            await asyncio.gather(observer, return_exceptions=True)
    intake = lab.events[eid]["start"]
    ack = lab.fleet.acks[eid][ident]
    assert read_denial(lab.path / ident / "audit.db", withdrawal) == (True, 1)
    return {
        "event_id": eid, "agent_id": ident, "mixed_profile_rejected": True,
        "same_profile_started_during_journal_read_lock": True, "ordinary_admission_rejection_atomic": True,
        "clock_ns": {"rejoined": rejoined, "intake": intake, "denied": denied,
                     "reported": reported, "received": ack["received"], "acked": ack["acked"]},
        "intake_to_local_denial_ms": harness.ms(intake, denied),
        "intake_to_ack_ms": harness.ms(intake, ack["acked"]),
        "intake_to_report_ms": harness.ms(intake, reported),
        "ordinary_still_unsent_at_withdrawal_ack": True,
        "withdrawal_ack": ack,
    }


async def crash(lab, client):
    before, after = (str(uuid4()) for _ in range(2))
    before_proc, before_log = lab.fleet.start(before, 2)
    folder = lab.path / after
    folder.mkdir()
    after_log = harness.Log(folder / "trace.jsonl")
    after_proc = lab.spawn(
        sys.executable, ROOT / "scripts/phase4a_worker.py", "--id", after,
        "--broker-port", lab.broker_port, "--coordinator-port", lab.coordinator_ports[0],
        "--config", lab.configs[2], "--audit", folder / "audit.db",
        "--stop-before-withdrawal-ack", log=after_log,
    )
    lab.fleet.agents[after] = 2, after_log
    lab.fleet.processes[after] = after_proc
    lab.fleet.paused.add(after)  # Cleanup must resume the deterministic SIGSTOP barrier.
    await ready(lab, before_log)
    await ready(lab, after_log)
    target = lab.make_finding(lab.publishers[0], 1)
    await lab.wait_acks([await lab.post(client, target, "target")])

    withdrawal = revocation(lab.revoker, target, 1)
    before_cut = harness.now()
    before_proc.kill()
    await asyncio.to_thread(before_proc.wait, 5)
    lab.fleet.start(before, 2)
    tasks = [asyncio.create_task(observe_denial(lab, identity, withdrawal)) for identity in (before, after)]
    try:
        eid = await lab.post(client, withdrawal, "withdrawal-sigkill")
        await lab.wait(lambda: any(row["kind"] == "withdrawal_commit" for row in after_log.rows),
                       "crash after audit, before ACK")
        assert read_denial(lab.path / after / "audit.db", withdrawal) == (True, 1)
        assert read_denial(lab.path / before / "audit.db", withdrawal) == (False, 0)
        assert after not in lab.fleet.acks[eid] and before not in lab.fleet.acks[eid]
        after_cut = harness.now()
        after_proc.kill()
        await asyncio.to_thread(after_proc.wait, 5)
        lab.fleet.paused.remove(after)
        lab.fleet.start(after, 2)
        await lab.wait_acks([eid], timeout=50)
        observations = await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    rows = []
    intake = lab.events[eid]["start"]
    for i, (identity, log, cut) in enumerate(((before, before_log, before_cut), (after, after_log, after_cut))):
        observed, reported = observations[i]
        ack = lab.fleet.acks[eid][identity]
        restarted, = [row for row in log.rows if row["kind"] == "ready" and row["ns"] > cut]
        assert read_denial(lab.path / identity / "audit.db", withdrawal) == (True, 1)
        rows.append({
            "fault": "before-audit" if not i else "after-audit-before-ack",
            "event_id": eid, "agent_id": identity, "ack_delivery": ack["delivery"],
            "intake_to_local_denial_ms": harness.ms(intake, observed),
            "intake_to_ack_ms": harness.ms(intake, ack["acked"]),
            "intake_to_report_ms": harness.ms(intake, reported),
            "crash_to_local_denial_ms": harness.ms(cut, max(observed, cut)) if not i else 0,
            "crash_to_ready_ms": harness.ms(cut, restarted["ns"]),
            "crash_to_ack_ms": harness.ms(cut, ack["acked"]),
            "clock_ns": {"crash": cut, "intake": intake, "denied": observed,
                         "reported": reported, "acked": ack["acked"], "ready": restarted["ns"]},
        })
    return rows


async def run(arm, args, run_number):
    priority = arm != "control"
    harness.ROOT = ROOT if priority else args.control_root
    os.environ["AEGIS_PHASE4E_PRIORITY"] = "1" if priority else "0"
    local = SimpleNamespace(coordinators=2, timeout=50, sample_interval=1.0, ssh_peer=[])
    with tempfile.TemporaryDirectory(prefix="aegis-4e-") as scratch, harness.local_docker() as docker_env:
        lab = harness.Lab(local, Path(scratch), docker_env)
        async with httpx.AsyncClient(trust_env=False, timeout=10) as client:
            try:
                await lab.start_services(client)
                if arm == "crash":
                    rows = await crash(lab, client)
                    row = {"faults": rows}
                elif arm == "partition":
                    row = await partition_and_pressure(lab, client)
                else:
                    row = await burst(lab, client, args.findings, args.delay_ms / 1000, priority)
            except Exception:
                for path in sorted(lab.path.glob("**/*.stderr")):
                    print(f"{path.name} {path.read_text()[-3500:]}", file=sys.stderr)
                raise
            finally:
                await lab.stop()
            if lab.failures:
                raise RuntimeError(lab.failures)
        row.update(arm=arm, trial=run_number, images=lab.images, docker=lab.docker_version)
        worker = [item for _, log in lab.fleet.agents.values() for item in log.read() if item["kind"] == "exit"]
        coordinators = [item for log in lab.coordinator_logs for item in log.read()
                        if item.get("stage") == "shutdown"]
        if worker and coordinators:
            row.update(worker_cpu_ms=sum(item["cpu_s"] for item in worker) * 1000,
                       worker_peak_rss_bytes=max(item["peak_rss_bytes"] for item in worker),
                       coordinator_cpu_ms=sum(item["cpu_s"] for item in coordinators) * 1000,
                       coordinator_peak_rss_bytes=max(item["peak_rss_bytes"] for item in coordinators))
        return row


async def main(args):
    if not (args.crash_only or args.partition_only):
        actual = harness.command("git", "rev-parse", "HEAD", cwd=args.control_root)
        if actual != BASELINE or harness.command("git", "status", "--porcelain", cwd=args.control_root):
            raise ValueError("control must be a clean checkout at the approved Phase 4D baseline")
    raw = []
    try:
        if not (args.crash_only or args.partition_only):
            for n in range(1, args.repeats + 1):
                arms = ("control", "priority") if n % 2 else ("priority", "control")
                for arm in arms:
                    print(f"Phase 4E trial {n} {arm}", flush=True)
                    raw.append(await run(arm, args, n))
        if args.crash or args.crash_only:
            raw.append(await run("crash", args, 1))
        if args.partition_only:
            raw.append(await run("partition", args, 1))
    finally:
        summaries = {}
        for arm in ("control", "priority", "crash", "partition"):
            rows = [row for row in raw if row["arm"] == arm]
            observations = [item for row in rows for item in row.get("faults", [row])]
            if rows:
                summaries[arm] = {metric: harness.distribution([item[metric] for item in
                                  (rows if "_cpu_" in metric or "_rss_" in metric else observations)
                                  if metric in item]) for metric in METRICS}
        control = [row for row in raw if row["arm"] == "control"]
        priority = [row for row in raw if row["arm"] == "priority"]
        overhead = {metric: harness.distribution([new[metric] - old[metric] for old, new in
                    zip(control, priority) if metric in new and metric in old]) for metric in METRICS[-4:]}
        report = {
            "schema_version": "1.0", "baseline": BASELINE, "platform": platform.platform(),
            "python": platform.python_version(), "signaling": "disposable local POSIX processes",
            "observer_poll_ms": OBSERVATION_POLL * 1000, "findings": args.findings,
            "slow_consumer_delay_ms": args.delay_ms, "sample_summary": summaries,
            "priority_minus_control": overhead, "trials": raw,
        }
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-local-lab", action="store_true")
    parser.add_argument("--control-root", type=Path, default=ROOT.parent / "phase4d")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--findings", type=int, default=1000)
    parser.add_argument("--delay-ms", type=float, default=3)
    parser.add_argument("--crash", action="store_true")
    faults = parser.add_mutually_exclusive_group()
    faults.add_argument("--crash-only", action="store_true")
    faults.add_argument("--partition-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if not arguments.authorize_local_lab or not 1 <= arguments.repeats <= 20:
        parser.error("authorize the disposable loopback lab and use 1–20 paired repeats")
    if not 1 <= arguments.findings <= 2048 or not 0 <= arguments.delay_ms <= 10:
        parser.error("use 1–2048 findings and 0–10 ms slow-consumer delay")
    logging.getLogger("nats.aio.client").setLevel(logging.CRITICAL)
    asyncio.run(main(arguments))
