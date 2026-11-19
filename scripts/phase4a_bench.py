"""Measure independent Aegis agents in a disposable, explicitly authorized lab."""

import argparse
import asyncio
from collections import Counter, defaultdict
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
import gzip
import hashlib
from importlib.metadata import version
import json
import math
import os
from pathlib import Path
import platform
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

import httpx
import nats
import psycopg

from aegis.agent_runtime import durable_name
from aegis.artifact import canonical_bytes, event_id, event_payload, sign
from aegis.mesh import STREAM, SUBJECT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phase2c_live import finding, revocation
from phase4a_peer import Peer, peer_spec

ROOT = Path(__file__).resolve().parents[1]
NS_PER_MS = 1_000_000
MIB = 1024 * 1024
REVOCATION_BUDGET_MS = 5_000  # Reporting threshold, not an enforcement deadline.


def now():
    return time.perf_counter_ns()


def ms(start, end):
    return round((end - start) / NS_PER_MS, 3)


def observed(row, timestamp="ns"):
    return row["controller_observed_ns"] if "controller_observed_ns" in row else row[timestamp]


def distribution(values):
    if not values:
        return None
    ordered = sorted(values)
    result = {"n": len(ordered), "max": round(ordered[-1], 3)}
    for label, fraction in [("p50", 0.5), ("p95", 0.95), ("p99", 0.99)]:
        offset = (len(values) - 1) * fraction
        lo = math.floor(offset)
        hi = math.ceil(offset)
        result[label] = round(ordered[lo] + (ordered[hi] - ordered[lo]) * (offset - lo), 3)
    return result


def python_env():
    return os.environ | {"PYTHONPATH": os.pathsep.join(map(str, [ROOT / "src", ROOT / "scripts"]))}


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=90, **kwargs).stdout.strip()


@contextmanager
def local_docker():
    # Do not provision or mutate a remote Docker context.
    endpoint = os.getenv("DOCKER_HOST") or command("docker", "context", "inspect", "--format",
                                                 "{{.Endpoints.docker.Host}}")
    if not endpoint.startswith(("unix://", "npipe://")):
        raise ValueError("Phase 4A requires a local Docker socket")
    env = os.environ.copy()
    env.pop("DOCKER_CONTEXT", None)
    env["DOCKER_HOST"] = endpoint
    yield env


class Log:
    """Read appended JSON records without accepting an incomplete final line."""

    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.rows = []

    def read(self):
        if not self.path.exists():
            return []
        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            data = stream.read()
        stop = data.rfind(b"\n") + 1
        self.offset += stop
        rows = [json.loads(line) for line in data[:stop].splitlines()]
        self.rows.extend(rows)
        return rows


class Fleet:
    def __init__(self, lab):
        self.lab = lab
        self.agents = {}
        self.processes = {}
        self.paused = set()
        self.acks = defaultdict(dict)
        self.commits = defaultdict(dict)

    def start(self, agent_id, index, *, delay=0, claim_timeout=45, probe=False):
        lab = self.lab
        folder = lab.path / ("probe" if probe else agent_id)
        folder.mkdir(exist_ok=True)
        log = Log(folder / "trace.jsonl")
        hosts = lab.coordinator_ports
        if peer := lab.peer_by_index.get(index):
            process = peer.start_agent(agent_id, index, len(hosts), delay)
        else:
            process = lab.spawn(
                sys.executable, ROOT / "scripts/phase4a_worker.py", "--id", agent_id,
                "--broker-port", lab.broker_port, "--coordinator-port", hosts[index % len(hosts)],
                "--config", lab.configs[index % 10], "--audit", folder / "audit.db",
                "--delay", delay, "--claim-timeout", claim_timeout, log=log,
            )
        if not probe:
            self.agents.setdefault(agent_id, (index, log))
            self.processes[agent_id] = process
        return process, log

    def refresh(self):
        for agent_id, (_, log) in self.agents.items():
            for row in log.read():
                if row["kind"] not in {"ack", "audit"} or row["decision"] is None:
                    continue
                event = row["decision"]["event_id"]
                by_event = self.acks if row["kind"] == "ack" else self.commits
                by_event[event].setdefault(agent_id, row)

    def failures(self):
        return {agent_id: code for agent_id, process in self.processes.items()
                if (code := process.poll()) is not None}

    def signal(self, agent_id, sig):
        self.processes[agent_id].send_signal(sig)
        if sig == signal.SIGSTOP:
            self.paused.add(agent_id)
        if sig == signal.SIGCONT:
            self.paused.discard(agent_id)


class Lab:
    def __init__(self, args, path, docker_env):
        self.args = args
        self.path = path
        self.env = docker_env | {"AEGIS_PHASE4A_PG_PASSWORD": secrets.token_hex(16)}
        self.project = "aegis-phase4a-" + uuid4().hex[:12]
        self.fleet = Fleet(self)
        self.children = []
        self.coordinator_logs = []
        self.coordinator_processes = []
        self.coordinator_ports = []
        self.snapshots = []
        self.container_samples = []
        self.journal = []
        self.events = {}
        self.phases = {}
        self.failures = []
        self.notes = []
        self.compose_log = []
        self.port_retries = 0
        self.setup_started = False
        self.monitoring = None
        self.connection = None
        self.monitor_client = None
        self.peers = []
        self.peer_by_index = {}

    def docker(self, *args):
        return command("docker", *args, env=self.env, cwd=self.path)

    def compose(self, *args):
        return self.docker("compose", "-f", str(ROOT / "compose.phase4a.yaml"), "-p", self.project, *args)

    def port(self, service, container_port):
        host, number = self.compose("port", service, str(container_port)).rsplit(":", 1)
        if host != "127.0.0.1":
            raise RuntimeError("disposable lab service must bind to IPv4 loopback")
        return int(number)

    def spawn(self, *argv, log, env=None, pass_fds=()):
        with log.path.open("ab") as out, log.path.with_suffix(".stderr").open("ab") as err:
            process = subprocess.Popen([str(arg) for arg in argv], cwd=self.path,
                                       env=env or python_env(), stdout=out, stderr=err,
                                       stdin=subprocess.DEVNULL, pass_fds=pass_fds)
        self.children.append(process)
        return process

    def prepare_keys(self):
        command(sys.executable, str(ROOT / "scripts/setup_lab.py"), cwd=self.path, env=python_env())
        config = self.path / "lab-config"
        self.publisher = Ed25519PrivateKey.from_private_bytes((config / "publisher.key").read_bytes())
        self.revoker = Ed25519PrivateKey.from_private_bytes((config / "revoker.key").read_bytes())
        self.trust_path = config / "publishers.json"
        trust = json.loads(self.trust_path.read_text())
        self.publishers = ["lab-publisher", "lab-publisher-b", "lab-publisher-c", "lab-publisher-d"]
        grant, revoke = trust["grants"]
        revoke["revocation_publishers"] = self.publishers
        trust["grants"].extend(grant | {"publisher_id": publisher} for publisher in self.publishers[1:])
        self.trust_path.write_text(json.dumps(trust))
        local = json.loads((config / "agent.json").read_text())
        local.update(publishers_file=str(self.trust_path),
                     allowed_templates=["observe-only", "restrict-fixture-route.v1"])
        self.configs = []
        for role, override in [
            ("denied", {"lab_authorized": False}),
            ("wrong-inventory", {"inventory": [{"purl": "pkg:generic/aegis-demo", "version": "9.0.0"}]}),
            ("allowed", {}),
        ]:
            path = config / f"{role}.json"
            path.write_text(json.dumps(local | override))
            self.configs.append(path)
        self.configs += [self.configs[-1]] * 7

    async def start_containers(self):
        self.setup_started = True
        for attempt in range(4):
            with socket.socket() as broker, socket.socket() as monitor:
                # Hold both until their addresses are distinct. Keep the
                # bindings stable when Docker restarts the broker in this run.
                broker.bind(("127.0.0.1", 0))
                monitor.bind(("127.0.0.1", 0))
                self.env["AEGIS_PHASE4A_NATS_PORT"] = str(broker.getsockname()[1])
                self.env["AEGIS_PHASE4A_MONITOR_PORT"] = str(monitor.getsockname()[1])
            try:
                self.compose_log.append(await asyncio.to_thread(
                    self.compose, "up", "-d", "--wait", "--wait-timeout", "45", "--pull", "never"))
                return
            except subprocess.CalledProcessError as exc:
                if attempt == 3 or "address already in use" not in (exc.stderr or ""):
                    raise
                # The Docker daemon can have a separate host namespace.
                # Retry its port race before creating any workload state.
                self.port_retries += 1
                self.compose_log.append(await asyncio.to_thread(
                    self.compose, "down", "--volumes", "--timeout", "5"))

    async def start_services(self, client):
        self.prepare_keys()
        await self.start_containers()
        self.broker_port = self.port("nats", 4222)
        self.monitor_port = self.port("nats", 8222)
        self.database_port = self.port("postgres", 5432)
        self.dsn = ("postgresql://aegis:" + self.env["AEGIS_PHASE4A_PG_PASSWORD"]
                    + f"@127.0.0.1:{self.database_port}/aegis?connect_timeout=3")
        self.images = {service: self.docker("inspect", "--format", "{{.Image}}",
                                           self.compose("ps", "-q", service))
                       for service in ("nats", "postgres")}
        self.docker_version = self.docker("info", "--format", "{{.ServerVersion}} {{.NCPU}} {{.MemTotal}}")
        self.monitor_client = client
        for _ in range(self.args.coordinators):
            await self.start_coordinator(client)
        self.connection = await nats.connect(f"nats://127.0.0.1:{self.broker_port}",
                                             name="phase4a-controller", connect_timeout=2)
        self.js = self.connection.jetstream()
        self.monitoring = asyncio.create_task(self.monitor())

    async def start_peers(self):
        offset = self.args.agents - sum(count for _, count in self.args.ssh_peer)
        for number, (target, count) in enumerate(self.args.ssh_peer, 1):
            path = self.path / f"peer-{number}"
            path.mkdir()
            peer = await Peer.start(target, count, self.args.peer_checkout, self.args.peer_python,
                                    self.broker_port, self.coordinator_ports,
                                    json.loads(self.trust_path.read_text()),
                                    [json.loads(config.read_text()) for config in self.configs], path)
            self.peers.append(peer)
            self.peer_by_index.update(dict.fromkeys(range(offset, offset + count), peer))
            offset += count

    async def container_stats(self, label):
        ids = await asyncio.to_thread(self.compose, "ps", "-q")
        raw = await asyncio.to_thread(self.docker, "stats", "--no-stream",
                                      "--format", "{{json .}}", *ids.splitlines())
        self.container_samples.append({"ns": now(), "label": label,
                                       "statistics": [json.loads(line) for line in raw.splitlines()]})

    def outbox_rows(self):
        with psycopg.connect(self.dsn) as db:
            rows = db.execute("SELECT j.position, o.event_id::text, o.sent_at FROM mesh_outbox o "
                              "JOIN mesh_journal j USING(event_id) ORDER BY j.position").fetchall()
        return [{"position": pos, "event_id": eid,
                 "sent_at": stamp.isoformat() if stamp else None} for pos, eid, stamp in rows]

    async def start_coordinator(self, client):
        index = len(self.coordinator_logs)
        log = Log(self.path / f"coordinator-{index}.jsonl")
        env = python_env() | {
            "AEGIS_DATABASE_URL": self.dsn,
            "AEGIS_NATS_URL": f"nats://127.0.0.1:{self.broker_port}",
            "AEGIS_PUBLISHERS_FILE": str(self.trust_path),
        }
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            process = self.spawn(sys.executable, "-m", "uvicorn", "phase4a_coordinator:app",
                                 "--fd", listener.fileno(), "--no-access-log",
                                 "--timeout-graceful-shutdown", "8", log=log,
                                 env=env, pass_fds=(listener.fileno(),))
        self.coordinator_logs.append(log)
        self.coordinator_processes.append(process)
        self.coordinator_ports.append(port)
        async with asyncio.timeout(20):
            while process.poll() is None:
                with suppress(httpx.HTTPError):
                    response = await client.get(f"http://127.0.0.1:{port}/health", timeout=1)
                    if response.status_code == 200:
                        return
                await asyncio.sleep(0.1)
        raise RuntimeError(f"coordinator {index} exited during startup")

    def pg_snapshot(self):
        with psycopg.connect(self.dsn) as db:
            outbox = db.execute(
                "SELECT count(*) FILTER (WHERE sent_at IS NULL), count(*) FROM mesh_outbox").fetchone()
            fields = ("size_bytes", "transactions", "rollbacks", "blocks_read", "blocks_hit",
                      "temp_bytes", "connections")
            db_stats = db.execute("SELECT pg_database_size(current_database()), xact_commit, xact_rollback,"
                                  "blks_read, blks_hit, temp_bytes, numbackends FROM pg_stat_database "
                                  "WHERE datname=current_database()").fetchone()
        return dict(zip(fields, db_stats, strict=True)) | {"outbox_pending": outbox[0], "outbox_total": outbox[1]}

    async def snapshot(self, label=None):
        sample = {"ns": now(), "label": label}
        base = f"http://127.0.0.1:{self.monitor_port}"
        try:
            async with asyncio.timeout(3):
                varz = (await self.monitor_client.get(base + "/varz")).raise_for_status().json()
                jsz = (await self.monitor_client.get(
                    base + "/jsz", params={"accounts": "true", "streams": "true", "consumers": "true",
                                           "limit": 2048})).raise_for_status().json()
            sample["nats"] = {field: varz.get(field) for field in (
                "cpu", "mem", "connections", "in_bytes", "out_bytes", "in_msgs", "out_msgs",
                "slow_consumers", "version", "max_connections", "start")}
            sample["jetstream"] = {field: jsz.get(field) for field in (
                "storage", "memory", "streams", "consumers", "api")}
            stream = next(item for account in jsz.get("account_details", [])
                          for item in account.get("stream_detail", []) if item.get("name") == STREAM)
            consumers = stream.get("consumer_detail", [])
            sample["findings_stream"] = {
                "state": stream["state"], "consumers_in_sample": len(consumers),
                "pending": sum(c["num_pending"] for c in consumers),
                "ack_pending": sum(c["num_ack_pending"] for c in consumers),
                "redelivered": sum(c["num_redelivered"] for c in consumers),
                "waiting_pulls": sum(c["num_waiting"] for c in consumers),
            }
        except (httpx.HTTPError, TimeoutError, StopIteration, KeyError) as exc:
            sample["nats_sampling_error"] = type(exc).__name__
        try:
            sample["postgres"] = await asyncio.to_thread(self.pg_snapshot)
        except psycopg.Error as exc:
            sample["postgres_sampling_error"] = type(exc).__name__
        self.snapshots.append(sample)
        return sample

    async def monitor(self):
        while True:
            await self.snapshot()
            await asyncio.sleep(self.args.sample_interval)

    async def wait(self, predicate, name, *, timeout=None, check_agents=True):
        deadline = time.monotonic() + (self.args.timeout if timeout is None else timeout)
        while time.monotonic() < deadline:
            await asyncio.to_thread(self.fleet.refresh)
            if check_agents and (failures := self.fleet.failures()):
                raise RuntimeError(f"agents exited during {name}: {failures}")
            if predicate():
                return
            await asyncio.sleep(0.10)
        raise TimeoutError(name)

    async def start_fleet(self):
        existing = set()
        started = now()
        host_counts = Counter(self.peer_by_index.get(index) for index in range(self.args.agents))
        for offset in range(0, self.args.agents, self.args.start_batch):
            batch = []
            for index in range(offset, min(offset + self.args.start_batch, self.args.agents)):
                agent_id = str(uuid4())
                batch.append(agent_id)
                delay = self.args.slow_ms / 1000 if self.args.faults and index % 10 == 9 else 0
                self.fleet.start(agent_id, index, delay=delay)
            await self.wait(lambda: all(any(row["kind"] == "ready" for row in self.fleet.agents[agent_id][1].rows)
                                        for agent_id in batch), "fleet startup")
            existing.update(batch)
            charges = defaultdict(list)
            for identity in existing:
                index, log = self.fleet.agents[identity]
                ready = next(row for row in log.rows if row["kind"] == "ready")
                charges[self.peer_by_index.get(index)].append(ready["memory_charge_bytes"])
            projected = {host: sum(values) / len(values) * host_counts[host] for host, values in charges.items()}
            self.phases["startup"] = {"launched": len(existing), "elapsed_ms": ms(started, now()),
                                      "projected_agent_memory_mib_by_host": {
                                          "controller" if host is None else f"peer-{self.peers.index(host) + 1}":
                                          round(amount / MIB) for host, amount in projected.items()}}
            if max(projected.values()) > self.args.agent_memory_budget_mib * MIB:
                raise ResourceLimit(f"projected agent memory on one host is {max(projected.values()) / MIB:.0f} MiB "
                                    f"with budget {self.args.agent_memory_budget_mib} MiB "
                                    f"after starting {len(existing)} agents")
            print(f"Agents ready: {len(existing)}/{self.args.agents}", flush=True)
        pids = {(self.peer_by_index.get(index), next(row["pid"] for row in log.rows if row["kind"] == "ready"))
                for index, log in self.fleet.agents.values()}
        if len(pids) != self.args.agents:
            raise RuntimeError("fleet readiness did not identify one OS process per deployment")

    async def post(self, client, envelope, phase, *, coordinator=0):
        eid = event_id(envelope)
        path = "/v1/findings" if envelope.kind == "finding" else "/v1/revocations"
        payload = event_payload(envelope)
        self.events[eid] = row = {
            "kind": envelope.kind, "phase": phase, "publisher": payload.publisher_id,
            "sequence": payload.sequence, "start": now(), "coordinator": coordinator,
            "digest": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
            "wire_bytes": len(envelope.model_dump_json().encode()),
        }
        if envelope.kind == "revocation":
            row["target"] = str(payload.target_artifact_id)
        response = await client.post(f"http://127.0.0.1:{self.coordinator_ports[coordinator]}{path}",
                                     content=envelope.model_dump_json(),
                                     headers={"Content-Type": "application/json"})
        row.update(http_end=now(), http_status=response.status_code)
        response.raise_for_status()
        if response.json().get("accepted") is not True:
            raise RuntimeError("fresh synthetic event was not accepted")
        return eid

    def make_finding(self, publisher, sequence):
        event = finding(self.publisher, sequence)
        if publisher == "lab-publisher":
            return event
        return sign(event.finding.model_copy(update={"publisher_id": publisher}), self.publisher)

    async def wait_acks(self, events, population=None, *, timeout=None):
        expected = set(self.fleet.agents if population is None else population)
        await self.wait(lambda: all(expected <= self.fleet.acks[eid].keys() for eid in events),
                        f"broker ack coverage {sum(len(self.fleet.acks[eid]) for eid in events)}/"
                        f"{len(expected) * len(events)} at start of wait", timeout=timeout)

    async def steady(self, client):
        events = []
        for sequence in range(1, self.args.steady + 1):
            envelope = self.make_finding(self.publishers[0], sequence)
            eid = await self.post(client, envelope, "steady",
                                  coordinator=(sequence - 1) % len(self.coordinator_ports))
            events.append(envelope)
            await self.wait_acks([eid])
        return events

    async def burst(self, client):
        start = now()
        pause = [agent_id for agent_id, (index, _) in self.fleet.agents.items()
                 if self.args.faults and index % 10 == 8]
        for agent_id in pause:
            self.fleet.signal(agent_id, signal.SIGSTOP)
        try:
            async def ingress(index, publisher):
                for seq in range(self.args.steady + 1, self.args.steady + self.args.burst + 1):
                    envelope = self.make_finding(publisher, seq)
                    await self.post(client, envelope, "burst",
                                    coordinator=(index + seq) % len(self.coordinator_ports))

            async with asyncio.TaskGroup() as group:
                for index, publisher in enumerate(self.publishers):
                    group.create_task(ingress(index, publisher))
            events = [eid for eid, row in self.events.items() if row["phase"] == "burst"]
            blocked = await self.snapshot("burst_ingress_complete")
            if pause:
                await self.wait_acks(events, set(self.fleet.agents) - set(pause))
                blocked = await self.snapshot("slow_agents_paused")
        finally:
            resumed = now()
            for agent_id in pause:
                self.fleet.signal(agent_id, signal.SIGCONT)
        await self.wait_acks(events)
        drained = max(observed(row, "acked") for eid in events for row in self.fleet.acks[eid].values())
        sampled_drain = await self.snapshot("burst_drained")
        self.phases["burst"] = {
            "publishers": len(self.publishers), "paused_agents": len(pause),
            "delayed_agents": self.args.agents // 10 if self.args.faults and self.args.slow_ms else 0,
            "paused_backlog": blocked.get("findings_stream"),
            "drained_backlog": sampled_drain.get("findings_stream"),
            "last_ack_after_resume_ms": ms(resumed, drained) if pause else None,
            "events_per_second": round(len(events) * 1000 / ms(
                start, max(self.events[eid]["http_end"] for eid in events)), 2),
            "acks_per_second": round(len(events) * len(self.fleet.agents) * 1000 / ms(start, drained), 2),
        }
        return events

    async def basic_revocations(self, client, first, second):
        later = revocation(self.revoker, first, 2)
        late = revocation(self.revoker, second, 1)
        for envelope in (later, late):
            eid = await self.post(client, envelope, "withdrawal")
            await self.wait_acks([eid])
        return first, later, second, late

    async def faults(self, client, target):
        agent_id = next(aid for aid, (index, _) in self.fleet.agents.items() if index == 2)
        index, log = self.fleet.agents[agent_id]
        phase = self.phases["faults"] = {}
        proc, probe = self.fleet.start(agent_id, index, claim_timeout=0, probe=True)
        await self.wait(lambda: proc.poll() is not None, "duplicate identity probe", timeout=15)
        if proc.returncode != 3 or not any(row["kind"] == "identity_in_use" for row in probe.read()):
            raise RuntimeError("simultaneous deployment identity was not rejected")
        phase["lease_collision"] = probe.rows

        crash = now()
        old = self.fleet.processes[agent_id]
        self.fleet.signal(agent_id, signal.SIGKILL)
        await asyncio.to_thread(old.wait, 10)
        self.fleet.start(agent_id, index)
        envelope = revocation(self.revoker, target, 3)
        eid = await self.post(client, envelope, "crash_withdrawal")
        await self.wait_acks([eid], set(self.fleet.agents) - {agent_id})
        await self.wait_acks([eid])
        claimed = [row for row in log.rows if row["kind"] == "claimed"][-1]
        ready = [row for row in log.rows if row["kind"] == "ready"][-1]
        phase["sigkill"] = dict(agent_id=agent_id, event_id=eid, old_pid=old.pid, new_pid=ready["pid"],
                               to_claim_ms=ms(crash, claimed["ns"]), to_ready_ms=ms(crash, ready["ns"]),
                               to_ack_ms=ms(crash, self.fleet.acks[eid][agent_id]["acked"]))

        cutoff = now()
        await asyncio.to_thread(self.compose, "stop", "-t", "0", "nats")
        envelope = self.make_finding(self.publishers[0], self.args.steady + self.args.burst + 1)
        during = await self.post(client, envelope, "broker_restart")
        pending = await self.snapshot("broker_stopped")
        if pending.get("postgres", {}).get("outbox_pending", 0) < 1:
            raise RuntimeError("finding submitted while broker stopped was not retained in outbox")
        await asyncio.to_thread(self.compose, "start", "nats")
        await self.wait_acks([during])
        reconnects = {agent_id: next((observed(row) for row in log.rows
                                    if observed(row) >= cutoff and row["kind"] == "reconnected"), None)
                      for agent_id, (_, log) in self.fleet.agents.items()}
        phase["broker_restart"] = {
            "event_id": during, "outbox_pending_during_stop": pending["postgres"]["outbox_pending"],
            "reconnection_ms": distribution([ms(cutoff, stamp) for stamp in reconnects.values() if stamp]),
            "to_all_acks_ms": ms(cutoff, max(observed(row, "acked") for row in self.fleet.acks[during].values())),
        }

        # Close the connection before submission so the consumer cannot buffer
        # the copy in its process while JetStream purges the stream.
        victim = self.fleet.processes.pop(agent_id)
        victim.terminate()
        if await asyncio.to_thread(victim.wait, 10) != 0:
            raise RuntimeError("could not stop journal probe deployment")
        envelope = revocation(self.revoker, envelope, 4)
        purged = await self.post(client, envelope, "journal_only")
        await self.wait_acks([purged], set(self.fleet.agents) - {agent_id})
        state = await self.js.consumer_info(STREAM, durable_name(agent_id))
        if state.num_pending < 1:
            raise RuntimeError("probe consumer did not miss the broker copy before purge")
        await self.js.purge_stream(STREAM)
        resumed = now()
        self.fleet.start(agent_id, index)
        await self.wait(lambda: agent_id in self.fleet.commits[purged], "signed journal repair")
        repair = self.fleet.commits[purged][agent_id]
        self.events[purged]["journal_only_agent"] = agent_id
        phase["journal_repair"] = dict(agent_id=agent_id, event_id=purged,
                                       pending_before_purge=state.num_pending + state.num_ack_pending,
                                       ms_from_resume=ms(resumed, repair["ns"]))

    async def authenticity(self, target):
        # The lab deliberately bypasses coordinator ingestion here to exercise
        # independent agent authentication. The body is an inert signed fixture.
        forged = self.make_finding(self.publishers[0], 999_999)
        forged = sign(forged.finding, Ed25519PrivateKey.generate())
        eid = event_id(forged)
        await self.js.publish(SUBJECT, forged.model_dump_json().encode())
        await self.wait_acks([eid])
        if any(row["decision"]["reason_code"] != "INVALID_SIGNATURE" for row in self.fleet.acks[eid].values()):
            raise RuntimeError("agent did not independently reject an invalid signature")
        replay = event_id(target)
        latest_seq = (await self.js.publish(SUBJECT, target.model_dump_json().encode())).seq
        await self.wait(lambda: all(any(row["kind"] == "ack" and row["sequence"] == latest_seq
                                        for row in log.rows)
                                    for _, log in self.fleet.agents.values()), "duplicate broker replay")
        observed = [row["decision"]["reason_code"] for _, log in self.fleet.agents.values()
                    for row in log.rows if row["kind"] == "ack" and row["sequence"] == latest_seq]
        if set(observed) != {"FINDING_REVOKED"}:
            raise RuntimeError("broker replay reopened a withdrawn finding")
        self.phases["authenticity"] = {"forged_event": eid, "replayed_event": replay,
                                       "replay_stream_sequence": latest_seq,
                                       "forge_and_replay_acks_each": len(observed)}

    async def capacity_backpressure(self, client):
        existing = await self.js.stream_info(STREAM)
        limited = await self.js.stream_info(STREAM)
        limited.config.max_bytes = existing.state.bytes
        if existing.state.bytes < 1:
            raise RuntimeError("need retained traffic to exercise the broker capacity limit")
        await self.js.update_stream(limited.config)
        try:
            event = self.make_finding(self.publishers[0], self.args.steady + self.args.burst + 2)
            eid = await self.post(client, event, "capacity_backpressure")
            # Permit repeated dispatcher attempts while the stream rejects new publishes.
            await asyncio.sleep(0.65)
            limited_state = await self.js.stream_info(STREAM)
            sample = await self.snapshot("stream_at_capacity")
            outbox = await asyncio.to_thread(self.outbox_rows)
            if (limited_state.state.last_seq != existing.state.last_seq
                    or not any(row["event_id"] == eid and row["sent_at"] is None for row in outbox)):
                raise RuntimeError("capacity rejection did not retain the expected outbox event")
        finally:
            restored = now()
            await self.js.update_stream(existing.config)
        await self.wait_acks([eid])
        self.phases["capacity_backpressure"] = {
            "event_id": eid, "temporary_stream_max_bytes": limited.config.max_bytes,
            "outbox_pending_during_limit": sample["postgres"]["outbox_pending"],
            "restore_to_all_acks_ms": ms(restored, max(observed(row, "acked")
                                                      for row in self.fleet.acks[eid].values())),
        }

    async def protection(self):
        log = Log(self.path / "protection.jsonl")
        output = self.path / "protection-result.json"
        proc = self.spawn(sys.executable, ROOT / "scripts/phase3c_lab.py", "--agents", "1",
                          "--eligible", "1", "--lease-ms", "3000", "--repeats", self.args.protection,
                          "--scripted-approval", "--directory", self.path / "fixture-audits",
                          "--broker-port", self.broker_port, "--coordinator-port", self.coordinator_ports[0],
                          "--output", output, log=log)
        await self.wait(lambda: proc.poll() is not None, "independent authorized fixture",
                        timeout=max(self.args.timeout, self.args.protection * 25))
        if proc.returncode:
            raise RuntimeError("independent Phase 3C fixture failed; inspect protection.stderr")
        report = json.loads(output.read_text())
        for run in report["runs"]:
            await self.wait_acks([run["event_id"]])
        self.phases["protection"] = report

    async def stop(self):
        if self.monitoring is not None:
            self.monitoring.cancel()
            await asyncio.gather(self.monitoring, return_exceptions=True)
        for agent_id in self.fleet.paused.copy():
            with suppress(ProcessLookupError):
                self.fleet.signal(agent_id, signal.SIGCONT)
        for result in await asyncio.gather(*(peer.stop() for peer in self.peers), return_exceptions=True):
            if isinstance(result, Exception):
                self.failures.append(f"SSH peer cleanup/readback: {type(result).__name__}: {result}")
        for process in reversed(self.children):
            if process.poll() is None:
                process.terminate()
        deadline = time.monotonic() + 20
        while any(process.poll() is None for process in self.children) and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        for process in self.children:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        if self.connection is not None:
            await self.connection.close()
        if self.setup_started:
            try:
                self.compose_log.append(await asyncio.to_thread(
                    self.compose, "down", "--volumes", "--timeout", "5"))
            except subprocess.SubprocessError as exc:
                self.failures.append(f"failed to clean up project {self.project}: {type(exc).__name__}")


class ResourceLimit(RuntimeError):
    pass


def expected_policy(index):
    if index % 10 == 0:
        return "LAB_NOT_AUTHORIZED"
    if index % 10 == 1:
        return "INVENTORY_NO_EXACT_MATCH"
    return "EXACT_MATCH_ALLOWED"


def disk_size(path):
    return sum(file.stat().st_size for file in path.glob("audit.db*"))


def read_audit(path):
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        records = db.execute("SELECT artifact_id,digest,reason_code,authenticated,dry_run "
                             "FROM decisions ORDER BY rowid").fetchall()
        revocations = db.execute("SELECT event_id,digest,target_artifact_id,reason_code,authenticated "
                                 "FROM revocation_decisions ORDER BY rowid").fetchall()
        effective = set(db.execute("SELECT artifact_id FROM revoked_targets "
                                   "JOIN decisions USING (artifact_id,digest) "
                                   "WHERE target_publisher_id=publisher_id").fetchall())
        rejected = db.execute("SELECT artifact_id,reason_code FROM rejected_events").fetchall()
        owner = db.execute("SELECT agent_id FROM agent_identity").fetchone()[0]
        cursor = db.execute("SELECT position FROM recovery_cursor").fetchone()[0]
    return records, revocations, effective, rejected, owner, cursor


def validate_audits(lab):
    finding_ids = {eid for eid, row in lab.events.items() if row["kind"] == "finding"}
    revocation_ids = set(lab.events) - finding_ids
    protection = {run["event_id"] for run in lab.phases.get("protection", {}).get("runs", [])}
    oracle = {"missing_findings": 0, "missed_revocations": 0, "stale_effective_revocations": 0,
              "incorrect_decisions": 0, "duplicate_logical_decisions": 0,
              "unexpected_audit_findings": 0, "bad_signature_audit_rows": 0,
              "audit_bytes": 0, "details": []}
    for agent_id, (index, _) in lab.fleet.agents.items():
        folder = lab.path / agent_id
        if not (folder / "audit.db").exists():
            oracle["missing_findings"] += len(finding_ids | protection)
            oracle["missed_revocations"] += len(revocation_ids)
            continue
        records, revocations, effective, rejected, owner, cursor = read_audit(folder / "audit.db")
        if owner != agent_id:
            raise RuntimeError("audit identity changed")
        recorded = {eid: (digest, reason, valid, dry_run) for eid, digest, reason, valid, dry_run in records}
        withdrawn = {eid: (digest, target, reason, valid)
                     for eid, digest, target, reason, valid in revocations}
        missing_findings = (finding_ids | protection) - recorded.keys()
        missing_revocations = revocation_ids - withdrawn.keys()
        wrong = [eid for eid, row in lab.events.items()
                 if (eid in recorded and recorded[eid] != (row["digest"], expected_policy(index), 1, 1))
                 or (eid in withdrawn and withdrawn[eid] != (row["digest"], row["target"], "REVOCATION_ACCEPTED", 1))]
        stale = [lab.events[eid]["target"] for eid in revocation_ids & withdrawn.keys()
                 if (lab.events[eid]["target"],) not in effective]
        forged = lab.phases.get("authenticity", {}).get("forged_event")
        if forged and (forged, "INVALID_SIGNATURE") in rejected and forged not in recorded:
            oracle["bad_signature_audit_rows"] += 1
        unexpected = set(recorded) - finding_ids - protection
        duplicate = len(records) + len(revocations) - len(recorded) - len(withdrawn)
        oracle["missing_findings"] += len(missing_findings)
        oracle["missed_revocations"] += len(missing_revocations)
        oracle["stale_effective_revocations"] += len(stale)
        oracle["incorrect_decisions"] += len(wrong)
        oracle["duplicate_logical_decisions"] += duplicate
        oracle["unexpected_audit_findings"] += len(unexpected)
        oracle["audit_bytes"] += disk_size(folder)
        oracle["details"].append({"agent_id": agent_id, "audit_bytes": disk_size(folder), "owner": owner,
                                  "cursor": cursor, "finding_rows": len(records),
                                  "revocation_rows": len(revocations),
                                  "missing_findings": sorted(missing_findings),
                                  "missing_revocations": sorted(missing_revocations),
                                  "incorrect_decisions": wrong, "stale_targets": stale,
                                  "unexpected_findings": sorted(unexpected)})
    return oracle


def summarize(lab, oracle):
    fleet = lab.fleet
    expected_acks = len(lab.events) * len(fleet.agents) - sum(
        "journal_only_agent" in event for event in lab.events.values())
    acked = sum(len(fleet.acks[eid]) for eid in lab.events)
    audit_keys = {(eid, identity) for eid in lab.events for identity in fleet.commits[eid]}
    by_phase = defaultdict(list)
    for eid, event in lab.events.items():
        by_phase[event["phase"]].append(eid)
    phases = {}
    for phase, ids in by_phase.items():
        ack_rows = [(eid, aid, row) for eid in ids for aid, row in fleet.acks[eid].items()]
        commits = [(eid, aid, row) for eid in ids for aid, row in fleet.commits[eid].items()]
        phases[phase] = {
            "events": len(ids), "broker_acks": len(ack_rows),
            "first_audit_commit": distribution([ms(lab.events[eid]["start"], observed(row))
                                                 for eid, _, row in commits]),
            "confirmed_ack": distribution([ms(lab.events[eid]["start"], observed(row, "acked"))
                                           for eid, _, row in ack_rows]),
            "coordinator_http": distribution([ms(lab.events[eid]["start"], lab.events[eid]["http_end"])
                                              for eid in ids if "http_end" in lab.events[eid]]),
            "local_audit_write": distribution([ms(row["start"], row["ns"]) for _, _, row in commits]),
            "lease_check": distribution([ms(row["received"], row["leased"]) for _, _, row in ack_rows]),
            "validation_and_audit": distribution([ms(row["leased"], row["committed"])
                                                  for _, _, row in ack_rows]),
            "ack_rtt": distribution([ms(row["committed"], row["acked"]) for _, _, row in ack_rows]),
            "replay_only_commits": len({(eid, aid) for eid, aid, _ in commits}
                                       - {(eid, aid) for eid, aid, _ in ack_rows}),
        }
    attempts = Counter((aid, row["decision"]["event_id"])
                       for aid, (_, log) in fleet.agents.items() for row in log.rows if row["kind"] == "ack")
    nats_samples = [snapshot["nats"] for snapshot in lab.snapshots if "nats" in snapshot]
    pg_samples = [snapshot["postgres"] for snapshot in lab.snapshots if "postgres" in snapshot]
    latest_usage = []
    for _, log in fleet.agents.values():
        by_pid_epoch = []
        for row in log.rows:
            if row["kind"] == "ready":
                by_pid_epoch.append(row)
            elif row["kind"] == "exit" and by_pid_epoch:
                by_pid_epoch[-1] = row
        latest_usage.extend(by_pid_epoch)
    def metric_range(samples, name):
        values = [sample[name] for sample in samples if sample.get(name) is not None]
        return [min(values), max(values)] if values else None

    by_broker_start = defaultdict(list)
    for sample in nats_samples:
        by_broker_start[sample["start"]].append(sample)
    network = [
        {name: group[-1][name] - group[0][name] for name in ("in_bytes", "out_bytes", "in_msgs", "out_msgs")}
        | {"server_epoch": start}
        for start, group in by_broker_start.items()
    ]
    coordinator = []
    for log, process in zip(lab.coordinator_logs, lab.coordinator_processes, strict=True):
        log.read()
        by_route = defaultdict(list)
        statuses = Counter()
        for row in log.rows:
            if "route" in row:
                by_route[row["route"]].append(ms(row["start"], row["end"]))
                statuses[str(row["status"])] += 1
        coordinator.append({
            "requests": {route: distribution(latencies) for route, latencies in by_route.items()},
            "http_status_counts": dict(statuses), "shutdown_exit_code": process.returncode,
            "resources": next((row for row in reversed(log.rows) if row.get("kind") == "resources"), None),
        })
    stale_past_budget = sum(ms(lab.events[eid]["start"], observed(row)) > REVOCATION_BUDGET_MS
                            for eid, aid in audit_keys if lab.events[eid]["kind"] == "revocation"
                            for row in [fleet.commits[eid][aid]])
    protection_runs = lab.phases.get("protection", {}).get("runs", [])
    protection_rows = [row for run in protection_runs for row in run["deployments"] if row["eligible"]]
    return {
        "confirmed_acks": acked, "expected_acks": expected_acks,
        "expected_logical_decisions": len(lab.events) * len(fleet.agents),
        "observed_first_audit_commits": len(audit_keys),
        "extra_broker_acks_of_same_logical_event": sum(count - 1 for count in attempts.values()),
        "revocation_stale_past_budget": stale_past_budget, "revocation_budget_ms": REVOCATION_BUDGET_MS,
        "phases": phases,
        "protection": {
            "confirmed": sum(row["status"] == "confirmed" for row in protection_rows),
            "eligible": len(protection_rows),
            "companion_mesh_acks": sum(len(fleet.acks[run["event_id"]]) for run in protection_runs),
            "verified_to_protection_ms": distribution([row["verified_to_protection_ms"]
                                                        for row in protection_rows]),
            "independent_probe_requests": sum(row["post_confirmation_probes"] for row in protection_rows),
            "marker_escapes": sum(row["marker_escapes"] for row in protection_rows),
        } if protection_runs else None,
        "audits": {key: val for key, val in oracle.items() if key != "details"},
        "resources": {
            "agent_cpu_s": round(sum(row["cpu_s"] for row in latest_usage), 3),
            "agent_peak_rss_bytes": distribution([row["peak_rss_bytes"] for row in latest_usage]),
            "agent_memory_charge_bytes": distribution([row["memory_charge_bytes"] for row in latest_usage]),
            "nats_cpu_pct_range": metric_range(nats_samples, "cpu"),
            "nats_resident_bytes_range": metric_range(nats_samples, "mem"),
            "nats_client_bytes_and_messages": network,
            "jetstream_storage_bytes_range": metric_range([s["jetstream"] for s in lab.snapshots
                                                           if "jetstream" in s], "storage"),
            "postgres_database_bytes_range": metric_range(pg_samples, "size_bytes"),
            "postgres_connections_range": metric_range(pg_samples, "connections"),
            "coordinators": coordinator,
        },
    }


def git_identity():
    tracked = sorted([ROOT / "compose.phase4a.yaml", ROOT / "src/aegis/agent_runtime.py",
                      ROOT / "src/aegis/mesh.py", ROOT / "src/aegis/api.py",
                      *((ROOT / "scripts").glob("phase4a_*.py"))])
    files = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
    return {"head": command("git", "rev-parse", "HEAD", cwd=ROOT), "instrumentation_sha256": files}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    opener = gzip.open if path.suffix == ".gz" else open
    temporary = path.with_name(path.name + ".tmp")
    with opener(temporary, "wt", encoding="utf-8") as stream:
        json.dump(data, stream, separators=(",", ":") if path.suffix == ".gz" else None,
                  indent=None if path.suffix == ".gz" else 2)
        stream.write("\n")
    temporary.replace(path)


async def run(args, path, docker_env):
    lab = Lab(args, path, docker_env)
    source = git_identity()
    cpu_begin = time.process_time()
    async with httpx.AsyncClient(trust_env=False, timeout=10) as client:
        try:
            await lab.start_services(client)
            await lab.snapshot("before_agents")
            await lab.container_stats("before_agents")
            await lab.start_peers()
            await lab.start_fleet()
            await lab.snapshot("fleet_ready")
            steady = await lab.steady(client)
            await lab.burst(client)
            await lab.basic_revocations(client, steady[0], steady[1])
            if args.faults:
                await lab.faults(client, steady[2])
                await lab.authenticity(steady[0])
                await lab.capacity_backpressure(client)
            if args.protection:
                await lab.protection()
            await lab.snapshot("workload_finished")
            lab.journal = await asyncio.to_thread(lab.outbox_rows)
            await lab.container_stats("workload_finished")
        except ResourceLimit as exc:
            lab.notes.append(str(exc))
        except Exception as exc:
            message = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
            # The raw artifact excludes credentials even in runtime errors.
            message = message.replace(lab.env["AEGIS_PHASE4A_PG_PASSWORD"], "[redacted]")
            lab.failures.append(f"{type(exc).__name__}: {message}")
        finally:
            await lab.stop()
    lab.fleet.refresh()
    try:
        oracle = validate_audits(lab)
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        oracle = {"details": []}
        lab.failures.append(f"audit readback: {type(exc).__name__}: {exc}")
    summary = summarize(lab, oracle)
    if not lab.notes and not lab.failures:
        for field in ("missing_findings", "missed_revocations", "stale_effective_revocations",
                      "incorrect_decisions", "duplicate_logical_decisions", "unexpected_audit_findings"):
            if oracle[field]:
                lab.failures.append(f"{field}={oracle[field]}")
        if args.faults and oracle["bad_signature_audit_rows"] != args.agents:
            lab.failures.append("bad signature evidence missing from local rejection audit")
        if summary["confirmed_acks"] != summary["expected_acks"]:
            lab.failures.append("broker confirmation coverage incomplete")
        if any(entry["sent_at"] is None for entry in lab.journal):
            lab.failures.append("outbox did not fully drain")
    outcome = "failed" if lab.failures else "resource_limited" if lab.notes else "passed"
    private_params = {"ssh_peer", "peer_checkout", "peer_python"}
    parameters = {key: value for key, value in vars(args).items()
                  if key not in private_params and not isinstance(value, Path)}
    report = {
        "schema": "aegis-phase4a-lab-v1",
        "outcome": outcome, "failures": lab.failures, "notes": lab.notes,
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "topology": {"agent_processes_requested": args.agents, "agent_ids_started": len(lab.fleet.agents),
                     "coordinator_processes": len(lab.coordinator_ports),
                     "agent_hosts": 1 + len(lab.peers),
                     "remote_peers": [{"agents": peer.count, **peer.platform} for peer in lab.peers],
                     "broker_nodes": 1, "database_nodes": 1,
                     "clock": "remote E2E is controller-observed upper bound" if lab.peers else "host monotonic",
                     "service_vm": platform.system() in {"Darwin", "Windows"},
                     "service_containers": 2, "fixture_processes": int(bool(args.protection)),
                     "docker_environment": getattr(lab, "docker_version", None)},
        "environment": {"platform": platform.platform(), "python": platform.python_version(),
                        "logical_cpu_count": os.cpu_count(), "docker_image_ids": getattr(lab, "images", {}),
                        "dependencies": {key: version(key) for key in (
                            "nats-py", "psycopg", "cryptography", "httpx", "uvicorn", "fastapi")},
                        "git": source},
        "parameters": parameters, "lab_port_retries": lab.port_retries,
        "metrics": summary, "scenarios": lab.phases,
        "events": lab.events, "broker_postgres_samples": sorted(lab.snapshots, key=lambda row: row["ns"]),
        "container_samples": lab.container_samples, "outbox": lab.journal,
        "coordinator_requests": [log.rows for log in lab.coordinator_logs],
        "agent_traces": {aid: {"index": index, "trace": log.rows} for aid, (index, log) in lab.fleet.agents.items()},
        "audit_readback": oracle["details"],
        "driver_cpu_s": round(time.process_time() - cpu_begin, 3),
    }
    write_json(args.output, report)
    condensed = {key: val for key, val in report.items()
                 if key not in {"events", "broker_postgres_samples", "agent_traces",
                                "coordinator_requests", "audit_readback"}}
    if args.summary:
        write_json(args.summary, condensed)
    print(json.dumps({"result": outcome, "failures": lab.failures, "notes": lab.notes,
                      "agents": args.agents, "broker_acks": [summary["confirmed_acks"], summary["expected_acks"]],
                      "raw_report": str(args.output)}, indent=2), flush=True)
    return {"passed": 0, "failed": 1, "resource_limited": 2}[outcome]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-local-lab", action="store_true", required=True,
                        help="explicit consent for disposable loopback services and test faults")
    parser.add_argument("--agents", type=int, required=True, help="fleet population, between 10 and 1,000")
    parser.add_argument("--coordinators", type=int, choices=(1, 2), default=1)
    parser.add_argument("--steady", type=int, default=5)
    parser.add_argument("--burst", type=int, default=5, help="events per publisher across four publishers")
    parser.add_argument("--faults", action="store_true")
    parser.add_argument("--slow-ms", type=int, default=80)
    parser.add_argument("--protection", type=int, default=0, help="separate local fixture repetitions")
    parser.add_argument("--ssh-peer", type=peer_spec, action="append", default=[], metavar="USER@PRIVATE_IPV4=COUNT",
                        help="pre-enrolled authorized lab host; COUNT is included in --agents")
    parser.add_argument("--peer-checkout", help="absolute checkout path common to all SSH peers")
    parser.add_argument("--peer-python", default="python3", help="Python executable with dependencies on each peer")
    parser.add_argument("--start-batch", type=int, default=25)
    parser.add_argument("--agent-memory-budget-mib", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=100, help="per-stage timeout in seconds")
    parser.add_argument("--sample-interval", type=float, default=0.5)
    parser.add_argument("--directory", type=Path, required=True, help="parent for private per-run state")
    parser.add_argument("--output", type=Path, required=True, help="raw report; suffix .gz enables compression")
    parser.add_argument("--summary", type=Path, help="optional condensed readable report")
    args = parser.parse_args()
    if args.ssh_peer and (not args.peer_checkout or not Path(args.peer_checkout).is_absolute()
                          or len({target.rsplit("@", 1)[1] for target, _ in args.ssh_peer}) != len(args.ssh_peer)
                          or sum(count for _, count in args.ssh_peer) > args.agents - 3):
        parser.error("SSH peers require a common absolute checkout, unique hosts, and at least three local agents")
    if (os.name != "posix" or not 10 <= args.agents <= 1000
            or not 3 <= args.steady <= 500 or not 1 <= args.burst <= 1000 or not 1 <= args.start_batch <= 50
            or not 0 <= args.slow_ms <= 1000 or not 0 <= args.protection <= 30
            or args.timeout < 10 or args.sample_interval < 0.2 or args.agent_memory_budget_mib < 1):
        parser.error("invalid workload or resource bounds")
    if args.agents * (args.steady + 4 * args.burst + args.protection + (9 if args.faults else 2)) > 250_000:
        parser.error("reduce fleet size or event counts to a maximum of 250,000 deliveries per run")
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="phase4a-", dir=args.directory.resolve()))
    print(f"Private run state: {path}", flush=True)
    with local_docker() as docker_env:
        return asyncio.run(run(args, path, docker_env))


if __name__ == "__main__":
    sys.exit(main())
