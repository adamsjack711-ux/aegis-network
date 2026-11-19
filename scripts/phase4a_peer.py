"""Private SSH transport for pre-enrolled Phase 4A lab hosts."""

import argparse
import asyncio
import base64
from contextlib import suppress
import hashlib
from ipaddress import IPv4Address, IPv4Network
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PEER_FILES = ["scripts/phase4a_worker.py", "scripts/phase4a_peer.py"]
PEER_USER = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}")
PEER_STATE = re.compile(r"/tmp/aegis-p4a\.[a-zA-Z0-9]+")
LAB_NETWORKS = tuple(map(IPv4Network, ("127.0.0.0/8", "10.0.0.0/8",
                                     "172.16.0.0/12", "192.168.0.0/16")))


def fingerprint():
    digest = hashlib.sha256()
    paths = [ROOT / name for name in PEER_FILES] + sorted((ROOT / "src/aegis").rglob("*.py"))
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def peer_spec(value):
    target, separator, count = value.rpartition("=")
    user, at, host = target.rpartition("@")
    try:
        address = IPv4Address(host)
    except ValueError:
        address = None
    if (not separator or not at or not PEER_USER.fullmatch(user) or not count.isdecimal()
            or not 1 <= int(count) <= 1000 or address is None
            or not any(address in network for network in LAB_NETWORKS)):
        raise argparse.ArgumentTypeError("use user@PRIVATE_IPV4=COUNT for an authorized lab host")
    return target, int(count)


def ssh():
    # Ignore ambient host aliases and forwarding rules. The authenticated SSH
    # connection is the only cross-host endpoint this harness creates.
    return ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=3"]


async def proxy(listener, target):
    async def forward(reader, writer):
        remote_writer = None
        try:
            remote_reader, remote_writer = await asyncio.open_unix_connection(target)

            async def pump(source, sink):
                while data := await source.read(64 * 1024):
                    sink.write(data)
                    await sink.drain()
                if sink.can_write_eof():
                    sink.write_eof()

            async with asyncio.TaskGroup() as group:
                group.create_task(pump(reader, remote_writer))
                group.create_task(pump(remote_reader, writer))
        except (OSError, ExceptionGroup):
            pass  # The normal agent transport handles disconnection and retry.
        finally:
            writer.close()
            if remote_writer is not None:
                remote_writer.close()
    return await asyncio.start_server(forward, listener, 0)


def send(kind, **values):
    print(json.dumps({"kind": kind, **values}, separators=(",", ":")), flush=True)


async def serve(path):
    from aegis.identity import canonical_agent_id

    if (not PEER_STATE.fullmatch(str(path)) or path.is_symlink()
            or path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid()):
        raise ValueError("expected a private disposable peer directory")
    # The Unix forward endpoints lie under a 0700 directory. The remote TCP
    # side is bound by this process to loopback, independent of sshd GatewayPorts.
    reader = asyncio.StreamReader()
    await asyncio.get_running_loop().connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    workers = {}
    logs = {}
    exiting = set()
    servers = []
    env = os.environ | {"PYTHONPATH": str(ROOT / "src")}

    def drain():
        for agent_id, (log, offset) in logs.items():
            with log.open("rb") as stream:
                stream.seek(offset)
                data = stream.read(32 * 1024)
            stop = data.rfind(b"\n") + 1
            if stop:
                logs[agent_id] = (log, offset + stop)
                send("trace", id=agent_id, data=base64.b64encode(data[:stop]).decode())
            elif agent_id in workers and workers[agent_id].poll() is not None and agent_id not in exiting:
                exiting.add(agent_id)
                send("exit", id=agent_id, status=workers[agent_id].returncode)
            elif data and len(data) == 32 * 1024:
                raise RuntimeError("peer trace line exceeds protocol limit")

    async def drain_periodically():
        while True:
            drain()
            await asyncio.sleep(0.10)

    sampler = None
    try:
        enrollment = json.loads(await reader.readline())
        if enrollment["fingerprint"] != fingerprint():
            raise ValueError("local and peer worker source fingerprints differ")
        public = path / "publishers.json"
        public.write_text(json.dumps(enrollment["publishers"]))
        configs = []
        for index, config in enumerate(enrollment["configs"]):
            dest = path / f"policy-{index}.json"
            dest.write_text(json.dumps(config | {"publishers_file": str(public)}))
            configs.append(dest)
        broker = await proxy("127.0.0.1", str(path / "n.sock"))
        servers.append(broker)
        for index in range(enrollment["coordinators"]):
            servers.append(await proxy("127.0.0.1", str(path / f"c{index}.sock")))
        ports = [server.sockets[0].getsockname()[1] for server in servers]
        send("ready", pid=os.getpid(), platform=sys.platform, python=sys.version.split()[0])
        sampler = asyncio.create_task(drain_periodically())
        while line := await reader.readline():
            item = json.loads(line)
            if item["op"] == "stop":
                break
            agent_id = item["id"]
            canonical_agent_id(agent_id)
            if item["op"] == "signal":
                if item["signal"] not in {"SIGSTOP", "SIGCONT"}:
                    raise ValueError("unsupported peer signal")
                workers[agent_id].send_signal(getattr(signal, item["signal"]))
                continue
            if item["op"] != "start" or agent_id in workers:
                raise ValueError("unexpected agent operation")
            log = path / f"{agent_id}.jsonl"
            error = path / f"{agent_id}.stderr"
            audit = path / f"{agent_id}.db"
            with log.open("ab") as out, error.open("ab") as err:
                workers[agent_id] = subprocess.Popen(
                    [sys.executable, str(ROOT / "scripts/phase4a_worker.py"),
                     "--id", agent_id, "--broker-port", str(ports[0]),
                     "--coordinator-port", str(ports[1 + item["coordinator"]]),
                     "--config", str(configs[item["policy"]]), "--audit", str(audit),
                     "--delay", str(item["delay"])], env=env, stdin=subprocess.DEVNULL,
                    stdout=out, stderr=err)
            logs[agent_id] = (log, 0)
    finally:
        if sampler is not None:
            sampler.cancel()
            await asyncio.gather(sampler, return_exceptions=True)
        for process in workers.values():
            if process.poll() is None:
                process.send_signal(signal.SIGCONT)
                process.terminate()
        deadline = time.monotonic() + 15
        while any(process.poll() is None for process in workers.values()) and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        for process in workers.values():
            if process.poll() is None:
                process.kill()
                process.wait()
        for server in servers:
            server.close()
            await server.wait_closed()
        try:
            while any(log.stat().st_size > offset for log, offset in logs.values()):
                previous = sum(offset for _, offset in logs.values())
                drain()
                if previous == sum(offset for _, offset in logs.values()):
                    break
            for agent_id in workers:
                audit = path / f"{agent_id}.db"
                if audit.is_file():
                    with audit.open("rb") as stream:
                        while data := stream.read(32 * 1024):
                            send("audit", id=agent_id, data=base64.b64encode(data).decode())
        finally:
            shutil.rmtree(path)


class Peer:
    def __init__(self, target, count, state, process, log_dir):
        self.target = target
        self.count = count
        self.state = state
        self.process = process
        self.log_dir = log_dir
        self.status = {}
        self.platform = None
        self.receiver = asyncio.create_task(self.receive())

    @classmethod
    async def start(cls, target, count, remote_root, remote_python, broker, coordinators, trust, configs, log_dir):
        base = ssh()
        prepared = await asyncio.create_subprocess_exec(
            *base, target, "mktemp -d /tmp/aegis-p4a.XXXXXXXX", stdout=asyncio.subprocess.PIPE)
        async with asyncio.timeout(15):
            raw, _ = await prepared.communicate()
        state = raw.decode().strip()
        if prepared.returncode or not PEER_STATE.fullmatch(state):
            raise RuntimeError("could not prepare peer state directory")
        forwards = ["-R", f"{state}/n.sock:127.0.0.1:{broker}"]
        for index, port in enumerate(coordinators):
            forwards.extend(("-R", f"{state}/c{index}.sock:127.0.0.1:{port}"))
        script = str(Path(remote_root) / "scripts" / "phase4a_peer.py")
        python_path = str(Path(remote_root) / "src")
        argv = ["env", f"PYTHONPATH={python_path}", remote_python, script, state]
        with (log_dir / "ssh.stderr").open("ab") as err:
            process = await asyncio.create_subprocess_exec(
                *base, *forwards, target, shlex.join(argv), stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=err)
        peer = cls(target, count, state, process, log_dir.parent)
        try:
            peer.write({"fingerprint": fingerprint(), "publishers": trust,
                        "configs": configs, "coordinators": len(coordinators)})
            async with asyncio.timeout(20):
                while peer.platform is None:
                    if peer.receiver.done():
                        await peer.receiver
                        raise RuntimeError("peer exited before startup")
                    await asyncio.sleep(0.1)
        except BaseException:
            with suppress(Exception):
                await peer.stop()
            raise
        return peer

    def write(self, item):
        self.process.stdin.write(json.dumps(item).encode() + b"\n")

    async def receive(self):
        async for line in self.process.stdout:
            row = json.loads(line)
            observed = time.perf_counter_ns()
            kind = row["kind"]
            if kind == "ready":
                self.platform = row
                continue
            agent_id = row["id"]
            if agent_id not in self.status:
                raise ValueError("peer reported a deployment outside this run")
            folder = self.log_dir / agent_id
            if kind == "exit":
                self.status[agent_id] = row["status"]
            elif kind == "trace":
                data = base64.b64decode(row["data"], validate=True)
                with (folder / "trace.jsonl").open("ab") as stream:
                    for record in data.splitlines():
                        trace = json.loads(record) | {"controller_observed_ns": observed}
                        stream.write(json.dumps(trace, separators=(",", ":")).encode() + b"\n")
            elif kind == "audit":
                with (folder / "audit.db").open("ab") as stream:
                    stream.write(base64.b64decode(row["data"], validate=True))
            else:
                raise ValueError("unsupported peer telemetry record")

    def start_agent(self, agent_id, index, coordinators, delay):
        self.status[agent_id] = None
        self.write({"op": "start", "id": agent_id, "policy": index % 10,
                    "coordinator": index % coordinators, "delay": delay})
        return RemoteProcess(self, agent_id)

    async def stop(self):
        try:
            if self.process.returncode is None:
                self.write({"op": "stop"})
                self.process.stdin.close()
            async with asyncio.timeout(90):
                await self.receiver
                code = await self.process.wait()
            if code != 0:
                raise RuntimeError(f"SSH lab worker exited with status {code}")
        finally:
            if self.process.returncode is None:
                self.process.kill()
                await self.process.wait()
            # State is normally removed by the peer. Remove any original
            # private directory left after a failed bootstrap.
            cleanup = await asyncio.create_subprocess_exec(
                *ssh(), self.target, shlex.join(["rm", "-rf", "--", self.state]),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            async with asyncio.timeout(15):
                await cleanup.wait()


class RemoteProcess:
    def __init__(self, peer, agent_id):
        self.peer = peer
        self.agent_id = agent_id

    def poll(self):
        if self.peer.receiver.done():
            return self.peer.process.returncode or 1
        return self.peer.status[self.agent_id]

    def send_signal(self, sig):
        self.peer.write({"op": "signal", "id": self.agent_id, "signal": sig.name})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path)
    asyncio.run(serve(parser.parse_args().state))
