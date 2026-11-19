from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID
import pytest

from aegis.evidence.records import canonical
from aegis.identity_lab.protocol import Enrollment, Workload, principal
from aegis.identity_lab.services import initialize
from aegis.identity_lab.transport import Client, Credentials, Endpoint, spki


def _private(path, key):
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    path.chmod(0o600)


from docker_rpc import accepts_expired_peer


class Lab:
    def __init__(self, root, *, lease_ns=30_000_000_000):
        self.root = root
        self.ca_key = Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Disposable Phase 4E CA")])
        self.ca = (self.builder(self.ca_key, subject, subject, 86_400)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                                  critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                                  critical=False)
                   .sign(self.ca_key, None))
        self.brokers = ("broker-a", "broker-b")
        self.targets = ("target-a", "target-b")
        self.agents = ("agent-a", "agent-b")
        self.services = ("anchor", "home", *self.brokers, *self.targets)
        self.processes = {}
        self.instances = {agent: Ed25519PrivateKey.generate() for agent in self.agents}
        self.approval = Ed25519PrivateKey.generate()
        tls_keys = {agent: Ed25519PrivateKey.generate() for agent in self.agents}
        rotated_key = Ed25519PrivateKey.generate()
        self.policy = Enrollment(
            deployment=str(uuid4()), brokers=self.brokers, targets=self.targets,
            workloads={agent: Workload(instance_key=self.instances[agent].public_key().public_bytes_raw().hex(),
                                       tls_keys=(spki(key.public_key()), spki(rotated_key.public_key()))
                                       if agent == "agent-a" else (spki(key.public_key()),))
                       for agent, key in tls_keys.items()},
            approval_key=self.approval.public_key().public_bytes_raw().hex(),
            lease_ns=lease_ns,
        )
        self.endpoints = self.addresses()
        for name in (*self.services, *self.agents, "operator", "observer"):
            self.issue(name, name, key=tls_keys.get(name))
        self.issue("lookalike", "agent-a")
        self.issue("expired", "agent-a", key=tls_keys["agent-a"], ttl=-60)
        self.issue("rotated", "agent-a", key=rotated_key)
        for role in self.services:
            config = self.root / role
            (config / "enrollment.json").write_text(self.policy.model_dump_json())
            (config / "endpoints.json").write_text(json.dumps({
                name: {"host": endpoint.host, "port": endpoint.port}
                for name, endpoint in self.endpoints.items()
            }))
        for role in ("anchor", "home", *self.targets):
            path = self.database(role)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            initialize(path, role, self.policy)

    def open(self):
        pass

    def close(self):
        for name in tuple(self.processes):
            self.stop(name)

    def addresses(self):
        with_sockets = []
        try:
            for role in self.services:
                sock = socket.socket()
                with_sockets.append(sock)
                sock.bind(("127.0.0.1", 0))
            return {
                role: Endpoint("127.0.0.1", sock.getsockname()[1], role)
                for role, sock in zip(self.services, with_sockets, strict=True)
            }
        finally:
            for sock in with_sockets:
                sock.close()

    @staticmethod
    def builder(key, subject, issuer, ttl):
        now = datetime.now(timezone.utc)
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=10)).not_valid_after(now + timedelta(seconds=ttl)))

    def issue(self, directory, name, *, key=None, ttl=3600):
        path = self.root / directory
        path.mkdir(mode=0o700, exist_ok=True)
        key = key or Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
        leaf = (self.builder(key, subject, self.ca.subject, ttl)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                               critical=True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                               critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(principal(name))]),
                               critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                                      ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.ca_key, None))
        _private(path / "key.pem", key)
        (path / "cert.pem").write_bytes(leaf.public_bytes(Encoding.PEM))
        (path / "ca.pem").write_bytes(self.ca.public_bytes(Encoding.PEM))

    def database(self, name):
        return self.root / name / "state.sqlite"

    def start(self, name):
        here = Path(__file__).resolve().parents[2]
        config = self.root / name
        log = config / "service.log"
        with log.open("ab") as stream:
            process = subprocess.Popen(
                [sys.executable, "-m", "aegis.identity_lab", "serve", name, str(config), str(config)],
                stdout=stream, stderr=stream, env=os.environ | {"PYTHONPATH": str(here / "src")},
            )
        self.processes[name] = process
        endpoint = self.endpoints[name]
        until = monotonic() + 5
        while monotonic() < until:
            if process.poll() is not None:
                raise RuntimeError(log.read_text())
            try:
                with socket.create_connection((endpoint.host, endpoint.port), timeout=0.1):
                    return
            except OSError:
                sleep(0.015)
        raise RuntimeError(f"{name} did not start: {log.read_text()}")

    def stop(self, name):
        process = self.processes.pop(name)
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def partition(self, name):
        self.stop(name)

    def heal(self, name):
        self.start(name)

    def client(self, name):
        return Client(Credentials(self.root / name))

    def expired_peer_accepted(self, service, body):
        return accepts_expired_peer(self.root / "expired", self.endpoints[service], canonical(body))

    def call(self, caller, service, path, body=None):
        return self.client(caller).call(self.endpoints[service], path, body)


@pytest.fixture
def lab(request):
    if os.getenv("AEGIS_PHASE4E_LIVE") != "1":
        pytest.skip("credentialed disposable mTLS tests require AEGIS_PHASE4E_LIVE=1")
    lease_ns = getattr(request, "param", 30_000_000_000)
    if os.getenv("AEGIS_PHASE4E_TOPOLOGY", "loopback") == "docker":
        from docker_lab import DockerLab

        # Colima bind mounts the workspace. Keep role material out of git.
        scratch = Path(__file__).resolve().parents[2] / ".venv"
        scratch.mkdir(exist_ok=True)
        with TemporaryDirectory(dir=scratch, prefix="identity-lab-") as path:
            with running(DockerLab(Path(path), lease_ns=lease_ns)) as scenario:
                yield scenario
    else:
        with TemporaryDirectory(dir=request.getfixturevalue("tmp_path")) as path:
            with running(Lab(Path(path), lease_ns=lease_ns)) as scenario:
                yield scenario


@contextmanager
def running(lab):
    try:
        lab.open()
        for service in lab.services:
            lab.start(service)
        yield lab
    finally:
        lab.close()
