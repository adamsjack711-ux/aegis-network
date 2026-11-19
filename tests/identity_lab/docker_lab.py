"""Fixture backend with an internal bridge, one service per network namespace."""

import json
import os
from pathlib import Path
import subprocess
from time import monotonic, sleep
from uuid import uuid4

from conftest import Lab

from aegis.identity_lab.protocol import Denied, Unavailable
from aegis.identity_lab.transport import AuthenticationFailed, Endpoint

REPO = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE = "aegis_phase4_baseline-coordinator:latest"


class DockerClient:
    def __init__(self, lab, role):
        self.lab = lab
        self.role = role

    def call(self, endpoint, route, body=None):
        result = self.lab.measure(self.role, endpoint, route, body)
        kind = result["outcome"]
        if kind == "ok":
            return result["result"]
        errors = {"AuthenticationFailed": AuthenticationFailed, "Denied": Denied,
                  "Unavailable": Unavailable}
        raise errors[kind](result["error"])


class DockerLab(Lab):
    def __init__(self, root, **options):
        self.network = "aegis-identity-" + uuid4().hex[:12]
        self.drivers = set()
        self.image = os.getenv("AEGIS_PHASE4E_IMAGE", DEFAULT_IMAGE)
        super().__init__(root, **options)

    @staticmethod
    def docker(*args, check=True, stdin=None):
        result = subprocess.run(["docker", *args], check=False, capture_output=True, text=True,
                                input=stdin, timeout=30)
        if result.returncode and check:
            raise RuntimeError(result.stderr.strip())
        return result.stdout.strip()

    def open(self):
        self.docker("image", "inspect", self.image, "--format", "{{.Id}}")
        self.docker("network", "create", "--internal", self.network)

    def close(self):
        for name in (*self.drivers, *self.processes):
            self.docker("rm", "--force", self.container(name), check=False)
        self.docker("network", "rm", self.network, check=False)

    def addresses(self):
        return {role: Endpoint(role, 8443, role) for role in self.services}

    def database(self, name):
        return self.root / "state" / name / "state.sqlite"

    def container(self, role):
        return self.network + "-" + role

    def run(self, role, credential, network, *command, state=None):
        args = ["run", "--detach", "--pull", "never", "--name", self.container(role),
                "--network", network, "--user", f"{os.getuid()}:{os.getgid()}",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "-e", "PYTHONPATH=/source/src", "-e", "PYTHONDONTWRITEBYTECODE=1",
                "--mount", f"type=bind,source={REPO / 'src'},target=/source/src,readonly",
                "--mount", f"type=bind,source={Path(__file__).with_name('docker_rpc.py')},target=/rpc.py,readonly",
                "--mount", f"type=bind,source={self.root / credential},target=/creds,readonly"]
        if network == self.network:
            args.extend(("--network-alias", role))
        if state is not None:
            args.extend(("--mount", f"type=bind,source={state},target=/state"))
        self.docker(*args, self.image, "python", *command)

    def start(self, name):
        state = self.database(name).parent
        self.run(name, name, self.network, "-m", "aegis.identity_lab", "serve", name,
                 "/creds", "/state", "--bind", "0.0.0.0", state=state if state.exists() else None)
        self.processes[name] = True
        until = monotonic() + 8
        while monotonic() < until:
            ready = self.docker(
                "exec", self.container(name), "python", "-c",
                "import socket; socket.create_connection(('127.0.0.1', 8443), 0.2).close(); print('ready')",
                check=False,
            )
            if ready == "ready":
                return
            sleep(0.05)
        raise RuntimeError(f"{name} did not start: {self.docker('logs', self.container(name))}")

    def stop(self, name):
        self.docker("rm", "--force", self.container(name))
        del self.processes[name]

    def partition(self, name):
        self.docker("network", "disconnect", self.network, self.container(name))

    def heal(self, name):
        self.docker("network", "connect", "--alias", name, self.network, self.container(name))

    def driver(self, role, credential=None, network=None):
        driver = "client-" + role
        if driver not in self.drivers:
            self.run(driver, credential or role, network or self.network, "-c",
                     "from threading import Event; Event().wait()")
            self.drivers.add(driver)
        return driver

    def measure(self, role, endpoint, route, body=None, *, count=1, driver=None):
        runner = driver or (role if role in self.processes else self.driver(role))
        request = {"endpoint": vars(endpoint), "route": route, "count": count,
                   "body": body.model_dump_json() if body else None}
        result = self.docker("exec", "-i", self.container(runner), "python",
                             "/rpc.py", stdin=json.dumps(request))
        return json.loads(result)

    def expired_peer_accepted(self, service, body):
        request = {"endpoint": vars(self.endpoints[service]), "body": body.model_dump_json(),
                   "expired_peer_probe": True}
        output = self.docker("exec", "-i", self.container(self.driver("expired")), "python",
                             "/rpc.py", stdin=json.dumps(request))
        return json.loads(output)["accepted"]

    def client(self, name):
        return DockerClient(self, name)

    def logs(self, name):
        result = subprocess.run(["docker", "logs", self.container(name)], check=True, capture_output=True,
                                text=True, timeout=10)
        return result.stderr.splitlines()
