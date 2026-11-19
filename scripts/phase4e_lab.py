"""Provision and exercise disposable Phase 4E-C processes on private Unix sockets."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence as Reference
from aegis.artifact import Finding, Revocation, Software, sign, sign_revocation
from aegis.evidence.records import Withdrawal, sign_record
from aegis.evidence.runner import ENVIRONMENT_SHA256
from aegis.evidence.status_protocol import observe
from aegis.evidence.synthetic import create_lab
from aegis.journal.client import finding_target
from aegis.journal.protocol import (Clock, Cut, Head, JournalBlocked, SignedHead, Vote, canonical, digest)
from aegis.journal.storage import EMPTY_CHAIN, SQLitePin
from aegis.journal.witness import collect_receipt
from aegis.phase3c import COHORT, MESH_TEMPLATE, PACKAGE, REFERENCE, VERSION, claim_bytes
from aegis.phase4e.history import make_tree
from aegis.phase4e.protocol import Floor, Leaf, MAX_RECORDS, Wire
from aegis.phase4e.service import Endpoint, RemotePin, load_policy
from aegis.phase4e.status import Gate, Reader, finding_wire


def public(key):
    return key.public_key().public_bytes_raw().hex()


def grants(lab):
    for grant in lab.trust.grants.values():
        row = {}
        for field in fields(grant):
            value = getattr(grant, field.name)
            if field.name == "public_key":
                value = value.public_bytes_raw().hex()
            elif isinstance(value, frozenset):
                value = sorted(value)
            row[field.name] = value
        yield row


class Lab:
    def __init__(self, path, *, retirement=3600, status_ms=3000):
        path.mkdir(mode=0o700, exist_ok=True)
        self.path, self.stack = path, ExitStack()
        self.configs, self.processes = {}, {}
        self.keys = {name: Ed25519PrivateKey.generate() for name in
                     ("cp", "status", "mesh", "old", "new", "evidence-new", "w0", "w1", "w2", "w3")}
        self.names = ("w0", "w1", "w2", "w3")
        self.evidence = create_lab(int(time.time()) - 1)
        start = self.evidence.now - 10
        self.retired = int(time.time()) + retirement

        def mesh(name, issuer, role, until, since=start):
            return {"publisher_id": issuer, "key_id": name, "public_key": public(self.keys[name]),
                    "roles": [role], "not_before": since, "expires_at": until,
                    "domain": "mesh-author" if role == "finding" else "mesh-revocation",
                    "revocation_publishers": ["author"] if role == "revocation" else []}

        evidence_grants = list(grants(self.evidence))
        revoker = next(grant for grant in evidence_grants if grant["role"] == "revoker")
        revoker["expires_at"] = self.retired
        evidence_grants.append(revoker | {
            "key_id": "lab-v2", "public_key": public(self.keys["evidence-new"]),
            "not_before": self.retired, "expires_at": self.evidence.now + 7200,
        })
        self.config = {
            "stream": "phase4e-local", "cohort": COHORT,
            "coordinator": {"key": public(self.keys["cp"]), "domain": "checkpoint-org"},
            "publisher": {"key": public(self.keys["status"]), "domain": "status-org"},
            "witnesses": {name: {"key": public(self.keys[name]), "domain": f"{name}-org"} for name in self.names},
            "quorum": 3, "faults": 1, "epoch_seconds": 2, "max_age": 20, "status_ms": status_ms,
            "mesh": [mesh("mesh", "author", "finding", self.evidence.now + 7200),
                     mesh("old", "mesh-review", "revocation", self.retired),
                     mesh("new", "mesh-review", "revocation", self.evidence.now + 7200, self.retired)],
            "evidence": evidence_grants,
        }
        self.policy = load_policy(self.config)
        self.epoch_width = self.policy.journal.epoch_seconds
        self.services = ("anchor", "arc", "mirror", "cp", *self.names, "status")
        for name in self.services:
            self.configs[name] = {"socket": str(path / f"{name}.sock"),
                                  "db": str(path / f"{name}.db"), "policy": self.config,
                                  "credentials": []}
        self.set_role("anchor", "anchor")
        self.order = self.credential("cp", "propose")
        self.set_role("cp", "checkpoint")
        for name in ("arc", "mirror"):
            self.set_role(name, "archive")
        self.arcs = tuple(self.credential(name, "snapshot", "append") for name in ("arc", "mirror"))
        for name in self.names:
            self.set_role(name, "witness", name=name, anchor=self.anchor(name, EMPTY_CHAIN),
                          namespace=name, archives=[self.credential(archive, "snapshot")
                                                    for archive in ("arc", "mirror")])
        self.admin = {name: self.credential(name, "seal", "receipt") for name in self.names}
        self.admission = {}
        for role, issuer, key in (("publish", "author", "mesh"), ("revoke", "mesh-review", "old"),
                                  ("revoke", "mesh-review", "new"), ("publish", "research", "lab-v1"),
                                  ("verify", "verifier-a", "lab-v1"), ("verify", "verifier-b", "lab-v1"),
                                  ("revoke", "review", "lab-v1"), ("revoke", "review", "lab-v2")):
            self.admission[issuer, key] = {name: self.credential(name, "admit", principal=(role, issuer, key))
                                           for name in self.names}
        self.set_role("status", "publisher", **self.reader_config("status"))
        self.reader_settings = self.reader_config("writer")
        self.status_remote = self.credential("status", "status", "audience:lab-writer")
        self.publisher = self.connect(self.status_remote)
        self.archive = tuple(self.connect(remote) for remote in self.arcs)
        self.coordinator = self.connect(self.order)
        self.operators = {name: self.connect(remote) for name, remote in self.admin.items()}
        self.admissions = {actor: {name: self.connect(remote) for name, remote in remotes.items()}
                           for actor, remotes in self.admission.items()}
        self.reader = self.new_reader()
        self.gate = Gate(self.reader, self.publisher.status, "lab-writer")

    def set_role(self, service, role, **fields):
        config = self.configs[service]
        config.update(role=role, **fields)
        if service in self.keys:
            config["private_key"] = self.keys[service].private_bytes_raw().hex()

    def credential(self, service, *permissions, principal=None):
        token = secrets.token_hex(32)
        config = self.configs[service]
        config["credentials"].append({"token": token, "permissions": permissions, "principal": principal})
        return {"socket": config["socket"], "token": token}

    def anchor(self, namespace, value):
        SQLitePin(self.path / "anchor.db", namespace).provision(value)
        return self.credential("anchor", f"pin:{namespace}")

    def reader_config(self, namespace):
        return {"anchor": self.anchor(namespace, canonical(Floor(context=self.policy.context))),
                "namespace": namespace, "archives": [self.credential(archive, "snapshot")
                                                       for archive in ("arc", "mirror")],
                "witnesses": {name: self.credential(name, "view") for name in self.names}}

    def connect(self, remote):
        endpoint = Endpoint(**remote)
        self.stack.callback(endpoint.close)
        return endpoint

    def new_reader(self):
        config = self.reader_settings
        return Reader(self.policy, {name: self.connect(remote).view for name, remote in config["witnesses"].items()},
                      tuple(self.connect(remote).snapshot for remote in config["archives"]),
                      RemotePin(self.connect(config["anchor"]), config["namespace"]), Clock())

    def __enter__(self):
        for name, config in self.configs.items():
            with open(self.path / f"{name}.json", "x", opener=_private) as file:
                json.dump(config, file)
        try:
            self.start("anchor")
            for name in self.services[1:]:
                self.start(name, wait=False)
            for name in self.services[1:]:
                self.ready(name)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_):
        for name in reversed(self.services):
            if name in self.processes:
                self.stop(name)
        self.stack.close()

    def start(self, name, wait=True):
        log = self.path / f"{name}.log"
        with log.open("ab") as output:
            self.processes[name] = subprocess.Popen(
                [sys.executable, "-m", "aegis.phase4e.service", str(self.path / f"{name}.json")],
                stdout=output, stderr=output,
            )
        if wait:
            self.ready(name)

    def ready(self, name):
        proc = self.processes[name]
        socket = Path(self.configs[name]["socket"])
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            if socket.exists():
                return
            time.sleep(0.02)
        raise RuntimeError(f"{name} startup failed: {(self.path / f'{name}.log').read_text()}")

    def stop(self, name):
        proc = self.processes.pop(name)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        Path(self.configs[name]["socket"]).unlink(missing_ok=True)

    def fixture(self, sequence=1):
        now = datetime.now(timezone.utc)
        body = Finding(schema_version="1.0", artifact_id=uuid4(), publisher_id="author", sequence=sequence,
                       issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(hours=1),
                       vulnerability_id="PHASE4E-DISPOSABLE-FIXTURE",
                       software=Software(purl=PACKAGE, affected_versions=[VERSION]),
                       evidence=[Reference(uri="urn:fixture", sha256="0" * 64, method="lab-reproduction")],
                       applicability="authorized-lab", mitigation_template=MESH_TEMPLATE)
        bundle = self.evidence.bundle(claim_bytes(body).decode(), family="route-toggle", cohort=COHORT)
        body = body.model_copy(update={"evidence": [
            Reference(uri=REFERENCE + bundle.sha256, sha256=bundle.sha256, method="lab-reproduction"),
        ]})
        return sign(body, self.keys["mesh"], "mesh"), bundle

    def receive(self, wire, actor, names=None):
        names = names or self.names
        with ThreadPoolExecutor(max_workers=len(names)) as pool:
            for attempt in range(3):
                responses = tuple(pool.map(lambda name: self.admissions[actor][name].call("/admit", Leaf, wire),
                                           names))
                try:
                    receipt = collect_receipt(self.policy.journal, (
                        (leaf.receipt.admission, leaf.receipt.votes[0]) for leaf in responses
                    ))
                except JournalBlocked:
                    if attempt == 2:
                        raise
                    continue
                assert receipt.admission.event == digest(wire)
                return Leaf(wire=wire, receipt=receipt)

    def append(self, leaf, indexes=(0, 1)):
        return tuple(self.archive[index].call("/append", data=leaf) for index in indexes)

    def seed(self):
        finding, bundle = self.fixture()
        manifest = self.receive(Wire.from_bytes("evidence", bundle.manifest), ("research", "lab-v1"))
        self.append(manifest)
        for verifier in self.evidence.verifiers:
            wire = observe(self.policy, verifier, bundle, clock=time.time)
            self.append(self.receive(Wire.from_bytes("evidence", wire), (verifier.issuer, verifier.key_id)))
        self.append(self.receive(finding_wire(finding), ("author", "mesh")))
        return finding, bundle

    def propose(self, epoch, index=0):
        remaining = self.policy.journal.cutoff(epoch) - time.time()
        if remaining > 0:
            time.sleep(remaining + 0.02)
        tree = make_tree(self.archive[index].snapshot(MAX_RECORDS))
        return self.coordinator.call("/propose", SignedHead, Head(
            context=self.policy.context, epoch=epoch, size=tree.size, root=tree.root(tree.size).hex(),
        ))

    def seal(self, signed, names=None, *, allow_failure=False):
        names = names or self.names

        def request(name):
            try:
                return self.operators[name].call("/seal", Vote, signed)
            except OSError:
                if not allow_failure:
                    raise
                return None

        with ThreadPoolExecutor(max_workers=len(names)) as pool:
            votes = tuple(v for v in pool.map(request, names) if v is not None)
        return Cut(signed=signed, votes=votes)

    def seal_latest(self):
        return self.seal(self.propose(int(time.time() // self.epoch_width)))

    def status(self, finding, bundle):
        return self.gate.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256)

    def mesh_withdrawal(self, finding, key="old", sequence=1):
        now = datetime.now(timezone.utc)
        publisher, identity, body = finding_target(finding)
        return finding_wire(sign_revocation(Revocation(
            schema_version="1.1", revocation_id=uuid4(), publisher_id="mesh-review", sequence=sequence,
            issued_at=now, expires_at=now + timedelta(minutes=5), target_artifact_id=identity,
            target_sha256=body, target_publisher_id=publisher, reason="withdrawn",
        ), self.keys[key], key))

    def evidence_withdrawal(self, bundle, key="lab-v1"):
        now = int(time.time())
        signing_key = self.evidence.revoker if key == "lab-v1" else self.keys["evidence-new"]
        return Wire.from_bytes("evidence", sign_record(Withdrawal(
            kind="aegis.evidence.withdrawal.v1", issuer="review", key_id=key, cohort=COHORT,
            record_id=uuid4().hex, issued_at=now, expires_at=now + 120, target_kind="bundle",
            target_issuer="research", target_sha256=bundle.sha256, reason="invalid-evidence",
        ), signing_key))


def _private(path, flags):
    return os.open(path, flags, 0o600)
