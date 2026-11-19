"""Individually configured HTTP roles on private Unix sockets for the disposable lab."""

import argparse
from datetime import datetime, timezone
import hmac
import json
import os
from pathlib import Path
import sqlite3
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import Field
import httpx
import uvicorn

from ..artifact import StrictModel
from ..evidence.records import Grant, Trust
from ..journal.protocol import Clock, Hash, Head, JournalBlocked, SignedHead, Vote, canonical, sign_head
from ..journal.storage import SQLitePin
from ..trust import PublisherGrant
from .history import Archive, Witness, make_tree
from .protocol import (Authority, Challenge, Leaf, MAX_RECORDS, SignedStatus, Snapshot, TrustPolicy, View, Wire)
from .status import Publisher, Reader

MAX_BODY = 6 * 1024 * 1024


class Credential(StrictModel, frozen=True):
    token: Hash
    permissions: tuple[str, ...]
    # Admission tokens additionally bind the native issuer and signing key ID.
    principal: tuple[str, str, str] | None = None


class PinUpdate(StrictModel, frozen=True):
    expected: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})+$", max_length=8192)]
    value: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})+$", max_length=8192)]


class Endpoint:
    def __init__(self, socket, token, timeout=1.0):
        self.client = httpx.Client(transport=httpx.HTTPTransport(uds=socket, retries=0),
                                   base_url="http://phase4e.local", timeout=timeout, trust_env=False,
                                   headers={"Authorization": "Bearer " + token})

    def close(self):
        self.client.close()

    def call(self, path, model=None, data=None):
        try:
            method = "POST" if data is not None else "GET"
            with self.client.stream(method, path, content=canonical(data) if data is not None else None) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BODY:
                        raise OSError("Phase 4E response exceeds allowance")
        except httpx.HTTPError as exc:
            raise OSError(f"Phase 4E endpoint {path} unavailable: {exc}") from exc
        return model.model_validate_json(body) if model else json.loads(body)

    def view(self, challenge):
        return self.call("/view", View, challenge)

    def snapshot(self, size):
        return self.call(f"/snapshot/{size}", Snapshot)

    def status(self, challenge):
        return self.call("/status", SignedStatus, challenge)


class RemotePin:
    def __init__(self, endpoint, namespace):
        self.endpoint, self.path = endpoint, f"/pins/{namespace}"

    def read(self):
        return bytes.fromhex(self.endpoint.call(self.path))

    def advance(self, expected, value):
        self.endpoint.call(self.path, data=PinUpdate(expected=expected.hex(), value=value.hex()))


def public(value):
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))


def load_policy(config):
    def authority(value):
        return Authority(value["domain"], public(value["key"]))

    def parse_time(seconds):
        return datetime.fromtimestamp(seconds, timezone.utc)

    mesh = []
    mesh_domains = {}
    for row in config["mesh"]:
        publisher, key_id = row["publisher_id"], row["key_id"]
        mesh_domains[publisher, key_id] = row["domain"]
        mesh.append(PublisherGrant(
            publisher, key_id, public(row["public_key"]), frozenset(row["roles"]),
            parse_time(row["not_before"]), parse_time(row["expires_at"]),
            parse_time(row["revoked_at"]) if row.get("revoked_at") is not None else None,
            frozenset(row["revocation_publishers"]),
        ))
    evidence = [Grant(
        row["issuer"], row["key_id"], row["organization"], row["role"], public(row["public_key"]),
        frozenset(row["cohorts"]), row["not_before"], row["expires_at"],
        frozenset(row["withdrawal_issuers"]), frozenset(row["withdrawal_kinds"]),
    ) for row in config["evidence"]]
    return TrustPolicy(
        stream=config["stream"], cohort=config["cohort"], coordinator=authority(config["coordinator"]),
        publisher=authority(config["publisher"]), witnesses={
            name: authority(witness) for name, witness in config["witnesses"].items()
        }, quorum=config["quorum"], faults=config["faults"], epoch_seconds=config["epoch_seconds"],
        max_age=config["max_age"], status_ms=config["status_ms"], mesh_grants=mesh,
        mesh_domains=mesh_domains, trust=Trust(evidence),
    )


def endpoint(config):
    return Endpoint(**config)


def archive_sources(config):
    return tuple(endpoint(remote).snapshot for remote in config["archives"])


def reader_from_config(config, policy, clock):
    return Reader(policy, {name: endpoint(remote).view for name, remote in config["witnesses"].items()},
                  archive_sources(config), pin_from_config(config), clock)


def pin_from_config(config):
    return RemotePin(endpoint(config["anchor"]), config["namespace"])


def private(config):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(config["private_key"]))


def create_app(config):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    credentials = tuple(Credential.model_validate_json(canonical(value)) for value in config["credentials"])
    if len({credential.token for credential in credentials}) != len(credentials):
        raise ValueError("service credentials must be distinct")

    def auth(request, permission):
        header = request.headers.get("Authorization", "")
        if not header.isascii():
            raise PermissionError("invalid credential")
        for credential in credentials:
            if hmac.compare_digest(header, "Bearer " + credential.token):
                if permission in credential.permissions:
                    return credential
                break
        raise PermissionError("credential lacks required operation")

    async def body(request, model):
        wire = bytearray()
        async for chunk in request.stream():
            wire.extend(chunk)
            if len(wire) > MAX_BODY:
                raise HTTPException(413, "request exceeds prototype limit")
        value = model.model_validate_json(wire)
        if wire != canonical(value):
            raise ValueError("request body must use canonical encoding")
        return value

    @app.exception_handler(PermissionError)
    async def forbidden(_, exc):
        return Response(canonical({"detail": str(exc)}), status_code=403, media_type="application/json")

    @app.exception_handler(JournalBlocked)
    @app.exception_handler(OSError)
    @app.exception_handler(ValueError)
    @app.exception_handler(sqlite3.Error)
    async def blocked(_, exc):
        return Response(canonical({"detail": str(exc)}), status_code=409, media_type="application/json")

    role = config["role"]
    if role == "anchor":
        @app.get("/pins/{namespace}")
        async def read_pin(namespace: str, request: Request):
            auth(request, f"pin:{namespace}")
            return SQLitePin(Path(config["db"]), namespace).read().hex()

        @app.post("/pins/{namespace}")
        async def update_pin(namespace: str, request: Request):
            auth(request, f"pin:{namespace}")
            update = await body(request, PinUpdate)
            SQLitePin(Path(config["db"]), namespace).advance(bytes.fromhex(update.expected),
                                                             bytes.fromhex(update.value))
            return True

        return app

    policy = load_policy(config["policy"])
    clock = Clock(error=config.get("clock_error", 0.0))
    if role == "witness":
        witness = Witness(config["name"], private(config), policy, clock, Path(config["db"]),
                          pin_from_config(config), archive_sources(config))

        @app.post("/admit")
        async def admit(request: Request):
            credential = auth(request, "admit")
            wire = await body(request, Wire)
            admission, _ = witness.admit(wire, credential.principal)
            return witness.recover(admission.event, admission.epoch)

        @app.get("/receipts/{epoch}/{event}")
        async def receipt(epoch: int, event: Hash, request: Request):
            auth(request, "receipt")
            return witness.recover(event, epoch)

        @app.post("/seal")
        async def seal(request: Request) -> Vote:
            auth(request, "seal")
            return witness.seal(await body(request, SignedHead))

        @app.post("/view")
        async def view(request: Request):
            auth(request, "view")
            return witness.view(await body(request, Challenge))

    elif role == "archive":
        archive = Archive(Path(config["db"]), policy)

        @app.post("/append")
        async def append(request: Request):
            auth(request, "append")
            return archive.append(await body(request, Leaf))

        @app.get("/snapshot/{size}")
        async def snapshot(size: int, request: Request):
            auth(request, "snapshot")
            if not 0 <= size <= MAX_RECORDS:
                raise ValueError("snapshot size is outside the lab limit")
            return archive.snapshot(size)

        @app.get("/proof/{size}/{index}")
        async def proof(size: int, index: int, request: Request):
            auth(request, "snapshot")
            if not 0 <= index < size <= MAX_RECORDS:
                raise ValueError("proof coordinates are outside the lab limit")
            tree = make_tree(archive.snapshot(size))
            return tuple(node.hex() for node in tree.inclusion(index, size))

    elif role == "checkpoint":
        key = private(config)
        if key.public_key() != policy.journal.coordinator:
            raise ValueError("checkpoint key does not match pinned enrollment")

        @app.post("/propose")
        async def propose(request: Request):
            auth(request, "propose")
            head = await body(request, Head)
            if head.context != policy.context or head.size > MAX_RECORDS:
                raise JournalBlocked("checkpoint is outside its enrolled stream")
            policy.journal.deadline(head, clock.sample())
            return sign_head(key, head)

    elif role == "publisher":
        publisher = Publisher(reader_from_config(config, policy, clock), private(config))

        @app.post("/status")
        async def status(request: Request):
            credential = auth(request, "status")
            challenge = await body(request, Challenge)
            if f"audience:{challenge.subject.audience}" not in credential.permissions:
                raise PermissionError("credential lacks the requested status audience")
            return publisher.publish(challenge)

    else:
        raise ValueError("unknown Phase 4E service role")
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(args.config.read_text())
    socket = Path(config["socket"])
    if socket.exists():
        raise FileExistsError("service socket already exists")
    if socket.parent.stat().st_mode & 0o077:
        raise PermissionError("service socket parent must be private")
    uvicorn.run(create_app(config), uds=str(socket), log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
