"""Deterministic disposable-file regression for publisher grant intake."""

import base64
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis.intelligence_adapter as adapter
from aegis.config import load_publishers, load_publishers_bytes
from aegis.local_observer import ObservationError


def feed(tmp_path):
    path = tmp_path / "mesh.json"
    path.write_text('{"adapter_version":"mesh-events-v1","events":[]}')
    return path


def grant(roles=("finding",), scope=None, revoked_at=None):
    key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    entry = {"publisher_id": "publisher", "key_id": "key-1",
             "public_key": base64.b64encode(key).decode(), "roles": list(roles),
             "not_before": "2020-01-01T00:00:00+00:00",
             "expires_at": "2035-01-01T00:00:00+00:00", "revoked_at": revoked_at}
    if scope is not None:
        entry["revocation_publishers"] = scope
    return {"grants": [entry]}


def test_grant_replacement_cannot_bypass_one_megabyte_limit(tmp_path, monkeypatch):
    source = feed(tmp_path)
    trust = tmp_path / "trust.json"
    trust.write_text('{"grants":[]}')
    original = adapter.os.open

    def replace_before_open(path, flags, *args, **kwargs):
        if path == trust.name:
            replacement = tmp_path / "new.json"
            replacement.write_text(json.dumps({"grants": [], "padding": "x" * (1024 * 1024)}))
            replacement.replace(trust)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(adapter.os, "open", replace_before_open)
    with pytest.raises(ObservationError, match="limit"):
        adapter.load_intelligence(source, trust_path=trust)


def test_replacement_after_open_is_rejected(tmp_path, monkeypatch):
    source = feed(tmp_path)
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(grant()))
    original_open = adapter.os.open

    def replace_after_open(path, flags, *args, **kwargs):
        fd = original_open(path, flags, *args, **kwargs)
        if path == trust.name:
            def swap():
                replacement = tmp_path / "new.json"
                replacement.write_text(json.dumps(grant(("revocation",), ["other"])))
                replacement.replace(trust)
            writer = threading.Thread(target=swap)
            writer.start()
            writer.join()
        return fd

    monkeypatch.setattr(adapter.os, "open", replace_after_open)
    with pytest.raises(ObservationError, match="path changed"):
        adapter.load_intelligence(source, trust_path=trust)


def test_in_place_mutation_during_read_is_rejected(tmp_path, monkeypatch):
    source = feed(tmp_path)
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(grant()))
    original_fstat = adapter.os.fstat
    changed = False

    def mutate_after_first_stat(fd):
        nonlocal changed
        meta = original_fstat(fd)
        if not changed and meta.st_ino == trust.stat().st_ino and meta.st_dev == trust.stat().st_dev:
            changed = True
            writer = threading.Thread(target=lambda: trust.write_text(
                json.dumps(grant(("revocation",), ["other"]))))
            writer.start()
            writer.join()
        return meta

    monkeypatch.setattr(adapter.os, "fstat", mutate_after_first_stat)
    with pytest.raises(ObservationError, match="changed during read"):
        adapter.load_intelligence(source, trust_path=trust)


def test_symlinks_traversal_and_nonregular_grants_fail_closed(tmp_path):
    source = feed(tmp_path)
    real = tmp_path / "real.json"
    real.write_text('{"grants":[]}')
    link = tmp_path / "link.json"
    link.symlink_to(real)
    directory = tmp_path / "directory"
    directory.mkdir()
    (directory / "trust.json").write_text('{"grants":[]}')
    dir_link = tmp_path / "dir-link"
    dir_link.symlink_to(directory, target_is_directory=True)
    paths = [link, dir_link / "trust.json", directory / ".." / "real.json", directory]
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        paths.append(fifo)
    for path in paths:
        with pytest.raises(ObservationError):
            adapter.load_intelligence(source, trust_path=path)


def test_group_writable_grant_is_rejected(tmp_path):
    source = feed(tmp_path)
    trust = tmp_path / "trust.json"
    trust.write_text('{"grants":[]}')
    trust.chmod(0o664)
    with pytest.raises(ObservationError, match="unsafe owner or write permissions"):
        adapter.load_intelligence(source, trust_path=trust)


def test_shared_parser_old_new_equivalence_and_invalid_grants(tmp_path):
    key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    cases = [{"legacy": base64.b64encode(key).decode()},
             grant(("finding", "revocation"), ["publisher"]),
             grant(("revocation",), ["other"]),
             grant(revoked_at="2021-01-01T00:00:00+00:00"),
             {"grants": grant()["grants"] * 2},
             grant(("finding",), ["other"]),
             {"grants": [{**grant()["grants"][0], "unexpected": True}]},
             {"grants": [{**grant()["grants"][0], "expires_at": "2010-01-01T00:00:00+00:00"}]}]
    now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    for case in cases:
        raw = json.dumps(case).encode()
        path = tmp_path / "trust.json"
        path.write_bytes(raw)
        outcomes = []
        for loader in (lambda: load_publishers(str(path)), lambda: load_publishers_bytes(raw)):
            try:
                store = loader()
                scopes = []
                for publisher, key_id in sorted(store.grants):
                    for role, target in (("finding", None), ("revocation", "publisher"),
                                         ("revocation", "other")):
                        try:
                            if target is None:
                                store.authorize(publisher, key_id, role, now)
                            else:
                                store.authorize_revocation(publisher, key_id, target, now)
                            scopes.append(True)
                        except ValueError:
                            scopes.append(False)
                outcomes.append((sorted(store.grants), scopes))
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                outcomes.append((type(exc), str(exc)))
        assert outcomes[0] == outcomes[1]
