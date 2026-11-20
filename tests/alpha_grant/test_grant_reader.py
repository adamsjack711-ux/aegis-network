"""Descriptor-level grant race controls; no production test bypass."""

import base64
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import stat
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis.intelligence_adapter as adapter
from aegis.config import load_publishers, load_publishers_bytes
from aegis.local_observer import ObservationError


def _key(seed: int) -> str:
    public = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key()
    return base64.b64encode(public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")


def _grant(seed: int, *, key_id: str = "key-a", roles=("finding",),
           revoked_at=None, scope=None) -> dict:
    result = {
        "publisher_id": "publisher-a", "key_id": key_id, "public_key": _key(seed),
        "roles": list(roles), "not_before": "2026-01-01T00:00:00+00:00",
        "expires_at": "2027-01-01T00:00:00+00:00", "revoked_at": revoked_at,
    }
    if scope is not None:
        result["revocation_publishers"] = list(scope)
    return result


def _json(*grants: dict) -> bytes:
    return json.dumps({"grants": list(grants)}, separators=(",", ":")).encode()


def _snapshot(store):
    return [(key, grant.roles, grant.not_before, grant.expires_at, grant.revoked_at,
             grant.revocation_publishers, grant.public_key.public_bytes(
                 encoding=serialization.Encoding.Raw,
                 format=serialization.PublicFormat.Raw,
             )) for key, grant in sorted(store.grants.items())]


@pytest.mark.parametrize("data", [
    _json(),
    _json(_grant(1)),
    _json(_grant(1, roles=("finding", "revocation"), scope=("publisher-a",))),
    _json(_grant(1, revoked_at="2026-06-01T00:00:00+00:00")),
    _json(_grant(1), _grant(2, key_id="key-b")),
    json.dumps({"publisher-a": _key(1)}).encode(),
    b'{"grants":[],"other":"legacy-accepted"}',
    b'{"grants":[],"grants":[]}',
    b'{"grants":[]}\n',
    b'{"grants":',
    b'\xef\xbb\xbf{"grants":[]}',
    b'\xff{"grants":[]}',
    b'{"grants":[{"publisher_id":"bad"}]}',
    _json(_grant(1), _grant(2)),
])
def test_golden_path_and_bytes_parser_are_equivalent(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "grants.json"
    path.write_bytes(data)
    try:
        old = load_publishers(str(path))
    except Exception as old_error:
        with pytest.raises(type(old_error)):
            load_publishers_bytes(data)
    else:
        assert _snapshot(old) == _snapshot(load_publishers_bytes(data))


def test_golden_role_scope_expiry_and_rotation(tmp_path: Path) -> None:
    data = _json(_grant(1, roles=("finding", "revocation"), scope=("publisher-a",),
                        revoked_at="2026-06-01T00:00:00+00:00"),
                 _grant(2, key_id="key-b"))
    path = tmp_path / "grants.json"
    path.write_bytes(data)
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    for store in (load_publishers(str(path)), load_publishers_bytes(data)):
        assert store.authorize("publisher-a", "key-a", "finding", now)
        assert store.authorize_revocation("publisher-a", "key-a", "publisher-a", now)
        assert store.authorize("publisher-a", "key-b", "finding", now)
        with pytest.raises(ValueError):
            store.authorize_revocation("publisher-a", "key-a", "publisher-b", now)
        with pytest.raises(ValueError):
            store.authorize("publisher-a", "key-a", "finding", datetime(2026, 6, 1, tzinfo=timezone.utc))
        with pytest.raises(ValueError):
            store.authorize("publisher-a", "key-b", "finding", datetime(2027, 1, 1, tzinfo=timezone.utc))


def test_g00_static_signed_fixture_bytes_unchanged() -> None:
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "phase-next-cli"
    expected = {
        "trust.json": "b451c45fef49f0f89fba7512e28aa0cbccf5a55656a9e5f4cb44fe9e807ac0cb",
        "signed-current.json": "9c49dd4b1ba1df9cfee47066f2fbfdc039037234dedd8250a27360d54365f989",
        "signed-withdrawn.json": "543aa0f5f6bfe45fc2ada1cfe8f8550e41da58c9b6d5a47667426425b483f375",
    }
    for name, digest in expected.items():
        assert hashlib.sha256((fixture / name).read_bytes()).hexdigest() == digest
    now = datetime(2026, 11, 20, tzinfo=timezone.utc)
    for name, status in (("signed-current.json", "current"),
                         ("signed-withdrawn.json", "withdrawn")):
        rows = adapter.load_intelligence(fixture / name, trust_path=fixture / "trust.json", now=now)
        assert len(rows) == 1
        assert rows[0].claim_status == status
        assert rows[0].publisher_authenticity == "verified"


def test_f_readable_legacy_modes_and_no_follow(tmp_path: Path) -> None:
    path = tmp_path / "grants.json"
    data = _json(_grant(1))
    for mode in (0o600, 0o644, 0o640, 0o444, 0o400, 0o666, 0o622):
        path.chmod(0o600) if path.exists() else None
        path.write_bytes(data)
        path.chmod(mode)
        assert adapter._read_local_grants(path) == data
    path.chmod(0o600)
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises((OSError, ObservationError)):
        adapter._read_local_grants(alias)
    path.write_bytes(data + b" " * (1024 * 1024 + 1))
    with pytest.raises(ObservationError, match="limit"):
        adapter._read_local_grants(path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ObservationError):
        adapter._read_local_grants(fifo)


def test_f_exact_one_megabyte_boundary(tmp_path: Path) -> None:
    path = tmp_path / "grants.json"
    base = b'{"grants":[],"padding":"'
    end = b'"}'
    path.write_bytes(base + b"x" * (1024 * 1024 - len(base) - len(end)) + end)
    assert len(adapter._read_local_grants(path)) == 1024 * 1024
    assert not load_publishers_bytes(adapter._read_local_grants(path)).grants
    with path.open("ab") as out:
        out.write(b" ")
    with pytest.raises(ObservationError, match="limit"):
        adapter._read_local_grants(path)


def test_r00_path_replacement_after_final_open_keeps_original_inode(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "grants.json"
    path.write_bytes(_json(_grant(1)))
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(_json(_grant(2)))
    original_open = adapter.os.open
    opened = []

    def replace_after_open(name, flags, *args, **kwargs):
        fd = original_open(name, flags, *args, **kwargs)
        if name == path.name:
            opened.append(os.fstat(fd).st_ino)
            os.replace(replacement, path)
        return fd

    monkeypatch.setattr(adapter.os, "open", replace_after_open)
    data = adapter._read_local_grants(path)
    assert opened and data == _json(_grant(1))
    assert path.read_bytes() == _json(_grant(2))


def test_r01_growth_after_first_fstat_denies(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "grants.json"
    path.write_bytes(_json(_grant(1)))
    original_fstat = adapter.os.fstat
    count = 0

    def grow_after_fstat(fd):
        nonlocal count
        result = original_fstat(fd)
        if stat.S_ISREG(result.st_mode):
            count += 1
            if count == 1:
                with path.open("ab") as out:
                    out.write(b" " * (1024 * 1024 + 1))
        return result

    monkeypatch.setattr(adapter.os, "fstat", grow_after_fstat)
    with pytest.raises(ObservationError, match="limit"):
        adapter._read_local_grants(path)
    assert count == 1


def test_r02_same_size_inode_rewrite_denies(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "grants.json"
    path.write_bytes(_json(_grant(1)))
    assert len(_json(_grant(1))) == len(_json(_grant(2)))
    original_fstat = adapter.os.fstat
    count = 0

    def rewrite_after_fstat(fd):
        nonlocal count
        result = original_fstat(fd)
        if stat.S_ISREG(result.st_mode):
            count += 1
            if count == 1:
                with path.open("r+b") as out:
                    out.write(_json(_grant(2)))
                    out.flush()
                    os.fsync(out.fileno())
        return result

    monkeypatch.setattr(adapter.os, "fstat", rewrite_after_fstat)
    with pytest.raises(ObservationError, match="changed"):
        adapter._read_local_grants(path)
    assert count == 2


@pytest.mark.parametrize("seam", ["open", "fstat", "read"])
def test_r03_os_errors_close_opened_descriptor(tmp_path: Path, monkeypatch, seam: str) -> None:
    path = tmp_path / "grants.json"
    path.write_bytes(_json(_grant(1)))
    original_open = adapter.os.open
    original_fstat = adapter.os.fstat
    opened = []

    def capture_open(name, flags, *args, **kwargs):
        if seam == "open" and name == path.name:
            raise OSError("injected final open failure")
        fd = original_open(name, flags, *args, **kwargs)
        opened.append(fd)
        return fd

    # os is a process-global module; scope the fault to the reader invocation so
    # pytest's own fstat/read calls cannot be mistaken for a product failure.
    with monkeypatch.context() as fault:
        fault.setattr(adapter.os, "open", capture_open)
        if seam == "fstat":
            fault.setattr(adapter.os, "fstat", lambda fd: (_ for _ in ()).throw(OSError("injected fstat")))
        if seam == "read":
            fault.setattr(adapter.os, "read", lambda fd, size: (_ for _ in ()).throw(OSError("injected read")))
        with pytest.raises(OSError):
            adapter._read_local_grants(path)
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("invalid", [b"\xff", b"{", b'{"grants":[{}]}'])
def test_r03_decode_and_parser_fail_without_promoting_advisory(tmp_path: Path, invalid: bytes) -> None:
    feed = tmp_path / "feed.json"
    feed.write_text('{"adapter_version":"mesh-events-v1","events":[]}')
    path = tmp_path / "grants.json"
    path.write_bytes(invalid)
    with pytest.raises(ObservationError, match="invalid local publisher grants"):
        adapter.load_intelligence(feed, trust_path=path)


def test_r04_concurrent_readers_use_their_own_inodes(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "grants.json"
    path.write_bytes(_json(_grant(1)))
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(_json(_grant(2)))
    first_opened = threading.Event()
    second_opened = threading.Event()
    original_open = adapter.os.open
    counter = 0
    lock = threading.Lock()

    def controlled_open(name, flags, *args, **kwargs):
        nonlocal counter
        fd = original_open(name, flags, *args, **kwargs)
        if name == path.name:
            with lock:
                counter += 1
                order = counter
            if order == 1:
                os.replace(replacement, path)
                first_opened.set()
                assert second_opened.wait(5)
            else:
                second_opened.set()
        return fd

    monkeypatch.setattr(adapter.os, "open", controlled_open)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(adapter._read_local_grants, path)
        assert first_opened.wait(5)
        second = pool.submit(adapter._read_local_grants, path)
        assert first.result(timeout=5) == _json(_grant(1))
        assert second.result(timeout=5) == _json(_grant(2))
