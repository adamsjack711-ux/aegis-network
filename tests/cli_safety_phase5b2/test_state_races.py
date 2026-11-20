"""Deterministic, disposable reproductions of explicit state path replacement."""

import os
from pathlib import Path
from uuid import UUID

import pytest

from aegis.local_observer import ObservationError, asset_identity


def test_replaced_final_directory_cannot_receive_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    state = tmp_path / "state"
    original = os.mkdir

    def replace_final(path, mode=0o777, *, dir_fd=None):
        result = original(path, mode, dir_fd=dir_fd)
        if Path(path).name == "state":
            state.rmdir()
            state.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(os, "mkdir", replace_final)
    blocked = False
    try:
        asset_identity(state)
    except ObservationError:
        blocked = True
    assert not (outside / "identity.json").exists()
    assert blocked


def test_replaced_parent_symlink_cannot_receive_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    state = parent / "state"
    original = os.mkdir

    def replace_parent(path, mode=0o777, *, dir_fd=None):
        if Path(path).name == "state":
            parent.rmdir()
            parent.symlink_to(outside, target_is_directory=True)
        return original(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", replace_parent)
    blocked = False
    try:
        asset_identity(state)
    except ObservationError:
        blocked = True
    assert not (outside / "state" / "identity.json").exists()
    assert blocked


def test_existing_final_and_identity_symlinks_are_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    state = tmp_path / "state"
    state.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ObservationError, match="symlink"):
        asset_identity(state)
    assert not (outside / "identity.json").exists()
    state.unlink()
    state.mkdir(mode=0o700)
    target = outside / "target"
    target.write_text("unchanged")
    (state / "identity.json").symlink_to(target)
    with pytest.raises(ObservationError):
        asset_identity(state)
    assert target.read_text() == "unchanged"


def test_explicit_identity_bytes_and_modes_are_stable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import aegis.local_observer as observer

    fixed = UUID("00000000-0000-4000-8000-000000000001")
    monkeypatch.setattr(observer, "uuid4", lambda: fixed)
    state = tmp_path / "state"
    assert asset_identity(state) == str(fixed)
    assert asset_identity(state) == str(fixed)
    assert (state / "identity.json").read_bytes() == (
        b'{"asset_id": "00000000-0000-4000-8000-000000000001"}\n'
    )
    assert state.stat().st_mode & 0o077 == 0
    assert (state / "identity.json").stat().st_mode & 0o077 == 0


def test_identity_fifo_fails_without_waiting_for_a_writer(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.mkfifo(state / "identity.json", mode=0o600)
    with pytest.raises(ObservationError):
        asset_identity(state)
