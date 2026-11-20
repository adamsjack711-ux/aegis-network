"""Private observer packaging and grant-reader boundaries."""

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.observer_grants import load_observer_publishers
from aegis.intelligence_adapter import load_intelligence
from aegis.local_observer import ObservationError


def _grant_file(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "publishers.json"
    raw = {"grants": [{
        "publisher_id": "fixture-publisher", "key_id": "fixture-key",
        "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "roles": ["finding", "revocation"],
        "not_before": "2026-01-01T00:00:00+00:00",
        "expires_at": "2028-01-01T00:00:00+00:00",
        "revoked_at": None,
        "revocation_publishers": ["fixture-publisher"],
    }]}
    path.write_text(json.dumps(raw))
    return path, raw


def _grant_fingerprint(store):
    return {identity: (grant.public_key.public_bytes_raw(), grant.roles,
                       grant.not_before, grant.expires_at, grant.revoked_at,
                       grant.revocation_publishers)
            for identity, grant in store.grants.items()}


def test_observer_grants_equal_existing_parser_on_golden_inputs(tmp_path):
    # The shared loader is imported only by this test, never by the CLI.
    from aegis.config import load_publishers

    path, raw = _grant_file(tmp_path)
    assert _grant_fingerprint(load_observer_publishers(path)) == _grant_fingerprint(load_publishers(str(path)))
    path.write_text(json.dumps({"fixture-publisher": raw["grants"][0]["public_key"]}))
    assert _grant_fingerprint(load_observer_publishers(path)) == _grant_fingerprint(load_publishers(str(path)))


def test_observer_grants_match_role_time_revocation_and_scope(tmp_path):
    from aegis.config import load_publishers

    path, raw = _grant_file(tmp_path)

    def decisions(store):
        times = [datetime(2025, 12, 31, tzinfo=timezone.utc),
                 datetime(2026, 6, 1, tzinfo=timezone.utc),
                 datetime(2028, 1, 1, tzinfo=timezone.utc)]
        answers = []
        for now in times:
            for role in ("finding", "revocation", "unknown"):
                try:
                    key = store.authorize("fixture-publisher", "fixture-key", role, now)
                    answers.append((role, now.isoformat(), key.public_bytes_raw()))
                except ValueError as exc:
                    answers.append((role, now.isoformat(), type(exc).__name__, str(exc)))
            for target in ("fixture-publisher", "other-publisher"):
                try:
                    key = store.authorize_revocation("fixture-publisher", "fixture-key", target, now)
                    answers.append((target, now.isoformat(), key.public_bytes_raw()))
                except ValueError as exc:
                    answers.append((target, now.isoformat(), type(exc).__name__, str(exc)))
        return answers

    assert decisions(load_observer_publishers(path)) == decisions(load_publishers(str(path)))
    raw["grants"][0]["revoked_at"] = "2026-05-01T00:00:00+00:00"
    path.write_text(json.dumps(raw))
    assert decisions(load_observer_publishers(path)) == decisions(load_publishers(str(path)))


def test_repeated_publisher_id_matches_shared_key_rotation_semantics(tmp_path):
    from aegis.config import load_publishers

    path, raw = _grant_file(tmp_path)
    rotated = raw["grants"][0].copy()
    rotated["key_id"] = "rotated-key"
    rotated["public_key"] = base64.b64encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    ).decode()
    raw["grants"].append(rotated)
    path.write_text(json.dumps(raw))
    observer = load_observer_publishers(path)
    shared = load_publishers(str(path))
    assert _grant_fingerprint(observer) == _grant_fingerprint(shared)
    assert len(observer.grants) == 2
    for store in (observer, shared):
        for key_id in ("fixture-key", "rotated-key"):
            assert store.authorize("fixture-publisher", key_id, "finding",
                                   datetime(2026, 6, 1, tzinfo=timezone.utc))


@pytest.mark.parametrize("mutation", [
    lambda raw: raw["grants"][0].update(roles=["publisher"]),
    lambda raw: raw["grants"][0].update(public_key="invalid-base64"),
    lambda raw: raw["grants"].append(raw["grants"][0].copy()),
    lambda raw: raw["grants"][0].update(revocation_publishers=["not a publisher!"]),
    lambda raw: raw["grants"][0].update(expires_at="2025-01-01T00:00:00+00:00"),
])
def test_observer_grants_reject_shared_negative_vectors(tmp_path, mutation):
    from aegis.config import load_publishers

    path, raw = _grant_file(tmp_path)
    mutation(raw)
    path.write_text(json.dumps(raw))
    with pytest.raises((ValueError, TypeError, KeyError)):
        load_publishers(str(path))
    with pytest.raises((ValueError, TypeError, KeyError)):
        load_observer_publishers(path)


@pytest.mark.parametrize("raw", [[], "not-an-object", None, {"grants": "not-a-list"},
                                  {"grants": [None]}])
def test_malformed_grant_top_level_rejected_as_bounded_cli_error(tmp_path, monkeypatch, capsys, raw):
    from aegis.cli import main

    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": []}))
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(raw))
    state = tmp_path / "implicit-state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    assert main(["findings", "--feed", str(feed), "--trust", str(trust), "--json"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["schema_version"] == "observation-error-v2"
    assert output["status"] == output["independent_status"] == "unknown"
    assert len(output["error"]) < 256
    assert not state.exists()


@pytest.mark.parametrize("raw", [[], "not-an-object", None, {"grants": "not-a-list"},
                                  {"grants": [None]}])
def test_malformed_grant_file_is_rejected_by_both_readers(tmp_path, raw):
    from aegis.config import load_publishers

    path = tmp_path / "malformed-trust.json"
    path.write_text(json.dumps(raw))
    for reader in (lambda: load_publishers(str(path)), lambda: load_observer_publishers(path)):
        with pytest.raises((ValueError, TypeError, KeyError, AttributeError)):
            reader()


def test_oversized_grants_rejected_without_state(tmp_path, monkeypatch, capsys):
    from aegis.cli import main

    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": []}))
    trust = tmp_path / "trust.json"
    trust.write_bytes(b" " * (1024 * 1024 + 1))
    state = tmp_path / "implicit-state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    assert main(["findings", "--feed", str(feed), "--trust", str(trust), "--json"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "unknown" and output["error"] == "invalid local publisher grants"
    assert not state.exists()


def test_revoked_expired_and_out_of_scope_grants_rejected(tmp_path):
    from test_phase5b_cli import mesh_file
    from datetime import datetime, timedelta, timezone

    feed, trust = mesh_file(tmp_path)
    raw = json.loads(trust.read_text())
    for change in (
        {"revoked_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()},
        {"expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()},
    ):
        modified = json.loads(json.dumps(raw))
        modified["grants"][0].update(change)
        trust.write_text(json.dumps(modified))
        with pytest.raises(ObservationError, match="untrusted"):
            load_intelligence(feed, trust_path=trust)
    feed, trust = mesh_file(tmp_path, withdrawal=True)
    modified = json.loads(trust.read_text())
    modified["grants"][1]["revocation_publishers"] = ["other-publisher"]
    trust.write_text(json.dumps(modified))
    with pytest.raises(ObservationError, match="untrusted"):
        load_intelligence(feed, trust_path=trust)


def test_cli_import_graph_does_not_load_enforcement_modules():
    source = Path(__file__).resolve().parents[1] / "src"
    environment = os.environ | {"PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"}
    code = ("import aegis.cli,sys; blocked=('aegis.core','aegis.config','aegis.agent_runtime',"
            "'aegis.mitigation'); assert not [name for name in sys.modules "
            "if name in blocked or name.startswith('aegis.mitigation.')], "
            "[name for name in sys.modules if name.startswith('aegis.')] ")
    completed = subprocess.run([sys.executable, "-c", code], env=environment,
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
