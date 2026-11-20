"""Offline collection and signed Mesh observation boundary."""

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence, Finding, Revocation, Software, canonical_bytes, sign, sign_revocation
from aegis.cli import main
from aegis.intelligence_adapter import load_intelligence
from aegis.local_observer import Advisory, ObservationError, asset_identity, collect_inventory, collect_snapshot, match_findings


NOW = datetime.now(timezone.utc)
PURL = "pkg:deb/debian/curl"


def inventory_files(tmp_path, distro="debian", status=None):
    release = tmp_path / "os-release"
    release.write_text(f'ID="{distro}"\n')
    db = tmp_path / "status"
    db.write_text(status if status is not None else (
        "Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:8.0-1\n\n"
        "Package: removed\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1\n\n"))
    return release, db


def mesh_file(tmp_path, *, tamper=False, withdrawal=False, expired=False, conflict=False, purl=PURL, versions=None):
    key, revoker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    finding = Finding(schema_version="1.0", artifact_id=uuid4(), publisher_id="publisher-a", sequence=1,
                      issued_at=NOW - timedelta(days=2),
                      expires_at=NOW - timedelta(days=1) if expired else NOW + timedelta(days=1),
                      vulnerability_id="CVE-2026-0001", software=Software(purl=purl, affected_versions=versions or ["1:8.0-1"]),
                      evidence=[Evidence(uri="urn:local:test", sha256="a" * 64, method="advisory")],
                      applicability="authorized-lab", mitigation_template="observe-only")
    events = [sign(finding, key).model_dump(mode="json")]
    if conflict:
        events.append(sign(finding.model_copy(update={"artifact_id": uuid4()}), key).model_dump(mode="json"))
    if tamper:
        events[0]["finding"]["vulnerability_id"] = "CVE-2026-9999"
    if withdrawal:
        revocation = Revocation(schema_version="1.1", revocation_id=uuid4(), publisher_id="publisher-a", sequence=2,
                                issued_at=NOW - timedelta(hours=1), expires_at=NOW + timedelta(hours=1),
                                target_artifact_id=finding.artifact_id,
                                target_sha256=hashlib.sha256(canonical_bytes(finding)).hexdigest(),
                                target_publisher_id="publisher-a", reason="withdrawn")
        events.append(sign_revocation(revocation, revoker, "revoker").model_dump(mode="json"))
    feed = tmp_path / "mesh.json"
    feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": events}))
    grants = {"grants": []}
    for key_id, private, roles in (("default", key, ["finding"]), ("revoker", revoker, ["revocation"])):
        grants["grants"].append({"publisher_id": "publisher-a", "key_id": key_id,
                                 "public_key": base64.b64encode(private.public_key().public_bytes_raw()).decode(),
                                 "roles": roles, "not_before": (NOW - timedelta(days=10)).isoformat(),
                                 "expires_at": (NOW + timedelta(days=10)).isoformat(), "revoked_at": None})
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(grants))
    return feed, trust


def test_supported_distribution_identity_and_exact_version(tmp_path):
    for distro in ("debian", "ubuntu"):
        release, db = inventory_files(tmp_path, distro)
        packages = collect_inventory("asset", os_release=release, dpkg_status=db, now=NOW)
        assert len(packages) == 1
        assert (packages[0].purl, packages[0].version) == (f"pkg:deb/{distro}/curl", "1:8.0-1")
    release, db = inventory_files(tmp_path)
    packages = collect_inventory("asset", os_release=release, dpkg_status=db, now=NOW)
    def claim(versions, purl=PURL):
        return Advisory("CVE-2026-0001", purl, tuple(versions), "claim", "mesh", NOW + timedelta(days=1), None)
    assert match_findings(packages, [claim(["1:8.0-1"])], now=NOW)[0]["software_match"] == "matched"
    assert match_findings(packages, [claim(["1:8.0-2"])], now=NOW)[0]["software_match"] == "unmatched"
    assert match_findings(packages, [claim([">=1:8.0-1"])], now=NOW)[0]["software_match"] == "unknown"
    assert match_findings(packages, [claim(["1:8.0-1"], "pkg:deb/ubuntu/curl")], now=NOW)[0]["software_match"] == "unmatched"


def test_unsupported_missing_malformed_and_partial_inventory(tmp_path):
    release, db = inventory_files(tmp_path, "fedora")
    assert not collect_snapshot("asset", os_release=release, dpkg_status=db).complete
    release, db = inventory_files(tmp_path, status="Package: curl\nStatus: install ok installed\nVersion: 1\n\n")
    snapshot = collect_snapshot("asset", os_release=release, dpkg_status=db)
    assert not snapshot.complete and not snapshot.packages
    claim = Advisory("CVE-1", PURL, ("1",), "claim", "mesh", NOW + timedelta(days=1), None)
    assert match_findings(snapshot.packages, [claim], inventory_complete=snapshot.complete)[0]["match_reason"] == "INVENTORY_INCOMPLETE"
    db.unlink()
    assert not collect_snapshot("asset", os_release=release, dpkg_status=db).complete
    db.write_text("Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n" * 2)
    assert "duplicate" in collect_snapshot("asset", os_release=release, dpkg_status=db).reason
    db.unlink()
    db.symlink_to(release)
    assert "regular file" in collect_snapshot("asset", os_release=release, dpkg_status=db).reason


def test_expired_withdrawn_malformed_and_untrusted_signed_events(tmp_path):
    release, db = inventory_files(tmp_path)
    packages = collect_inventory("asset", os_release=release, dpkg_status=db, now=NOW)
    for kwargs, status in (({"expired": True}, "expired"), ({"withdrawal": True}, "withdrawn")):
        feed, trust = mesh_file(tmp_path, **kwargs)
        rows = match_findings(packages, load_intelligence(feed, trust_path=trust, now=NOW), now=NOW)
        assert rows[0]["software_match"] == "matched"
        assert rows[0]["local_claim_status"] == ("withdrawn-in-supplied-file" if status == "withdrawn" else "expired")
        assert rows[0]["independent_status"] == rows[0]["overall_assessment"] == "unknown"
    feed, trust = mesh_file(tmp_path, tamper=True)
    with pytest.raises(ObservationError, match="untrusted"):
        load_intelligence(feed, trust_path=trust, now=NOW)
    feed, trust = mesh_file(tmp_path)
    raw = json.loads(feed.read_text())
    raw["events"][0]["command"] = "rm -rf /"
    feed.write_text(json.dumps(raw))
    with pytest.raises(ObservationError, match="untrusted"):
        load_intelligence(feed, trust_path=trust, now=NOW)
    with pytest.raises(ObservationError, match="requires --trust"):
        load_intelligence(feed, now=NOW)
    feed.write_text("{broken")
    with pytest.raises(ObservationError, match="cannot read"):
        load_intelligence(feed, trust_path=trust, now=NOW)
    feed.write_text(json.dumps({"schema_version": "observation-v1", "advisories": []}))
    with pytest.raises(ObservationError, match="unsupported"):
        load_intelligence(feed, trust_path=trust, now=NOW)
    feed, trust = mesh_file(tmp_path, conflict=True)
    with pytest.raises(ObservationError, match="sequence conflict"):
        load_intelligence(feed, trust_path=trust, now=NOW)
    feed, trust = mesh_file(tmp_path)
    grants = json.loads(trust.read_text())
    grants["grants"][0]["revoked_at"] = (NOW - timedelta(hours=1)).isoformat()
    trust.write_text(json.dumps(grants))
    with pytest.raises(ObservationError, match="untrusted"):
        load_intelligence(feed, trust_path=trust, now=NOW)


def test_private_identity_and_offline_operation(tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "socket", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used")))
    state = tmp_path / "state"
    assert asset_identity(state) == asset_identity(state)
    assert os.stat(state).st_mode & 0o077 == 0
    assert os.stat(state / "identity.json").st_mode & 0o077 == 0
    os.chmod(state / "identity.json", 0o644)
    with pytest.raises(ObservationError, match="private"):
        asset_identity(state)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ObservationError, match="symlink"):
        asset_identity(link / "aegis")
    assert not (outside / "aegis").exists()
    with pytest.raises(ObservationError, match="parent must exist"):
        asset_identity(tmp_path / "missing-parent" / "aegis")
    assert not (tmp_path / "missing-parent").exists()


def test_input_limits_and_empty_signed_bundle(tmp_path, monkeypatch):
    release, db = inventory_files(tmp_path)
    import aegis.local_observer as observer
    monkeypatch.setattr(observer, "MAX_STATUS_BYTES", 32)
    assert "input limit" in collect_snapshot("asset", os_release=release, dpkg_status=db).reason
    feed, trust = mesh_file(tmp_path)
    import aegis.intelligence_adapter as adapter
    monkeypatch.setattr(adapter, "MAX_FEED_BYTES", 64)
    with pytest.raises(ObservationError, match="limit"):
        load_intelligence(feed, trust_path=trust)
    monkeypatch.setattr(adapter, "MAX_FEED_BYTES", 8 * 1024 * 1024)
    feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": []}))
    assert load_intelligence(feed, trust_path=trust) == []


def test_cli_json_human_and_explain(tmp_path, monkeypatch, capsys):
    release, db = inventory_files(tmp_path)
    import aegis.cli as cli
    monkeypatch.setattr(cli, "collect_snapshot", lambda asset_id: collect_snapshot(asset_id, os_release=release, dpkg_status=db, now=NOW))
    state = tmp_path / "state"
    feed, trust = mesh_file(tmp_path)
    assert main(["--state-dir", str(state), "inventory", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["package_count"] == 1
    assert main(["--state-dir", str(state), "findings", "--feed", str(feed), "--trust", str(trust), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == "observation-results-v2"
    assert (result["current_exact_package_match_count"], result["observation_count"]) == (1, 1)
    assert result["findings"][0]["independent_status"] == "unknown"
    assert result["findings"][0]["overall_assessment"] == "unknown"
    finding_id = result["findings"][0]["finding_id"]
    assert main(["--state-dir", str(state), "explain", finding_id, "--feed", str(feed), "--trust", str(trust)]) == 0
    assert "EXACT_PACKAGE_VERSION" in capsys.readouterr().out
    assert main(["--state-dir", str(state), "findings", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unknown"
    assert main(["--state-dir", str(state), "status", "--json"]) == 2
    assert "unknown" in json.loads(capsys.readouterr().out)["potential_findings"]
    feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": []}))
    assert main(["--state-dir", str(state), "findings", "--feed", str(feed), "--trust", str(trust), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["claim_count"] == 0
    feed, trust = mesh_file(tmp_path)
    db.unlink()
    assert main(["--state-dir", str(state), "inventory", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["inventory_complete"] is False
    assert main(["--state-dir", str(state), "findings", "--feed", str(feed), "--trust", str(trust), "--json"]) == 2
    incomplete = json.loads(capsys.readouterr().out)
    assert incomplete["findings"][0]["match_reason"] == "INVENTORY_INCOMPLETE"


def test_default_and_failure_paths_make_no_persistent_writes(tmp_path):
    def tree_signature(root):
        return sorted((path.relative_to(root).as_posix(), path.stat().st_mtime_ns,
                       hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
                      for path in root.rglob("*"))

    source = Path(__file__).resolve().parents[1] / "src"
    cases = {
        "status_no_feed": ["status", "--json"],
        "inventory": ["inventory", "--json"],
        "findings_no_feed": ["findings", "--json"],
        "findings_missing_file": ["findings", "--feed", str(tmp_path / "missing.json"), "--json"],
        "doctor": ["doctor", "--json"],
        "explain_no_feed": ["explain", "absent", "--json"],
    }
    for name, arguments in cases.items():
        scratch = tmp_path / name
        scratch.mkdir()
        (scratch / "sentinel").write_text("unchanged\n")
        state = scratch / "state"
        environment = os.environ | {"XDG_STATE_HOME": str(state), "PYTHONPATH": str(source),
                                    "PYTHONDONTWRITEBYTECODE": "1"}
        before = tree_signature(scratch)
        result = subprocess.run([sys.executable, "-m", "aegis.cli", *arguments],
                                env=environment, capture_output=True, text=True, check=False)
        assert result.returncode in {0, 2}, (name, result.stderr)
        assert tree_signature(scratch) == before, name
        assert not state.exists(), name
        if result.stdout.startswith("{"):
            body = json.loads(result.stdout)
            assert body.get("asset_id") is None
            assert body.get("identity_scope", "none") == "none"


def test_explicit_identity_opt_in_is_confined(tmp_path, monkeypatch, capsys):
    release, db = inventory_files(tmp_path)
    import aegis.cli as cli
    monkeypatch.setattr(cli, "collect_snapshot", lambda asset_id: collect_snapshot(
        asset_id, os_release=release, dpkg_status=db, now=NOW))
    state = tmp_path / "selected"
    assert main(["inventory", "--json"]) == 0
    default = json.loads(capsys.readouterr().out)
    assert default["asset_id"] is None and default["identity_scope"] == "none"
    assert not state.exists()
    assert main(["--state-dir", str(state), "inventory", "--json"]) == 0
    explicit = json.loads(capsys.readouterr().out)
    assert explicit["asset_id"] and explicit["identity_scope"] == "explicit-local"
    assert {path.relative_to(state).as_posix() for path in state.rglob("*")} == {"identity.json"}
    assert os.stat(state).st_mode & 0o077 == 0
    assert os.stat(state / "identity.json").st_mode & 0o077 == 0


def test_signed_match_separates_local_claim_and_independent_status(tmp_path, monkeypatch, capsys):
    release, db = inventory_files(tmp_path)
    import aegis.cli as cli
    monkeypatch.setattr(cli, "collect_snapshot", lambda asset_id: collect_snapshot(
        asset_id, os_release=release, dpkg_status=db, now=NOW))
    for kwargs, local_status, expected_exit in (
        ({}, "current-in-supplied-file", 0),
        ({"expired": True}, "expired", 2),
        ({"withdrawal": True}, "withdrawn-in-supplied-file", 2),
    ):
        feed, trust = mesh_file(tmp_path, **kwargs)
        assert main(["findings", "--feed", str(feed), "--trust", str(trust), "--json"]) == expected_exit
        output = json.loads(capsys.readouterr().out)
        row = output["findings"][0]
        assert output["schema_version"] == "observation-results-v2"
        assert output["asset_id"] is None and output["identity_scope"] == "none"
        assert row["publisher_authenticity"] == "verified"
        assert row["local_claim_status"] == local_status
        assert row["software_match"] == "matched"
        assert row["independent_status"] == "unknown"
        assert row["independent_status_reason"] == "NO_VERIFIABLE_T4_T5_PROOF"
        assert row["overall_assessment"] == "unknown"
        assert "result" not in row and "claim_status" not in row
        assert output["current_exact_package_match_count"] == (1 if expected_exit == 0 else 0)
