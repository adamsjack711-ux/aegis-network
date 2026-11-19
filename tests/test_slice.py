import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aegis.api import app
from aegis.artifact import Evidence, Finding, SignedFinding, Software, sign
from aegis.core import Coordinator, InventoryItem, LocalAgent, LocalPolicy
from aegis.storage import MemoryBus, MemoryRepository, SqliteAudit


NOW = datetime.now(timezone.utc)


def sample(key, *, sequence=1, template="observe-only", version="1.0.0", expires=None):
    finding = Finding(
        schema_version="1.0",
        artifact_id=uuid4(),
        publisher_id="lab-publisher",
        sequence=sequence,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=expires or NOW + timedelta(hours=1),
        vulnerability_id="AEGIS-LAB-0001",
        software=Software(purl="pkg:generic/aegis-demo", affected_versions=[version]),
        evidence=[Evidence(uri="urn:aegis:lab:evidence", sha256="a" * 64, method="lab-reproduction")],
        applicability="authorized-lab",
        mitigation_template=template,
    )
    return sign(finding, key)


def setup(tmp_path, *, authorized=True, templates=frozenset({"observe-only"}), inventory=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pubs = {"lab-publisher": key.public_key()}
    bus = MemoryBus()
    coordinator = Coordinator(pubs, MemoryRepository(), bus)
    policy = LocalPolicy(pubs, templates, authorized)
    audit = SqliteAudit(tmp_path / "audit.db")
    agent = LocalAgent(policy, inventory if inventory is not None else [InventoryItem("pkg:generic/aegis-demo", "1.0.0")], audit)
    return key, coordinator, bus, agent, audit


def test_http_to_bus_to_local_audit(tmp_path):
    key, coordinator, bus, agent, audit = setup(tmp_path)
    envelope = sample(key)
    app.state.coordinator = coordinator
    client = TestClient(app)
    response = client.post("/v1/findings", json=envelope.model_dump(mode="json"))
    assert response.status_code == 202, response.text
    assert response.json()["accepted"] is True
    assert len(bus.events) == 1
    decision = agent.evaluate(bus.events[0], NOW)
    assert decision.outcome == "allow_dry_run"
    assert decision.dry_run is True
    assert len(audit.all_decisions()) == 1
    assert coordinator.submit(envelope, NOW) is False
    assert agent.evaluate(envelope, NOW) == decision
    assert len(audit.all_decisions()) == 1


def test_tamper_and_expiry_fail_at_coordinator(tmp_path):
    key, coordinator, bus, _, _ = setup(tmp_path)
    envelope = sample(key)
    tampered = envelope.model_copy(update={"finding": envelope.finding.model_copy(update={"mitigation_template": "evil"})})
    with pytest.raises(ValueError, match="signature"):
        coordinator.submit(tampered, NOW)
    expired = sample(key, expires=NOW - timedelta(microseconds=1))
    with pytest.raises(ValueError, match="currently valid"):
        coordinator.submit(expired, NOW)
    assert bus.events == []


def test_unknown_fields_and_versions_rejected():
    key = Ed25519PrivateKey.generate()
    payload = sample(key).model_dump(mode="json")
    payload["finding"]["command"] = "echo bad"
    with pytest.raises(Exception):
        SignedFinding.model_validate(payload)
    del payload["finding"]["command"]
    payload["finding"]["schema_version"] = "2.0"
    with pytest.raises(Exception):
        SignedFinding.model_validate(payload)


def test_local_policy_is_independent(tmp_path):
    key, _, _, agent, audit = setup(tmp_path, authorized=False)
    decision = agent.evaluate(sample(key), NOW)
    assert decision.outcome == "deny"
    assert decision.reason == "lab not authorized"
    assert len(audit.all_decisions()) == 1


def test_no_exact_match_and_unapproved_template(tmp_path):
    key, _, _, agent, _ = setup(tmp_path, inventory=[InventoryItem("pkg:generic/aegis-demo", "2.0.0")])
    assert agent.evaluate(sample(key), NOW).reason == "no exact inventory match"
    key2, _, _, agent2, _ = setup(tmp_path / "other", templates=frozenset())
    assert agent2.evaluate(sample(key2), NOW).reason == "template not allowed"


def test_invalid_signature_does_not_poison_sequence(tmp_path):
    key, _, _, agent, audit = setup(tmp_path)
    forged = sample(key, sequence=100)
    forged = forged.model_copy(update={"signature": base64.b64encode(b"x" * 64).decode()})
    assert agent.evaluate(forged, NOW).reason_code == "INVALID_SIGNATURE"
    assert audit.high_water("lab-publisher") == 0
    assert agent.evaluate(sample(key, sequence=1), NOW).outcome == "allow_dry_run"
    assert len(audit.rejected_events()) == 1


def test_malformed_base64_signature_is_rejected(tmp_path):
    key, coordinator, _, agent, audit = setup(tmp_path)
    invalid = sample(key).model_copy(update={"signature": "!!!"})
    with pytest.raises(ValueError, match="invalid signature"):
        coordinator.submit(invalid, NOW)
    assert agent.evaluate(invalid, NOW).outcome == "deny"
    assert audit.high_water("lab-publisher") == 0


def test_stale_sequence_denied(tmp_path):
    key, _, _, agent, audit = setup(tmp_path)
    assert agent.evaluate(sample(key, sequence=2), NOW).outcome == "allow_dry_run"
    assert agent.evaluate(sample(key, sequence=1), NOW).reason == "stale sequence"
    assert audit.high_water("lab-publisher") == 2
