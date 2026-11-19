"""Negative and durability checks for the agent's local dry-run boundary."""

import base64
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence, Finding, Revocation, Software, canonical_bytes, sign, sign_revocation
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.storage import SqliteAudit
from aegis.trust import PublisherGrant, TrustStore


NOW = datetime.now(timezone.utc)
PURL = "pkg:generic/aegis-demo"


def finding(key, sequence=1, *, artifact_id=None, purl=PURL, versions=None,
            template="observe-only", publisher="publisher-a"):
    return sign(Finding(
        schema_version="1.0", artifact_id=artifact_id or uuid4(), publisher_id=publisher,
        sequence=sequence, issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1), vulnerability_id="AEGIS-LAB-1",
        software=Software(purl=purl, affected_versions=versions or ["1.0.0"]),
        evidence=[Evidence(uri="urn:untrusted:opaque", sha256="a" * 64, method="lab-reproduction")],
        applicability="authorized-lab", mitigation_template=template,
    ), key)


def agent(path, key, *, inventory=None, authorized=True, templates=None, agent_id="agent-a",
          trust=None):
    audit = SqliteAudit(path, agent_id=agent_id)
    policy = LocalPolicy(
        trust or {"publisher-a": key.public_key()},
        frozenset({"observe-only"}) if templates is None else templates,
        authorized,
    )
    return LocalAgent(policy, [InventoryItem(PURL, "1.0.0")] if inventory is None else inventory, audit), audit


def revocation(key, envelope, sequence=2, *, digest=None):
    return sign_revocation(Revocation(
        schema_version="1.0", revocation_id=uuid4(), publisher_id="publisher-a",
        sequence=sequence, issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1), target_artifact_id=envelope.finding.artifact_id,
        target_sha256=digest or hashlib.sha256(canonical_bytes(envelope.finding)).hexdigest(),
        reason="withdrawn",
    ), key, "revoker")


def revocation_trust(finding_key, revocation_key):
    start, end = NOW - timedelta(days=1), NOW + timedelta(days=1)
    return TrustStore([
        PublisherGrant("publisher-a", "default", finding_key.public_key(),
                       frozenset({"finding"}), start, end),
        PublisherGrant("publisher-a", "revoker", revocation_key.public_key(),
                       frozenset({"revocation"}), start, end),
    ])


def test_exact_inventory_and_local_policy_deny_by_default(tmp_path):
    key = Ed25519PrivateKey.generate()
    cases = [
        ([InventoryItem(PURL, "1.0.0")], False, frozenset({"observe-only"}), PURL, ["1.0.0"], "LAB_NOT_AUTHORIZED"),
        ([InventoryItem(PURL, "1.0.0")], True, frozenset(), PURL, ["1.0.0"], "TEMPLATE_NOT_ALLOWED"),
        ([InventoryItem(PURL.upper(), "1.0.0")], True, frozenset({"observe-only"}), PURL, ["1.0.0"], "INVENTORY_NO_EXACT_MATCH"),
        ([InventoryItem(PURL, "1.0.0")], True, frozenset({"observe-only"}), PURL, ["1.0"], "INVENTORY_NO_EXACT_MATCH"),
        ([InventoryItem(PURL, "1.0.0")], True, frozenset({"observe-only"}), "pkg:generic/other", ["1.0.0"], "INVENTORY_NO_EXACT_MATCH"),
        ([InventoryItem(PURL, "1.0.0")], True, frozenset({"observe-only"}), PURL, [">=1.0.0"], "INVENTORY_NO_EXACT_MATCH"),
        ([], True, frozenset({"observe-only"}), PURL, ["1.0.0"], "INVENTORY_NO_EXACT_MATCH"),
    ]
    for index, (inventory, authorized, templates, purl, versions, expected) in enumerate(cases):
        local, audit = agent(tmp_path / f"case-{index}.db", key, inventory=inventory,
                             authorized=authorized, templates=templates)
        decision = local.evaluate(finding(key, purl=purl, versions=versions), NOW)
        assert (decision.outcome, decision.reason_code, decision.dry_run) == ("deny", expected, True)
        assert audit.all_decisions()[0]["reason_code"] == expected
    allowed, _ = agent(tmp_path / "allowed.db", key)
    assert allowed.evaluate(finding(key, versions=["9.9", "1.0.0"]), NOW).reason_code == "EXACT_MATCH_ALLOWED"


def test_duplicate_and_restart_keep_one_logical_decision(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "durable.db"
    first_agent, first_audit = agent(path, key)
    envelope = finding(key)
    first = first_agent.evaluate(envelope, NOW)
    assert first_agent.evaluate(envelope, NOW) == first
    first_audit.db.close()
    restarted, audit = agent(path, key)
    assert restarted.evaluate(envelope, NOW) == first
    assert len(audit.all_decisions()) == 1
    assert audit.high_water("publisher-a") == 1
    assert audit.all_decisions()[0]["agent_id"] == "agent-a"


def test_tightened_local_policy_persists_denial_on_replay(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "audit.db"
    envelope = finding(key)
    first, audit = agent(path, key)
    assert first.evaluate(envelope, NOW).outcome == "allow_dry_run"
    audit.db.close()
    tightened, audit = agent(path, key, authorized=False)
    denied = tightened.evaluate(envelope, NOW)
    assert (denied.outcome, denied.reason_code) == ("deny", "LAB_NOT_AUTHORIZED")
    assert len(audit.all_decisions()) == 1
    assert audit.db.execute("SELECT COUNT(*) FROM decision_overrides").fetchone()[0] == 1
    audit.db.close()
    restored, audit = agent(path, key)
    assert restored.evaluate(envelope, NOW) == denied
    assert audit.get(str(envelope.finding.artifact_id)) == denied


def test_audit_file_is_bound_to_agent_identity(tmp_path):
    path = tmp_path / "audit.db"
    first = SqliteAudit(path, agent_id="agent-a")
    first.db.close()
    with pytest.raises(ValueError, match="different agent"):
        SqliteAudit(path, agent_id="agent-b")
    second = SqliteAudit(path, agent_id="agent-a")
    second.db.close()


def test_existing_audit_schema_migrates_without_losing_decision(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE decisions (
        artifact_id TEXT PRIMARY KEY, digest TEXT NOT NULL, publisher_id TEXT NOT NULL,
        sequence INTEGER NOT NULL, authenticated INTEGER NOT NULL,
        outcome TEXT NOT NULL, reason TEXT NOT NULL, dry_run INTEGER NOT NULL,
        decided_at TEXT NOT NULL DEFAULT (datetime('now'))
    )""")
    db.execute("INSERT INTO decisions(artifact_id,digest,publisher_id,sequence,authenticated,outcome,reason,dry_run) "
               "VALUES('old-id','abc','publisher-a',1,1,'deny','old reason',1)")
    db.commit()
    db.close()
    audit = SqliteAudit(path, agent_id="agent-a")
    assert audit.get("old-id").reason_code == "LEGACY_REASON"
    assert audit.high_water("publisher-a") == 1


def test_forgery_and_id_conflict_never_overwrite_audited_decision(tmp_path):
    key = Ed25519PrivateKey.generate()
    local, audit = agent(tmp_path / "audit.db", key)
    envelope = finding(key)
    assert local.evaluate(envelope, NOW).outcome == "allow_dry_run"
    forged = envelope.model_copy(update={"signature": base64.b64encode(b"x" * 64).decode()})
    assert local.evaluate(forged, NOW).reason_code == "INVALID_SIGNATURE"
    conflict = finding(key, sequence=2, artifact_id=envelope.finding.artifact_id, versions=["2.0.0"])
    assert local.evaluate(conflict, NOW).reason_code == "ARTIFACT_ID_CONFLICT"
    assert audit.high_water("publisher-a") == 1
    assert len(audit.all_decisions()) == 1
    assert [row["reason_code"] for row in audit.rejected_events()] == [
        "INVALID_SIGNATURE", "ARTIFACT_ID_CONFLICT"
    ]


def test_key_role_and_expiry_fail_closed(tmp_path):
    key = Ed25519PrivateKey.generate()
    revoker = Ed25519PrivateKey.generate()
    trust = revocation_trust(key, revoker)
    local, audit = agent(tmp_path / "audit.db", key, trust=trust)
    envelope = finding(key)
    assert local.evaluate(envelope, NOW + timedelta(hours=2)).reason_code == "FINDING_INVALID_TIME"
    assert local.evaluate(sign(envelope.finding, revoker, "revoker"), NOW).reason_code == "PUBLISHER_ROLE_DENIED"
    assert audit.high_water("publisher-a") == 0
    assert local.evaluate(envelope, NOW).outcome == "allow_dry_run"


def test_unknown_and_revoked_publisher_keys_cannot_advance_sequence(tmp_path):
    key = Ed25519PrivateKey.generate()
    envelope = finding(key, sequence=100)
    unknown, unknown_audit = agent(tmp_path / "unknown.db", key,
                                   trust=TrustStore([]))
    assert unknown.evaluate(envelope, NOW).reason_code == "UNKNOWN_PUBLISHER_KEY"
    assert unknown_audit.high_water("publisher-a") == 0
    grant = PublisherGrant(
        "publisher-a", "default", key.public_key(), frozenset({"finding"}),
        NOW - timedelta(days=1), NOW + timedelta(days=1), revoked_at=NOW - timedelta(minutes=1),
    )
    revoked, revoked_audit = agent(tmp_path / "revoked.db", key,
                                   trust=TrustStore([grant]))
    assert revoked.evaluate(envelope, NOW).reason_code == "PUBLISHER_KEY_REVOKED"
    assert revoked_audit.high_water("publisher-a") == 0


@pytest.mark.parametrize("revocation_first", [False, True])
def test_revocation_durable_and_overrides_allow(tmp_path, revocation_first):
    finding_key, revoker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trust = revocation_trust(finding_key, revoker)
    path = tmp_path / "audit.db"
    local, audit = agent(path, finding_key, trust=trust)
    envelope = finding(finding_key)
    revoke = revocation(revoker, envelope)
    if not revocation_first:
        assert local.evaluate(envelope, NOW).outcome == "allow_dry_run"
    assert local.evaluate_revocation(revoke, NOW).reason_code == "REVOCATION_ACCEPTED"
    audit.db.close()
    restarted, audit = agent(path, finding_key, trust=trust)
    assert restarted.evaluate_revocation(revoke, NOW).reason_code == "REVOCATION_ACCEPTED"
    decision = restarted.evaluate(envelope, NOW)
    assert (decision.outcome, decision.reason_code) == ("deny", "FINDING_REVOKED")
    assert (audit.get(str(envelope.finding.artifact_id)).outcome,
            audit.get(str(envelope.finding.artifact_id)).reason_code) == (
                "deny", "FINDING_REVOKED"
            )
    assert len(audit.all_decisions()) == 1
    assert audit.is_revoked("publisher-a", str(envelope.finding.artifact_id),
                            hashlib.sha256(canonical_bytes(envelope.finding)).hexdigest())


def test_wrong_digest_revocation_cannot_revoke_finding(tmp_path):
    finding_key, revoker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    local, audit = agent(tmp_path / "audit.db", finding_key,
                         trust=revocation_trust(finding_key, revoker))
    envelope = finding(finding_key)
    assert local.evaluate_revocation(revocation(revoker, envelope, digest="0" * 64), NOW).outcome == "revoked_dry_run"
    # This new finding has a lower sequence, so stale-sequence denial still applies.
    # It is not denied as revoked: the target digest must match exactly.
    assert local.evaluate(envelope, NOW).reason_code == "STALE_SEQUENCE"
    assert not audit.is_revoked("publisher-a", str(envelope.finding.artifact_id),
                                hashlib.sha256(canonical_bytes(envelope.finding)).hexdigest())
