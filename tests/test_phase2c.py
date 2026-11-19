"""Integration migration checks for the previously deployed Mesh audit schema."""

import sqlite3

import pytest

from aegis.storage import SqliteAudit


def test_mesh_audit_migrates_without_losing_revocation_or_identity(tmp_path):
    path = tmp_path / "mesh.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE audit_identity (agent_id TEXT PRIMARY KEY);
        INSERT INTO audit_identity VALUES ('agent-a');
        CREATE TABLE decisions (
            artifact_id TEXT PRIMARY KEY, digest TEXT NOT NULL, publisher_id TEXT NOT NULL,
            sequence INTEGER NOT NULL, authenticated INTEGER NOT NULL,
            outcome TEXT NOT NULL, reason TEXT NOT NULL, dry_run INTEGER NOT NULL,
            decided_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        INSERT INTO decisions(artifact_id,digest,publisher_id,sequence,authenticated,outcome,reason,dry_run)
        VALUES ('finding-1','abc','finder',1,1,'allow_dry_run','allowed',1);
        CREATE TABLE rejected_events (
            id INTEGER PRIMARY KEY, artifact_id TEXT NOT NULL, digest TEXT NOT NULL,
            publisher_id TEXT NOT NULL, reason TEXT NOT NULL, decided_at TEXT
        );
        CREATE TABLE revocation_decisions (
            event_id TEXT PRIMARY KEY, target_artifact_id TEXT NOT NULL,
            target_digest TEXT NOT NULL, digest TEXT NOT NULL,
            publisher_id TEXT NOT NULL, sequence INTEGER NOT NULL,
            authenticated INTEGER NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL,
            decided_at TEXT NOT NULL
        );
        INSERT INTO revocation_decisions VALUES
        ('revoke-1','finding-1','abc','def','revoker',1,1,'revoked_dry_run','withdrawn','2026-11-19');
        CREATE TABLE revoked_artifacts (
            publisher_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
            digest TEXT NOT NULL, revocation_id TEXT NOT NULL,
            PRIMARY KEY (publisher_id, artifact_id, digest)
        );
        INSERT INTO revoked_artifacts VALUES ('revoker','finding-1','abc','revoke-1');
    """)
    db.close()

    with pytest.raises(ValueError, match="different agent"):
        SqliteAudit(path, agent_id="agent-b")
    audit = SqliteAudit(path, agent_id="agent-a")
    assert audit.get("finding-1").reason_code == "FINDING_REVOKED"
    assert audit.get("finding-1").outcome == "deny"
    assert audit.get_revocation("revoke-1").reason_code == "LEGACY_REASON"
    assert audit.all_decisions()[0]["reason_code"] == "LEGACY_REASON"
    assert audit.high_water("finder") == audit.high_water("revoker") == 1
    assert audit.db.execute("SELECT agent_id FROM agent_identity").fetchone()[0] == "agent-a"
    audit.db.close()
