"""Diagnostic tests for recovery evidence and unreviewed replay boundaries."""

import sqlite3

from aegis.storage import SqliteAudit
from scripts.phase4f_recovery_evidence import score


def test_retained_crash_denominator_and_read_only_denials():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    result = score(root)
    counts = result["diagnostic_denominator"]
    assert counts == {
        "crash_trials": 5, "crash_pairs": 10, "crash_pairs_over_5000_ms": 10,
        "healthy_trials": 2, "healthy_pairs": 4, "healthy_pairs_within_5000_ms": 4,
    }
    assert result["frozen_release_matrix"]["full_oracle_evaluable_fault_pairs"] == 0
    assert result["frozen_release_matrix"]["required_fault_agent_pairs"] == 72
    assert all(trial["read_only_denial_matches_findings"] for trial in result["trials"])
    assert all(trial["busy_kv_claims"] == 30 for trial in result["trials"]
               if trial["pre_intake_sigkill"])


def test_current_critical_cursor_has_no_generation_or_denial_cas(tmp_path):
    """Counterexample: old-session cursor movement needs a reviewed v2 schema."""
    path = tmp_path / "audit.db"
    audit = SqliteAudit(path, "agent-a")
    audit.advance_journal(1, critical=True)
    audit.db.close()
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as db:
        columns = [row[1] for row in db.execute("PRAGMA table_info(critical_recovery_cursor)")]
        assert columns == ["singleton", "position"]
        assert db.execute("SELECT position FROM critical_recovery_cursor").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM revocation_decisions").fetchone()[0] == 0
