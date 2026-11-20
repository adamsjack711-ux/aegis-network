"""Independent local SQLite writer-boundary and reader-snapshot checks.

Run from the candidate root in a network-disabled process with PYTHONPATH=src.
"""
import hashlib
import json
import sqlite3
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.handoff import OfflineHandoff
from aegis.intelligence.investigator import ScriptedProvider
from aegis.intelligence.models import Asset
from aegis.intelligence.scout import ThreatScout


def disable_network(event, args):
    if event.startswith("socket."):
        raise PermissionError("independent offline fixture forbids network")


sys.addaudithook(disable_network)
VID = "CVE-2099-2500"
ADVISORY = "OSV-2099-2500"
NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)
ASSET = Asset(asset_id="local-test", identity_kind="purl", identity="pkg:pypi/test-wheel", version="1.2")
PROVIDER = ScriptedProvider({"proposed_outcome": "affected", "claims": [
    {"kind": "applicability", "source_id": "S1", "quote": '"versions":["1.2"]'}], "uncertainties": []})


def make_source(identifier=ADVISORY, *, withdrawal=False, conflicting=False, acquisition="fixture"):
    when = "2026-11-19T00:00:00Z"
    body = {"id": identifier, "aliases": [VID], "published": when, "modified": when,
            "affected": [{"package": {"ecosystem": "PyPI", "name": "test-wheel"},
                          "versions": ["1.3" if conflicting else "1.2"]}]}
    if withdrawal:
        body["modified"] = body["withdrawn"] = "2026-11-19T01:00:00Z"
    return snapshot("osv", "https://api.osv.dev/v1/vulns/" + identifier,
                    json.dumps(body, separators=(",", ":"), sort_keys=True).encode(),
                    retrieved_at=NOW, acquisition=acquisition)


def run(folder, schedule):
    path = folder / (schedule + ".sqlite")
    writer = ThreatScout(path)
    assert writer.db.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    writer.db.execute("PRAGMA busy_timeout=0")
    worker = OfflineHandoff(path)
    reader = OfflineHandoff(path)
    trace = []
    boundary = []
    source = make_source(acquisition="https" if schedule == "archive" else "fixture")
    event, = writer.ingest(source)
    trace.append(["scout-committed", event.sequence, source.sha256])

    def read(label):
        rows = reader.history("osv", ADVISORY)
        trace.append([label, [r["status"] for r in rows]])
        return rows

    def withdraw():
        withdrawal, = writer.ingest(make_source(withdrawal=True))
        trace.append(["withdrawal-committed", withdrawal.sequence, withdrawal.advisory.content_sha256])

    def consume(selected=VID, asset=ASSET):
        result = worker.consume(event.sequence, selected, asset, PROVIDER, now=NOW)
        trace.append(["consume", asdict(result)])
        return result

    def checkpoint(statement):
        sql = statement.strip().upper()
        if sql == "BEGIN IMMEDIATE":
            boundary.append("begin-immediate-dispatch")
            if schedule == "competing-consumers":
                second = OfflineHandoff(path)
                try:
                    other = second.consume(event.sequence, VID, ASSET, PROVIDER, now=NOW)
                    trace.append(["second-consumer-commit-before-first-lock", asdict(other)])
                    assert other.outcome == "committed"
                finally:
                    second.close()
            if schedule == "withdraw-before-lock":
                withdraw()
                assert read("after-withdraw-before-resume") == []
        elif sql.startswith("INSERT INTO RESEARCH_RESULTS"):
            boundary.append("insert-dispatch")
            if schedule == "withdraw-during-locked-insert":
                try:
                    withdraw()
                except sqlite3.OperationalError as error:
                    trace.append(["competing-withdrawal", error.sqlite_errorname])
                    assert error.sqlite_errorcode == sqlite3.SQLITE_BUSY
                else:
                    raise AssertionError("competing withdrawal committed before result")
                assert read("before-result-commit") == []
        elif sql == "COMMIT":
            boundary.append("result-commit-dispatch")
            if schedule == "withdraw-before-lock":
                assert read("before-result-txn-commit") == []

    # Exceptions in sqlite3 trace callbacks do not propagate. Save and assert them outside SQLite.
    callback_errors = []
    def guarded(statement):
        try:
            checkpoint(statement)
        except Exception as error:
            callback_errors.append(repr(error))

    worker.db.set_trace_callback(guarded)
    try:
        if schedule == "withdraw-before-pickup":
            withdraw()
            assert consume().outcome == "held"
            assert read("after-pickup") == []
            assert boundary == []
        elif schedule == "withdraw-before-lock":
            assert consume().outcome == "held"
            assert read("after-resume") == []
            assert boundary == ["begin-immediate-dispatch", "insert-dispatch", "result-commit-dispatch"]
        elif schedule == "competing-consumers":
            assert consume().outcome == "duplicate"
            single, = read("after-both-consumers")
            assert single["sequence"] == 1 and single["status"] == "current"
        elif schedule == "conflict-before-pickup":
            conflict, = writer.ingest(make_source(conflicting=True))
            assert conflict.kind == "conflict"
            trace.append(["conflict-committed", conflict.sequence, conflict.advisory.content_sha256])
            assert consume().outcome == "held"
            assert read("after-conflict") == []
        elif schedule == "wrong-id":
            assert consume(selected="CVE-2099-9999").outcome == "held"
            assert read("after-selection") == []
        elif schedule == "uncertain-asset":
            assert consume(asset=Asset(asset_id="other", identity_kind="purl",
                                      identity="pkg:pypi/different", version="1.2")).outcome == "committed"
            row, = read("after-unknown-match")
            assert row["research"]["candidate"]["reportable_outcome"] == "unknown"
        else:
            if schedule == "unrelated-event":
                other, = writer.ingest(make_source("OSV-2099-2501"))
                trace.append(["unrelated-commit", other.sequence])
            assert consume().outcome == "committed"
            row, = read("fresh-after-result")
            assert row["status"] == "current" and row["sequence"] == event.sequence
            assert row["advisory_id"] == ADVISORY and row["vulnerability_id"] == VID
            assert row["source_uri"] == source.uri and row["revision"] == hashlib.sha256(source.content).hexdigest()
            candidate = row["research"]["candidate"]
            assert candidate["advisory_id"] == ADVISORY and candidate["independently_verified"] is False
            assert candidate["reportable_outcome"] == "affected"
            excerpt, = candidate["excerpts"]
            assert source.content[excerpt["byte_start"]:excerpt["byte_end"]] == b'"versions":["1.2"]'
            assert excerpt["source_sha256"] == source.sha256
            if schedule == "archive":
                assert row["provenance"] == "unverified-archive" and row["redistribution"] == "unknown"
            worker.db.set_trace_callback(None)
            assert consume().outcome == "duplicate"
            if schedule in ("withdraw-during-locked-insert", "restart"):
                reader.db.execute("BEGIN")
                assert read("open-read-snapshot")[0]["status"] == "current"
                withdraw()
                assert read("already-open-read-snapshot-after-withdrawal")[0]["status"] == "current"
                reader.db.rollback()
                after, = read("fresh-post-withdrawal")
                assert after["status"] == "withdrawn" and after["research"] == row["research"]
                assert consume().outcome == "held"
                worker.close()
                worker = OfflineHandoff(path)
                assert consume().outcome == "held"
                assert read("after-restart") == [after]
        assert callback_errors == [], callback_errors
    finally:
        writer.close()
        worker.close()
        reader.close()
    return {"schedule": schedule, "trace": trace, "worker_sql_boundaries": boundary}


if __name__ == "__main__":
    schedules = ["normal", "withdraw-before-pickup", "withdraw-before-lock", "withdraw-during-locked-insert",
                 "restart", "conflict-before-pickup", "unrelated-event", "wrong-id", "uncertain-asset", "archive", "competing-consumers"]
    print(json.dumps({"python": sys.version, "sqlite": sqlite3.sqlite_version}), flush=True)
    with tempfile.TemporaryDirectory() as temporary:
        for schedule in schedules:
            print(json.dumps(run(Path(temporary), schedule)), flush=True)
