import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.scout import AdvisoryInput, ThreatScout


CORPUS = json.loads((Path(__file__).parent / "fixtures" / "scout-corpus-v1.json").read_text())
NOW = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)


def source(row, *, content=None):
    raw = content if content is not None else json.dumps(row["body"], sort_keys=True, separators=(",", ":")).encode()
    if content is None:
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
    return snapshot(row["kind"], row["uri"], raw, retrieved_at=NOW)


def test_corpus_normalization_dedup_conflict_and_event_order(tmp_path):
    scout = ThreatScout(tmp_path / "scout.sqlite")
    emitted = []
    for row in CORPUS["entries"]:
        events = scout.ingest(source(row), exposure={"CVE-2099-0002": True})
        assert [event.kind for event in events] == row["expected_events"]
        emitted.extend(events)
        normalized = scout.revisions(row["kind"], row["expected_advisory_id"])[-1]
        assert normalized.content_sha256 == row["sha256"]
        assert normalized.vulnerability_ids == tuple(row["expected_vulnerability_ids"])
        assert normalized.claims[0].identity == row["expected_identity"]
        assert normalized.priority.tier == row["expected_priority"]
        assert scout.ingest(source(row), exposure={"CVE-2099-0002": True}) == ()
    assert [event.sequence for event in emitted] == list(range(1, len(emitted) + 1))
    assert [event.kind for event in scout.events(after=2, limit=2)] == ["conflict", "new"]
    assert len(scout.revisions("osv", "OSV-2099-1")) == 5
    assert scout.revisions("osv", "OSV-2099-1")[2].conflict is True
    assert scout.revisions("osv", "OSV-2099-1")[3].conflict is False
    assert scout.revisions("osv", "OSV-2099-1")[0].claims[0].identity == "pkg:pypi/acme-parser"
    assert scout.revisions("osv", "OSV-2099-1")[1].claims[0].versions[0].fixed == "2.1"
    assert scout.revisions("osv", "OSV-2099-1")[2].claims[0].versions[0].fixed == "2.2"
    kev = scout.revisions("kev", "CVE-2099-0002")[0]
    assert kev.priority.tier == "urgent"
    assert kev.priority.reasons == ("listed-as-known-exploited", "operator-reported-exposure")
    assert kev.claims[0].missing == ("affected-versions", "fixed-version")
    nvd = scout.revisions("nvd", "CVE-2099-0003")[0]
    assert nvd.priority.severity_score == 9.8
    assert "configuration-context" in nvd.claims[0].missing
    ghsa = scout.revisions("vendor-ghsa", "GHSA-abcd-efgh-ijkl")[0]
    assert "CVE-2099-0001" in ghsa.vulnerability_ids
    assert len(ghsa.claims) == 1
    assert all(event.advisory.schema_version == "scout-advisory-input-v1" for event in emitted)
    assert all(event.advisory.provenance == "synthetic-fixture" for event in emitted)
    assert b"Ignore prior instructions" in scout.source_bytes(CORPUS["entries"][-1]["sha256"])
    scout.close()
    reopened = ThreatScout(tmp_path / "scout.sqlite")
    assert [e.sequence for e in reopened.events()] == list(range(1, len(emitted) + 1))
    assert reopened.ingest(source(CORPUS["entries"][0])) == ()
    assert reopened.source_bytes(CORPUS["entries"][0]["sha256"]) == source(CORPUS["entries"][0]).content
    reopened.close()


def test_format_only_revision_is_saved_without_new_event():
    row = CORPUS["entries"][0]
    scout = ThreatScout()
    first = source(row)
    assert scout.ingest(first)[0].kind == "new"
    alternate = source(row, content=json.dumps(row["body"], indent=2).encode())
    assert scout.ingest(alternate) == ()
    assert len(scout.revisions("osv", "OSV-2099-1")) == 2
    assert len(scout.events()) == 1
    assert scout.source_bytes(alternate.sha256) == alternate.content
    later = snapshot(row["kind"], row["uri"], first.content,
                     retrieved_at=datetime(2026, 11, 21, tzinfo=timezone.utc))
    assert scout.ingest(later) == ()
    assert len(scout.observations(first.sha256)) == 2


def test_missing_metadata_and_unverified_archive_label():
    row = CORPUS["entries"][0]
    body = dict(row["body"])
    body.pop("published")
    body.pop("modified")
    raw = json.dumps(body).encode()
    archived = snapshot(row["kind"], row["uri"], raw, retrieved_at=NOW, acquisition="https")
    scout = ThreatScout()
    record = scout.ingest(archived)[0].advisory
    assert record.provenance == "unverified-archive"
    assert record.redistribution == "unknown"
    assert record.missing == ("modified-at", "published-at")
    assert AdvisoryInput.model_validate_json(record.model_dump_json()) == record


@pytest.mark.parametrize("content", [
    b'{"id":"OSV-2099-1","id":"OSV-2099-2"}',
    b'{"id":"OSV-2099-1","affected":42}',
    b'not-json',
])
def test_malformed_snapshot_is_atomic(content, tmp_path):
    scout = ThreatScout(tmp_path / "failure.sqlite")
    row = CORPUS["entries"][0]
    with pytest.raises((ValueError, TypeError, KeyError, AttributeError)):
        scout.ingest(source(row, content=content))
    assert scout.events() == ()
    assert scout.source_bytes(hashlib.sha256(content).hexdigest()) is None


def test_spoofed_source_and_metadata_change_rejected():
    row = CORPUS["entries"][0]
    scout = ThreatScout()
    with pytest.raises(ValueError, match="noncanonical"):
        scout.ingest(snapshot(row["kind"], "https://evil.example/vulns/OSV-2099-1",
                              source(row).content, retrieved_at=NOW))
    assert scout.ingest(source(row), exposure={"CVE-2099-0001": False})
    with pytest.raises(ValueError, match="metadata differs"):
        scout.ingest(source(row), exposure={"CVE-2099-0001": True})
    assert len(scout.events()) == 1
    assert len(scout.revisions("osv", "OSV-2099-1")) == 1


def test_older_revision_never_rolls_back_current():
    scout = ThreatScout()
    rows = CORPUS["entries"]
    assert scout.ingest(source(rows[1]))[0].kind == "new"
    assert scout.ingest(source(rows[0])) == ()
    assert len(scout.revisions("osv", "OSV-2099-1")) == 2
    assert scout.ingest(source(rows[2]))[0].kind == "conflict"
    assert [event.kind for event in scout.events()] == ["new", "conflict"]


def test_withdrawn_notice_has_no_priority_escalation():
    row = CORPUS["entries"][0]
    body = dict(row["body"], withdrawn="2026-11-19T00:00:00Z")
    raw = json.dumps(body).encode()
    record = ThreatScout().ingest(source(row, content=raw), exposure={"CVE-2099-0001": True})[0].advisory
    assert record.priority.tier == "unscored"
    assert "withdrawn-source" in record.priority.reasons


def test_missing_product_is_retained_as_unknown():
    for row in (CORPUS["entries"][0], CORPUS["entries"][6]):
        body = dict(row["body"])
        body.pop("affected", None)
        body.pop("vulnerabilities", None)
        record = ThreatScout().ingest(source(row, content=json.dumps(body).encode()))[0].advisory
        assert record.claims[0].identity_kind == "unknown"
        assert {"affected-products", "affected-versions"} <= set(record.missing)


def test_empty_kev_catalogue_records_observation_without_event():
    row = CORPUS["entries"][4]
    body = dict(row["body"], count=0, vulnerabilities=[])
    scout = ThreatScout()
    empty = source(row, content=json.dumps(body).encode())
    assert scout.ingest(empty) == ()
    assert scout.source_bytes(empty.sha256) == empty.content
    assert len(scout.observations(empty.sha256)) == 1
