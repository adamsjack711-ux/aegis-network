import json
import runpy
import sys
from pathlib import Path

import pytest

from aegis.intelligence import Asset, FeedClient, assess, normalize, snapshot
from aegis.intelligence.models import SourceSnapshot
from aegis.intelligence.evaluate import evaluate
from aegis.intelligence.research import FixtureProvider, research


CORPUS = Path(__file__).parent / "fixtures" / "phase5a_cases.json"


def case(index=0):
    item = json.loads(CORPUS.read_text())[index]
    sources = [snapshot(x["kind"], x["uri"], json.dumps(x["body"]).encode()) for x in item["sources"]]
    claims = tuple(claim for source in sources for claim in normalize(source))
    return item, claims


def test_offline_corpus_and_no_claimed_improvement():
    report = evaluate(CORPUS)
    assert len(report["cases"]) == 12
    assert report["baseline"]["correct"] == 12
    assert report["ai"]["correct"] == 12
    assert report["improvement_correct_cases"] == 0
    assert report["citation_valid"] == 12
    assert report["baseline"]["false_positive"] == 0
    assert report["baseline"]["false_negative"] == 0


def test_conflict_preserved_and_nvd_configuration_abstains():
    item, claims = case(3)
    result = assess(Asset.model_validate(item["asset"]), claims, item["vulnerability_id"])
    assert result.outcome == "conflicting"
    assert len(result.references) == 2
    assert {claim.versions[0].fixed for claim in claims} == {"2.0", "3.0"}
    item, claims = case(5)
    assert assess(Asset.model_validate(item["asset"]), claims, item["vulnerability_id"]).outcome == "unknown"
    assert "configuration-context" in claims[0].missing


def test_snapshot_integrity_and_duplicate_keys():
    source = snapshot("osv", "https://api.osv.dev/v1/vulns/OSV-2099-1", b'{"id":"a","id":"b"}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        normalize(source)
    with pytest.raises(ValueError, match="digest"):
        SourceSnapshot.model_validate({**source.model_dump(), "content": b"changed"})


def test_external_network_is_disabled_before_transport():
    client = FeedClient(vendor_repositories=frozenset({"acme/parser"}))
    with pytest.raises(ValueError, match="not enrolled"):
        client.fetch("nvd", "CVE-2024-1/../../private")
    with pytest.raises(ValueError, match="not enrolled"):
        client.fetch("vendor-ghsa", "GHSA-abcd-efgh-ijkl", repository="other/parser")
    assert client.canonical_uri("nvd", "CVE-2099-0001").startswith("https://services.nvd.nist.gov/")
    with pytest.raises(ValueError, match="allowlisted"):
        client.canonical_uri("vendor-ghsa", "GHSA-abcd-efgh-ijkl", repository="other/parser")


def test_cli_rejects_network_mode_before_fetch(monkeypatch, tmp_path):
    request = json.loads((Path(__file__).parent / "fixtures" / "phase5a_request.json").read_text())
    request["sources"][0]["mode"] = "https"
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request))
    monkeypatch.setattr(sys, "argv", ["phase5a_research.py", str(path)])
    with pytest.raises(ValueError, match="source mode must be fixture"):
        runpy.run_path(str(Path(__file__).parents[1] / "scripts" / "phase5a_research.py"), run_name="__main__")


def test_prompt_is_data_and_private_identifiers_are_redacted():
    item, claims = case()
    asset = Asset.model_validate(item["asset"])
    captured = {}

    class CaptureProvider:
        def complete_json(self, instructions, payload, *, max_output_tokens):
            captured["instructions"] = instructions
            captured["payload"] = payload
            return FixtureProvider(item["fixture_response"]).complete_json(
                instructions, payload, max_output_tokens=max_output_tokens)

    result = research(asset, claims, item["vulnerability_id"], CaptureProvider())
    assert result.independently_verified is False
    assert "private-prod-1" not in captured["payload"]
    assert "secret-host.internal" not in captured["payload"]
    assert "acme-parser" not in captured["payload"]
    assert "untrusted data" in captured["instructions"]


def test_invalid_citation_and_schema_rejected():
    item, claims = case()
    asset = Asset.model_validate(item["asset"])
    forged = dict(item["fixture_response"])
    forged["points"] = [{"text": "Invented fact", "fact_ids": ["F99"]}]
    with pytest.raises(ValueError, match="unknown source facts"):
        research(asset, claims, item["vulnerability_id"], FixtureProvider(forged))
    forged["points"] = [{"text": "Claim", "fact_ids": ["F1"], "verified": True}]
    with pytest.raises(ValueError, match="invalid structured"):
        research(asset, claims, item["vulnerability_id"], FixtureProvider(forged))
    forged["points"] = [{"text": "Run sudo now", "fact_ids": ["F1"]}]
    with pytest.raises(ValueError, match="executable instruction"):
        research(asset, claims, item["vulnerability_id"], FixtureProvider(forged))


def test_budget_and_unsupported_version_abstention():
    item, claims = case(2)
    asset = Asset.model_validate(item["asset"])
    assert assess(asset, claims, item["vulnerability_id"]).outcome == "unknown"
    with pytest.raises(ValueError, match="budget"):
        research(asset, claims, item["vulnerability_id"], FixtureProvider(item["fixture_response"]),
                 max_input_bytes=100)
