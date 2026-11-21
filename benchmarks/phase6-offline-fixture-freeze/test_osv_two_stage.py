"""Development controls for the separate identity and version stages."""

from hashlib import sha256
import json

import pytest

import osv_two_stage as trial
from osv_row_selection import DRAFT_LIMIT, SOURCE_LIMIT, canonical


def context(version="2.0", ecosystem="PyPI", package="sample"):
    return canonical({"ecosystem": ecosystem, "package": package, "version": version})


def row(name="sample", ecosystem="PyPI", *, versions=("1.0",), **package_features):
    return {"package": {"ecosystem": ecosystem, "name": name, **package_features}, "versions": versions}


def source(*rows):
    return canonical({"id": "SYNTHETIC-DEVELOPER-OSV", "affected": rows})


def a_draft(outcome, ids=()):
    return canonical({"identity_outcome": outcome, "selected_row_ids": ids})


def b_draft(outcome, ids=()):
    return canonical({"proposed_outcome": outcome, "selected_row_ids": ids})


def oracle(*positions):
    return canonical({"matched_pointers": [f"/affected/{position}" for position in positions]})


def row_ids(report):
    return [row["row_id"] for row in report["payload"]["candidate_rows"]]


def test_stage_a_render_is_independent_of_target_and_source_versions():
    first = source(row(versions=("11.22.33",)), row("decoy"))
    later = source(row(versions=("44.55.66",)), row("decoy", versions=("77.88.99",)))
    a = trial.prepare_a(first, context("61.62.63"))
    b = trial.prepare_a(later, context("71.72.73"))
    assert a["status"] == b["status"] == "prepared"
    assert a["source_sha256"] != b["source_sha256"]
    assert a["payload"] == b["payload"]
    assert a["request_sha256"] == b["request_sha256"]
    assert a["payload"]["asset_context"] == {"ecosystem": "PyPI", "package": "sample"}
    assert all(set(item) == {"row_id", "ecosystem", "package", "purl", "purl_present"}
               for item in a["payload"]["candidate_rows"])


@pytest.mark.parametrize("purl", [
    "pkg:pypi/sample@77.88?tag=version-secret",
    "pkg:pypi/sample@77.88",
    "pkg:pypi/sample?tag=version-secret",
    "pkg:pypi/sample#version-secret",
    "pkg:pypi/sample%4077.88",
])
def test_stage_a_redacts_versioned_or_qualified_identity_without_hiding_ambiguity(purl):
    affected = row(purl=purl, version="66.55", extra="package-secret", versions=("44.33",))
    affected["ranges"] = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "22.11"}]}]
    raw = source(affected)
    target = context("99.98")
    report = trial.prepare_a(raw, target)
    assert report["status"] == "prepared"
    rendered = canonical(report["payload"])
    assert all(item not in rendered for item in (b"77.88", b"version-secret", b"99.98", b"66.55",
                                                 b"package-secret", b"44.33", b"22.11",
                                                 b"versions", b"ranges"))
    candidate, = report["payload"]["candidate_rows"]
    assert candidate["purl"] is None and candidate["purl_present"] is True
    assert trial.check_a(raw, target, a_draft("no_match"))["reason"] == "ambiguous-source-identity"
    assert trial.check_a(raw, target, a_draft("match", [candidate["row_id"]]))["status"] == "refused"
    assert trial.check_a(raw, target, a_draft("unknown"))["status"] == "abstained"


def test_valid_scoped_purl_has_no_version_and_matches():
    raw = source(row("@shoal/yarn", "npm", purl="pkg:npm/@shoal/yarn"))
    target = context(ecosystem="npm", package="@shoal/yarn")
    report = trial.prepare_a(raw, target)
    candidate, = report["payload"]["candidate_rows"]
    assert candidate["purl"] == "pkg:npm/@shoal/yarn"
    verdict = trial.check_a(raw, target, a_draft("match", [candidate["row_id"]]))
    assert verdict["status"] == "verified"


def test_identity_complete_set_and_silent_partial_selection_are_distinct():
    raw = source(row(), row(ecosystem="npm"), row("Sample"), row("decoy"))
    target = context()
    first, wrong_ecosystem, second, _ = row_ids(trial.prepare_a(raw, target))
    good = a_draft("match", [second, first])
    accepted = trial.check_a(raw, target, good)
    assert accepted["matched_row_ids"] == [first, second]
    assert accepted["matched_pointers"] == ["/affected/0", "/affected/2"]
    for draft in (a_draft("match", [first]), a_draft("match", [first, second, wrong_ecosystem]),
                  a_draft("match", [first, first]), a_draft("match", ["i-forged"]),
                  a_draft("no_match"), a_draft("unknown", [first])):
        rejected = trial.check_a(raw, target, draft)
        assert rejected["status"] == "refused" and rejected["matched_pointers"] == []
        blocked = trial.prepare_b(raw, target, draft, arm="linked")
        assert blocked["status"] == "blocked" and blocked["upstream_status"] == "refused"
        assert "payload" not in blocked and blocked["references"] == []


def test_verified_no_match_blocks_b_without_a_version_verdict():
    raw = source(row("decoy"), row(ecosystem="npm"))
    target = context()
    proven = trial.check_a(raw, target, a_draft("no_match"))
    assert proven["status"] == "verified" and proven["identity_outcome"] == "no_match"
    for arm, admission in (("linked", a_draft("no_match")), ("oracle", oracle())):
        report = trial.prepare_b(raw, target, admission, arm=arm)
        assert report["status"] == "blocked" and report["reason"] == "no-matching-identity"
        assert "payload" not in report


def test_oracle_b_can_measure_version_after_linked_a_abstains():
    raw = source(row(versions=("2.0",)), row("decoy"))
    target = context()
    a = trial.check_a(raw, target, a_draft("unknown"))
    assert a["status"] == "abstained"
    linked = trial.check_b(raw, target, a_draft("unknown"), b"malformed-unused", arm="linked")
    assert linked["status"] == "blocked" and linked["upstream_status"] == "abstained"
    prepared = trial.prepare_b(raw, target, oracle(0), arm="oracle")
    only, = row_ids(prepared)
    verdict = trial.check_b(raw, target, oracle(0), b_draft("affected", [only]), arm="oracle")
    assert verdict["status"] == "verified" and verdict["reportable_outcome"] == "affected"


def test_oracle_and_linked_render_identically_and_preserve_original_byte_attribution():
    lexeme = b'{ "package":{"ecosystem":"PyPI","name":"sample"}, "versions":["1.0"] }'
    raw = '{"summary":"clé","affected":[{"package":{"ecosystem":"npm","name":"sample"}},'.encode()
    raw += lexeme + b',\n' + lexeme + b'], "id":"SYNTHETIC-SPANS"}'
    target = context()
    _, id1, id2 = row_ids(trial.prepare_a(raw, target))
    linked = a_draft("match", [id2, id1])
    independent = oracle(2, 1)
    prepared_linked = trial.prepare_b(raw, target, linked, arm="linked")
    prepared_oracle = trial.prepare_b(raw, target, independent, arm="oracle")
    assert prepared_linked["payload"] == prepared_oracle["payload"]
    assert prepared_linked["request_sha256"] == prepared_oracle["request_sha256"]
    assert prepared_linked["payload"]["asset_context"] == {"version": "2.0"}
    assert [item["osv_row"].encode() for item in prepared_linked["payload"]["candidate_rows"]] == [lexeme, lexeme]
    b1, b2 = row_ids(prepared_linked)
    assert {b1, b2}.isdisjoint({id1, id2})
    for arm, admission in (("linked", linked), ("oracle", independent)):
        report = trial.check_b(raw, target, admission, b_draft("unaffected", [b2, b1]), arm=arm)
        assert report["status"] == "verified" and report["reportable_outcome"] == "unaffected"
        assert [ref["pointer"] for ref in report["references"]] == ["/affected/2", "/affected/1"]
        for ref in report["references"]:
            assert raw[ref["byte_start"]:ref["byte_end"]] == ref["osv_row"].encode() == lexeme
            assert ref["source_sha256"] == sha256(raw).hexdigest()
        assert trial.check_b(raw, target, admission, b_draft("unaffected", [b1]), arm=arm)["status"] == "refused"


@pytest.mark.parametrize("admission", [
    oracle(0), oracle(0, 0, 1), oracle(0, 1, 2), oracle(0, 1, 9),
    canonical({"matched_pointers": ["/affected/0", "/affected/1"], "gold": "affected"}),
    b"x" * (DRAFT_LIMIT + 1),
])
def test_oracle_arm_also_rejects_incomplete_or_invalid_upstream_identity(admission):
    raw = source(row(), row(), row("decoy"))
    blocked = trial.prepare_b(raw, context(), admission, arm="oracle")
    assert blocked["status"] == "blocked" and blocked["upstream_status"] == "refused"
    assert "payload" not in blocked and blocked["references"] == []


def test_indeterminate_version_after_verified_identity_is_a_stage_b_abstention():
    raw = source(row(versions=("2.0rc1",)), row("decoy"))
    target = context()
    identity_id, _ = row_ids(trial.prepare_a(raw, target))
    a = a_draft("match", [identity_id])
    assert trial.check_a(raw, target, a)["status"] == "verified"
    only, = row_ids(trial.prepare_b(raw, target, a, arm="linked"))
    assert trial.check_b(raw, target, a, b_draft("affected", [only]), arm="linked")["status"] == "refused"
    abstained = trial.check_b(raw, target, a, b_draft("unknown"), arm="linked")
    assert abstained["status"] == "abstained" and abstained["references"] == []


def test_source_and_stage_specific_render_bounds_fail_without_partial_payload():
    assert trial.prepare_a(b"x" * (SOURCE_LIMIT + 1), context())["reason"] == "source-byte-limit"
    embedded = row()
    embedded["database_specific"] = {"padding": "x" * 12000}
    raw = source(embedded)
    a = trial.prepare_a(raw, context())
    assert a["status"] == "prepared" and "padding" not in json.dumps(a["payload"])
    b = trial.prepare_b(raw, context(), oracle(0), arm="oracle")
    assert b["status"] == "refused" and b["reason"] == "request-byte-limit" and "payload" not in b


def test_withdrawal_refused_for_both_stages_and_both_arms():
    raw = canonical({"id": "SYNTHETIC-WITHDRAWN", "withdrawn": "2026-01-01", "affected": [row()]})
    assert trial.prepare_a(raw, context())["reason"] == "withdrawn-source"
    assert trial.prepare_b(raw, context(), oracle(0), arm="oracle")["reason"] == "withdrawn-source"
    assert trial.prepare_b(raw, context(), a_draft("none"), arm="linked")["reason"] == "withdrawn-source"
