"""Development controls for bounded synthetic row selection."""

from hashlib import sha256
import json

import pytest

import osv_row_selection as trial


def source(*rows):
    return trial.canonical({"id": "SYNTHETIC-LOCAL-1", "affected": rows})


def target(package="fern-spool", ecosystem="PyPI", version="2.4"):
    return trial.canonical({"ecosystem": ecosystem, "package": package, "version": version})


def row(package="fern-spool", ecosystem="PyPI", **keys):
    return {"package": {"name": package, "ecosystem": ecosystem}, **keys}


def interval(start, stop, range_type="ECOSYSTEM"):
    return {"type": range_type, "events": [{"introduced": start}, {"fixed": stop}]}


def ids(raw, context=None):
    report = trial.prepare(raw, target() if context is None else context)
    assert report["status"] == "prepared"
    return [item["row_id"] for item in report["payload"]["candidate_rows"]]


def check(raw, proposal, selected=(), context=None):
    return trial.check(
        raw, target() if context is None else context,
        trial.canonical({"proposed_outcome": proposal, "selected_row_ids": selected}),
    )


def test_complete_input_and_original_spans_include_noncanonical_and_repeated_rows():
    lexeme = b'{ "versions": ["2.4"],  "package": {"ecosystem":"PyPI", "name":"fern-spool"} }'
    raw = '{"summary":"clé","nested":{"affected":[{}]}, "affected" : [ '.encode() + lexeme
    raw += b',\n' + lexeme + b' ], "id":"SYNTHETIC-LOCAL-2"}'
    context = target()
    prepared = trial.prepare(raw, context)
    first, second = prepared["payload"]["candidate_rows"]

    assert prepared["payload"]["asset_context"] == json.loads(context)
    assert set(prepared["payload"]) == {"asset_context", "candidate_rows"}
    assert set(first) == set(second) == {"row_id", "osv_row"}
    assert first["row_id"] != second["row_id"]
    assert first["osv_row"].encode() == second["osv_row"].encode() == lexeme
    canonical_request = trial.canonical({"instructions": prepared["instructions"], "payload": prepared["payload"]})
    assert prepared["request_bytes"] == len(canonical_request)
    assert prepared["request_sha256"] == sha256(canonical_request).hexdigest()

    observed = check(raw, "affected", [second["row_id"], first["row_id"]])
    assert observed["status"] == "verified" and observed["reportable_outcome"] == "affected"
    assert [ref["pointer"] for ref in observed["references"]] == ["/affected/1", "/affected/0"]
    spans = []
    for ref in observed["references"]:
        span = ref["byte_start"], ref["byte_end"]
        spans.append(span)
        assert raw[slice(*span)] == ref["osv_row"].encode() == lexeme
        assert ref["source_sha256"] == sha256(raw).hexdigest()
    assert spans[0][0] > spans[1][1]


def test_prepared_context_has_no_selection_hints_or_provenance_locations():
    raw = source(row("decoy", versions=["2.4"]), row(versions=["2.4"]))
    report = trial.prepare(raw, target())
    payload = report["payload"]
    text = json.dumps(payload)
    assert len(payload["candidate_rows"]) == 2
    assert "pointer" not in text and "/affected/" not in text
    assert "source_sha256" not in text and "expected" not in text and "proposed_outcome" not in text


def test_exact_identity_and_version_independent_of_draft():
    raw = source(row("decoy", versions=["2.4"]), row(ecosystem="npm", versions=["2.4"]),
                 row("Fern_Spool", versions=["2.4.0"]))
    wrong_name, wrong_ecosystem, correct = ids(raw)
    for wrong in (wrong_name, wrong_ecosystem):
        assert check(raw, "affected", [wrong])["status"] == "refused"
    result = check(raw, "affected", [correct])
    assert result["references"][0]["pointer"] == "/affected/2"


def test_select_only_including_rows_within_a_package_union():
    raw = source(row(versions=["2.4"]), row(versions=["2.3"]), row(versions=["99"]))
    includes, excludes, _ = ids(raw)
    assert check(raw, "affected", [includes])["status"] == "verified"
    assert check(raw, "affected", [includes, excludes])["status"] == "refused"
    assert check(raw, "unaffected", [excludes])["reason"] == "unaffected-is-contradicted-or-indeterminate"


def test_negative_requires_all_target_exclusions_and_no_decoys():
    raw = source(row(ranges=[interval("2.0", "2.4")]), row(versions=["1.9"]),
                 row("different", versions=["2.4"]))
    first, second, decoy = ids(raw)
    assert check(raw, "unaffected", [first])["reason"] == "unaffected-selection-incomplete"
    assert check(raw, "unaffected", [first, second, decoy])["status"] == "refused"
    result = check(raw, "unaffected", [first, second])
    assert result["reportable_outcome"] == "unaffected"
    assert [item["pointer"] for item in result["references"]] == ["/affected/0", "/affected/1"]


@pytest.mark.parametrize("bad", [
    row(), row(versions=["2.4rc1"]), row(versions=[2.4]),
    row(ranges=[interval("2.4", "2.4")]), row(ranges=[interval("3.0", "2.0")]),
    row(ranges=[interval("2.0", "3.0", "GIT")]),
    row(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.4"}]}]),
    {"versions": ["2.4"]},
    {"package": {"ecosystem": "PyPI", "name": "other", "purl": "pkg:pypi/fern-spool"}, "versions": ["2.4"]},
])
def test_unknown_identity_or_range_blocks_negative_and_cannot_be_selected(bad):
    raw = source(row(versions=["1.0"]), bad)
    excluded, uncertain = ids(raw)
    assert check(raw, "unaffected", [excluded])["reason"] == "unaffected-is-contradicted-or-indeterminate"
    result = check(raw, "affected", [uncertain])
    assert result["status"] == "refused" and result["references"] == []


def test_npm_scope_and_alternating_ranges():
    context = target("@test/fern-spool", "npm", "4.5.0")
    events = [{"introduced": "0"}, {"fixed": "2.0"}, {"introduced": "4.5"}, {"fixed": "5.0"}]
    raw = source(row("@test/fern-spool", "npm", ranges=[{"type": "SEMVER", "events": events}]),
                 row("@other/fern-spool", "npm", versions=["4.5.0"]))
    target_id, wrong_id = ids(raw, context)
    assert check(raw, "affected", [target_id], context)["status"] == "verified"
    assert check(raw, "affected", [wrong_id], context)["status"] == "refused"


def test_abstention_and_request_bound_opaque_ids():
    raw = source(row(versions=["2.4"]), row("different", versions=["2.4"]))
    valid, _ = ids(raw)
    report = check(raw, "unknown")
    assert report["status"] == "abstained" and report["reportable_outcome"] == "unknown"
    assert report["references"] == []
    assert check(raw, "unknown", [valid])["reason"] == "abstention-has-evidence"
    assert check(raw, "affected", [])["reason"] == "selection-required"
    assert check(raw, "affected", [valid, valid])["reason"] == "duplicate-row-id"
    assert check(raw + b"\n", "affected", [valid])["reason"] == "unknown-row-id"
    assert check(raw, "affected", [valid], target(version="2.3"))["reason"] == "unknown-row-id"
    assert check(raw, "affected", ["/affected/0"])["reason"] == "unknown-row-id"


@pytest.mark.parametrize("raw, reason", [
    (b"x" * (trial.SOURCE_LIMIT + 1), "source-byte-limit"),
    (source(*(row(versions=["2.4"]) for _ in range(trial.ROW_LIMIT + 1))), "row-count-limit"),
    (source(row(versions=["2.4"], database_specific={"detail": "x" * trial.REQUEST_LIMIT})),
     "request-byte-limit"),
    (b'{"id":"A","affected":[],"affected":[]}', "duplicate-json-key"),
    (b'{"id":"A","affected":[', "invalid-source-json"),
    (b'{"id":"A","withdrawn":"2026-01-01","affected":[{}]}', "withdrawn-source"),
])
def test_reject_overflow_or_malformed_source_without_partial_projected_payload(raw, reason):
    result = trial.prepare(raw, target())
    assert result == {"status": "refused", "reason": reason, "reportable_outcome": "unknown", "references": []}


def test_reject_bad_draft_and_excess_fields():
    raw = source(row(versions=["2.4"]), row("different", versions=["2.4"]))
    only, _ = ids(raw)
    oversized = b" " * (trial.DRAFT_LIMIT + 1)
    assert trial.check(raw, target(), oversized)["reason"] == "draft-byte-limit"
    with_claim = trial.canonical({"proposed_outcome": "affected", "selected_row_ids": [only], "quote": "made up"})
    assert trial.check(raw, target(), with_claim)["reason"] == "invalid-selection-draft"
