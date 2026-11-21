"""Offline checks for the frozen h84 linked trial entry point."""

import json
import subprocess
import sys

import pytest

import h84_linked_trial as trial
from osv_row_selection import canonical
from osv_two_stage import check_b


def payload(body):
    return json.loads(json.loads(body)["input"])


def command(*args):
    return subprocess.run([sys.executable, "-B", trial.__file__, *args], check=False, capture_output=True)


def identity_draft(outcome, row_ids):
    return canonical({"identity_outcome": outcome, "selected_row_ids": row_ids})


def assert_b_refuses(tmp_path, draft, reason):
    draft_path = tmp_path / "a-draft.json"
    draft_path.write_bytes(draft)
    result = command("B", str(draft_path))
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr == f"h84: {reason}\n".encode()


@pytest.fixture
def ids():
    rows = payload(trial.request_a())["candidate_rows"]
    return [row["row_id"] for row in rows]


def test_complete_draft_yields_only_both_original_matching_rows(tmp_path):
    a_run = command("A")
    assert a_run.returncode == 0 and not a_run.stderr
    assert a_run.stdout == trial.request_a()
    a = payload(a_run.stdout)
    assert set(a) == {"asset_context", "candidate_rows"}
    assert a["asset_context"] == {"ecosystem": "npm", "package": "pinevell-stage"}
    assert [
        {key: value for key, value in row.items() if key != "row_id"}
        for row in a["candidate_rows"]
    ] == [
        {"ecosystem": ecosystem, "package": "pinevell-stage", "purl": None, "purl_present": False}
        for ecosystem in ("npm", "PyPI", "npm")
    ]
    ids = [row["row_id"] for row in a["candidate_rows"]]
    assert len(set(ids)) == 3
    for version in (b"4.1.0", b"4.3.0", b"4.5.0", b"4.6.0", b"4.7.0"):
        assert version not in a_run.stdout

    first, _, last = ids
    draft = identity_draft("match", [last, first])
    draft_path = tmp_path / "a-draft.json"
    draft_path.write_bytes(draft)
    b_run = command("B", str(draft_path))
    assert b_run.returncode == 0 and not b_run.stderr
    assert b_run.stdout == trial.request_b(draft)
    b = payload(b_run.stdout)
    assert set(b) == {"asset_context", "candidate_rows"}
    assert b["asset_context"] == {"version": "4.5.0"}
    source, target = trial.fixture()
    # Original byte spans for /affected/0 and /affected/2 from the sealed h84 labels.
    spans = [(13, 149), (228, 312)]
    assert [row["osv_row"].encode() for row in b["candidate_rows"]] == [
        source[start:end] for start, end in spans
    ]
    assert all(set(row) == {"row_id", "osv_row"} for row in b["candidate_rows"])
    b_ids = [row["row_id"] for row in b["candidate_rows"]]
    assert len(set(b_ids)) == 2 and set(b_ids).isdisjoint(ids)
    for forbidden in (b"/affected/", b"matched_pointers", b"identity_outcome", b"expected_outcome"):
        assert forbidden not in b_run.stdout

    version_draft = canonical({"proposed_outcome": "unaffected", "selected_row_ids": b_ids})
    verdict = check_b(source, target, draft, version_draft, arm="linked")
    assert verdict["status"] == "verified"
    assert verdict["reportable_outcome"] == "unaffected"
    assert [reference["pointer"] for reference in verdict["references"]] == ["/affected/0", "/affected/2"]

    partial_draft = canonical({"proposed_outcome": "unaffected", "selected_row_ids": b_ids[:1]})
    refused = check_b(source, target, draft, partial_draft, arm="linked")
    assert refused["reason"] == "unaffected-selection-incomplete"
    assert refused["references"] == []


@pytest.mark.parametrize(("outcome", "indices", "reason"), [
    ("match", [0], "identity-selection-is-incomplete-or-incorrect"),
    ("match", [0, 1, 2], "identity-selection-is-incomplete-or-incorrect"),
    ("match", [0, 0, 2], "duplicate-identity-row-id"),
    ("no_match", [], "unverified-no-match"),
    ("unknown", [], "identity-abstained"),
    ("unknown", [0, 2], "identity-abstention-has-selected-rows"),
])
def test_unverified_identity_writes_no_b_body(outcome, indices, reason, tmp_path, ids):
    assert_b_refuses(tmp_path, identity_draft(outcome, [ids[i] for i in indices]), reason)


@pytest.mark.parametrize(("draft", "reason"), [
    (b'{"identity_outcome":"match","identity_outcome":"unknown","selected_row_ids":[]}', "duplicate-json-key"),
    (b'{"matched_pointers":["/affected/0","/affected/2"]}', "invalid-identity-draft"),
    (b'{"identity_outcome":', "invalid-identity-draft-json"),
])
def test_invalid_native_draft_writes_no_b_body(draft, reason, tmp_path):
    assert_b_refuses(tmp_path, draft, reason)


def test_b_cannot_be_built_without_a_draft():
    result = command("B")
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"identity_draft" in result.stderr
