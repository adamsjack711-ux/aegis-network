import json
import os
from pathlib import Path

from aegis.intelligence.investigator import Draft
import pytest

from row_selection_trial import build_request, fixture, score
from osv_row_selection import canonical


@pytest.fixture
def trial():
    source, target = fixture((Path(__file__).resolve().parents[1] / "phase6-multirow-independent/seal/inputs.json").read_bytes())
    original = Path(os.environ["AEGIS_TEST_REVIEW_BODY"]).read_bytes()
    body = build_request(source, target, original)
    assert body.split(b'\n  "text": ', 1)[1] == original.split(b'\n  "text": ', 1)[1]
    payload = json.loads(json.loads(body)["input"])
    assert set(payload) == {"candidate_rows", "asset_context"}
    rows = payload["candidate_rows"]
    assert len(rows) == 3
    assert all(set(row) == {"row_id", "osv_row"} for row in rows)
    assert [json.loads(row["osv_row"]) for row in rows] == json.loads(source)["affected"]
    return source, target, rows


@pytest.mark.parametrize(("id_index", "quote_index", "expected"), [
    (0, 0, "unaffected"), (1, 1, "unknown"), (0, 1, "unknown"), (2, 2, "unknown"),
])
def test_live_selection_projection(trial, id_index, quote_index, expected):
    source, target, rows = trial
    draft = Draft.model_validate_json(canonical({
        "proposed_outcome": "unaffected", "uncertainties": [], "claims": [{
            "kind": "applicability", "source_id": rows[id_index]["row_id"], "quote": rows[quote_index]["osv_row"],
        }],
    }))
    result = score(source, target, draft)
    assert result["reportable_outcome"] == expected
    assert [ref["pointer"] for ref in result["references"]] == (["/affected/0"] if id_index == quote_index == 0 else [])
