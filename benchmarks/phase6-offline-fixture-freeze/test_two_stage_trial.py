from hashlib import sha256
import json

import pytest

import two_stage_trial as trial
from openai_responses_adapter import Refused, complete_responses_once
from test_openai_one_shot import DUMMY_SECRET, fake_endpoint, response_body


@pytest.mark.parametrize("stage,expected_rows", [("A", 3), ("B", 1)])
def test_native_stage_transport(stage, expected_rows, tmp_path):
    body = trial.request_body(stage)
    request = json.loads(body)
    payload = json.loads(request["input"])
    assert len(payload["candidate_rows"]) == expected_rows
    assert set(payload["asset_context"]) == ({"ecosystem", "package"} if stage == "A" else {"version"})
    field = "identity_outcome" if stage == "A" else "proposed_outcome"
    schema = request["text"]["format"]["schema"]
    assert schema["required"] == [field, "selected_row_ids"] and schema["additionalProperties"] is False
    output = [{"type": "message", "role": "assistant", "status": "completed",
               "content": [{"type": "output_text", "text": json.dumps({field: "unknown", "selected_row_ids": []})}]}]
    raw = response_body(output=output)
    connection, _ = fake_endpoint(tmp_path, reply=raw)
    result = complete_responses_once(body, body_sha256=sha256(body).hexdigest(), model=trial.MODEL,
                                     input_token_limit=10261, credential_reader=lambda: DUMMY_SECRET,
                                     connection_factory=connection, draft_type=trial.DRAFT_TYPES[stage])
    assert result.draft.selected_row_ids == ()
    replay = trial.replay(stage, raw)
    assert replay["check"]["status"] == "abstained"
    assert replay["input_request_provenance"] == "unverified"
    assert replay["evaluated_contract_body_sha256"] == sha256(body).hexdigest()
    with pytest.raises(ValueError, match="exceeds"):
        trial.replay(stage, raw + b" " * trial.RAW_REPLY_LIMIT)
    other = "B" if stage == "A" else "A"
    with pytest.raises(Refused):
        trial.replay(other, raw)


@pytest.mark.parametrize(("stage", "expected", "expected_sha"), [
    ("A", "match", "bcd7a58962ec8aebdb0e6cbf1012e8edc9f501158252a414cbd56833426ee375"),
    ("B", "unaffected", "6d3e172a61c815be80f6f7118d835d451b5e0981301ac1eb4232370603298924"),
])
def test_h53_bodies_and_fixed_boundary_typed_replay(stage, expected, expected_sha, tmp_path):
    body = trial.request_body(stage, case="h53")
    request = json.loads(body)
    original = json.loads(trial.request_body(stage))
    assert sha256(body).hexdigest() == expected_sha
    assert {key: value for key, value in request.items() if key != "input"} == {
        key: value for key, value in original.items() if key != "input"
    }
    payload = json.loads(request["input"])
    assert set(payload) == {"asset_context", "candidate_rows"}
    assert not any(label in request["input"] for label in ("h53", "matched_pointers", "/affected/",
                                                           "expected", "unaffected", "source_sha256"))
    context = payload["asset_context"]
    rows = payload["candidate_rows"]
    if stage == "A":
        assert len(rows) == 3
        assert set(context) == {"ecosystem", "package"}
        assert "2.7.0" not in request["input"]
        field, chosen = "identity_outcome", rows[2]["row_id"]
    else:
        assert len(rows) == 1 and context == {"version": "2.7.0"}
        source, _ = trial.fixture("h53")
        assert rows[0]["osv_row"].encode() == source[167:303]
        field, chosen = "proposed_outcome", rows[0]["row_id"]

    def raw_draft(outcome, ids):
        return response_body(output=[{"type": "message", "role": "assistant", "status": "completed",
                                      "content": [{"type": "output_text", "text": json.dumps({
                                          field: outcome, "selected_row_ids": ids,
                                      })}]}])

    raw = raw_draft(expected, [chosen])
    connection, _ = fake_endpoint(tmp_path, reply=raw)
    reply = complete_responses_once(body, body_sha256=expected_sha, model=trial.MODEL,
                                    input_token_limit=10261, credential_reader=lambda: DUMMY_SECRET,
                                    connection_factory=connection, draft_type=trial.DRAFT_TYPES[stage])
    assert type(reply.draft) is trial.DRAFT_TYPES[stage]
    assert reply.draft.selected_row_ids == (chosen,)
    result = trial.replay(stage, raw, case="h53")
    assert result["evaluated_contract_body_sha256"] == expected_sha
    assert result["input_request_provenance"] == "unverified"
    assert result["check"]["status"] == "verified"
    if stage == "A":
        assert result["check"]["matched_pointers"] == ["/affected/2"]
        assert trial.replay(stage, raw_draft("match", [rows[0]["row_id"]]), case="h53")[
            "check"]["status"] == "refused"
    else:
        ref, = result["check"]["references"]
        assert result["check"]["reportable_outcome"] == "unaffected"
        assert (ref["pointer"], ref["byte_start"], ref["byte_end"]) == ("/affected/2", 167, 303)
        assert trial.replay(stage, raw_draft("affected", [chosen]), case="h53")[
            "check"]["status"] == "refused"
    assert trial.replay(stage, raw_draft("unknown", []), case="h53")["check"]["status"] == "abstained"


def test_h28_remains_default_with_exact_original_bodies():
    for stage, digest in (
        ("A", "71291fec6d5e0215655b09af0e8f1b337da84560ebc8689e9e5f5b257bcd886e"),
        ("B", "eddb187063fe829896d45323bd8329e73f7a7a8bd01550ff099c5585d7ee8536"),
    ):
        assert trial.request_body(stage) == trial.request_body(stage, case="h28")
        assert sha256(trial.request_body(stage)).hexdigest() == digest


def test_h75_has_only_an_oracle_b_probe():
    with pytest.raises(ValueError, match="B-only"):
        trial.request_body("A", case="h75")
    with pytest.raises(ValueError, match="B-only"):
        trial.replay("A", b"{}", case="h75")

    raw = trial.request_body("B", case="h75")
    wire = json.loads(raw)
    assert len(raw) == 1189
    assert sha256(raw).hexdigest() == "4ba3b36148fecd4c4b081d0731cfb5a2e8bec1594c3b1a9d7499358a90e661b0"
    assert sha256(wire["input"].encode()).hexdigest() == (
        "473525251c76d2c8242ee1113c4651021e29e524099925a2807edac30eae20b3"
    )
    for other in ("h28", "h53"):
        previous = json.loads(trial.request_body("B", case=other))
        assert {key: value for key, value in wire.items() if key != "input"} == {
            key: value for key, value in previous.items() if key != "input"
        }
    payload = json.loads(wire["input"])
    assert payload["asset_context"] == {"version": "3.1"}
    admitted, = payload["candidate_rows"]
    row = json.loads(admitted["osv_row"])
    assert row == {"package": {"ecosystem": "PyPI", "name": "leekvale-bell"}}
    assert all(label not in wire["input"] for label in (
        "h75", "npm", "expected", "/affected/", "matched_pointers", "proposed_outcome",
    ))


@pytest.mark.parametrize(("proposal", "status"), [("unknown", "abstained"), ("affected", "refused"),
                                                   ("unaffected", "refused")])
def test_h75_replay_distinguishes_warranted_abstention_and_unsupported_claim(proposal, status):
    payload = json.loads(json.loads(trial.request_body("B", case="h75"))["input"])
    row, = payload["candidate_rows"]
    ids = [] if proposal == "unknown" else [row["row_id"]]
    raw = response_body(output=[{"type": "message", "role": "assistant", "status": "completed",
                                 "content": [{"type": "output_text", "text": json.dumps({
                                     "proposed_outcome": proposal, "selected_row_ids": ids,
                                 })}]}])
    result = trial.replay("B", raw, case="h75")
    assert result["draft"]["proposed_outcome"] == proposal
    assert result["input_request_provenance"] == "unverified"
    assert result["check"]["status"] == status
    assert result["check"]["reportable_outcome"] == "unknown"
    assert result["check"]["references"] == []
