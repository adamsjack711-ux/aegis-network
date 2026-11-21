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
    assert trial.replay(stage, raw)["check"]["status"] == "abstained"
    other = "B" if stage == "A" else "A"
    with pytest.raises(Refused):
        trial.replay(other, raw)
