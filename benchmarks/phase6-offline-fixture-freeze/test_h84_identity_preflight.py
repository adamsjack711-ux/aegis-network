"""Check the pinned h84 export and the retained Stage A evidence gate offline."""

from hashlib import sha256
import json
import subprocess
import sys

import pytest

import h84_identity_preflight as review
import h84_linked_trial as h84
from osv_row_selection import canonical
from test_openai_one_shot import response_body


def run_review(*args):
    return subprocess.run([sys.executable, "-B", review.__file__, *args], capture_output=True, check=False)


def test_create_and_count_preserve_the_exact_reviewed_fields():
    create, count = review.frozen_a()
    assert create == h84.request_a()
    fields = {"input", "instructions", "model", "text", "tool_choice", "tools"}
    wire = json.loads(create)
    assert json.loads(count) == {name: wire[name] for name in fields}
    for mode, expected in (("create", create), ("count", count)):
        result = run_review(mode)
        assert result.returncode == 0 and result.stderr == b"" and result.stdout == expected


def write_scripted_receipts(directory, outcome, indices):
    payload = json.loads(json.loads(h84.request_a())["input"])
    ids = [row["row_id"] for row in payload["candidate_rows"]]
    draft = json.dumps({"identity_outcome": outcome, "selected_row_ids": [ids[i] for i in indices]}, indent=2)
    output = [{"type": "message", "role": "assistant", "status": "completed",
               "content": [{"type": "output_text", "text": draft}]}]
    raw = response_body(output=output)
    wire_sha = review.A_CREATE[1]
    transport = {"evaluated_contract_body_sha256": wire_sha, "response_sha256": sha256(raw).hexdigest(),
                 "draft_sha256": sha256(draft.encode()).hexdigest(), "model": review.MODEL,
                 "input_tokens": 436, "output_tokens": 60}
    records = {
        "attempt": canonical({"attempt": 1, "request_sha256": wire_sha}),
        "http": canonical({"http_status": 200}),
        "response": raw,
        "transport": canonical(transport),
    }
    for artifact, data in records.items():
        (directory / f"h84-two-stage-A.{artifact}.json").write_bytes(data)
    return draft.encode()


def test_complete_retained_draft_uses_the_linked_renderer(tmp_path):
    draft = write_scripted_receipts(tmp_path, "match", (2, 0))
    result = run_review("linked-b", str(tmp_path), "436")
    assert result.returncode == 0 and result.stderr == b""
    assert result.stdout == h84.request_b(draft)


@pytest.mark.parametrize(("case", "reason"), [
    ("partial", "identity-selection-is-incomplete-or-incorrect"),
    ("abstained", "identity-abstained"),
    ("wrong-http", "Stage A attempt or HTTP receipt mismatch"),
    ("wrong-digest", "Stage A transport receipt mismatch"),
    ("over-limit", "response envelope, draft or usage refused"),
    ("missing-attempt", "retained input unavailable or invalid"),
])
def test_refused_review_emits_no_stage_b_bytes(tmp_path, case, reason):
    if case == "partial":
        write_scripted_receipts(tmp_path, "match", (0,))
    elif case == "abstained":
        write_scripted_receipts(tmp_path, "unknown", ())
    else:
        write_scripted_receipts(tmp_path, "match", (2, 0))

    if case == "wrong-http":
        (tmp_path / "h84-two-stage-A.http.json").write_bytes(canonical({"http_status": 500}))
    elif case == "wrong-digest":
        path = tmp_path / "h84-two-stage-A.transport.json"
        record = json.loads(path.read_bytes())
        path.write_bytes(canonical(record | {"response_sha256": "0" * 64}))
    elif case == "missing-attempt":
        (tmp_path / "h84-two-stage-A.attempt.json").unlink()

    limit = "435" if case == "over-limit" else "436"
    result = run_review("linked-b", str(tmp_path), limit)
    assert result.returncode == 2 and result.stdout == b""
    assert result.stderr == f"h84 preflight: {reason}\n".encode()
