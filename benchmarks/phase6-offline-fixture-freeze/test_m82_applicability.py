"""Regression controls for the separate v2 synthetic m82 request and local checks."""

from functools import partial
from hashlib import sha256
import json
import os
from pathlib import Path

import pytest

import m82_applicability as trial
from openai_responses_adapter import Refused, parse_reply
from replay import canonical

CONTEXT_QUOTE = '"asset":{"alias":"asset-1","version":"8.6"}'
SUMMARY_QUOTE = '"summary":"The note about dry-canvas refers to a separate inventory."'


@pytest.fixture
def sealed():
    return trial.load_m82(Path(os.environ["AEGIS_TEST_M82_INPUTS"]))


@pytest.fixture
def accepted_request():
    return Path(os.environ["AEGIS_TEST_REVIEW_BODY"]).read_bytes()


def wire(outcome, quote=None, source_id="S1", kind="applicability"):
    claims = [] if quote is None else [{"kind": kind, "source_id": source_id, "quote": quote}]
    return canonical({"proposed_outcome": outcome, "claims": claims, "uncertainties": []})


def test_request_contains_only_exact_source_evidence_and_separate_asset_context(sealed, accepted_request):
    raw, count = trial.request_objects(sealed, accepted_request)
    body = json.loads(raw)
    manifest = trial.request_manifest(sealed, raw, count)
    assert manifest["create_body_sha256"] == "e90bc1b7aab14d23f9c535e8f3faafb8eaea4bb724e389c3b7a447a0982eedfe"
    assert manifest["count_projection_sha256"] == "1dcd3825c83000369b0f5eae7ac4935ca0dc74641649a90fb6dd49a7d115dce8"
    assert manifest["count_status"] == "no count for this projection"
    assert manifest["approval_status"] == "new approval required"
    logical = json.loads(body["input"])
    assert set(logical) == {"asset_context", "source_evidence"}
    assert logical["asset_context"] == {"ecosystem": "PyPI", "package": "plumrill-sheet", "version": "8.6"}
    evidence = logical["source_evidence"]
    quote = evidence["affected_row_verbatim"].encode()
    source, = sealed.sources
    assert source.content.count(quote) == 1
    assert quote == canonical(json.loads(source.content)["affected"][0])
    assert evidence["source_sha256"] == sha256(source.content).hexdigest()
    assert evidence["source_pointer"] == "/affected/0"
    assert b"dry-canvas" not in canonical(body) and b"baseline_outcome" not in canonical(body)
    marker = b'\n  "text": '
    assert raw.split(marker, 1)[1] == accepted_request.split(marker, 1)[1]
    assert json.loads(count)["text"] == json.loads(accepted_request)["text"]
    original = json.loads(accepted_request)
    assert {k: v for k, v in body.items() if k not in {"instructions", "input"}} == {
        k: v for k, v in original.items() if k not in {"instructions", "input"}
    }


@pytest.mark.parametrize(("proposal", "expected", "excerpts"), [
    ("unaffected", "unaffected", 1),
    ("affected", "unknown", 1),
    ("unknown", "unknown", 0),
])
def test_local_investigator_still_checks_admitted_drafts(sealed, proposal, expected, excerpts):
    quote = trial.source_evidence(sealed)["affected_row_verbatim"] if excerpts else None
    draft = trial.checked_draft(wire(proposal, quote), sealed)
    observed = trial.check_projected_draft(draft, sealed)
    assert observed["structured_outcome"] == "unaffected"
    assert observed["reportable_outcome"] == expected and observed["excerpts"] == excerpts
    assert observed["independently_verified"] is False
    assert [ref["pointer"] for ref in observed["applicability_references"]] == ["/affected/0"]


@pytest.mark.parametrize("quote", [CONTEXT_QUOTE, SUMMARY_QUOTE, '"fixed":"8.6"'])
def test_exact_but_nonapproved_source_quote_is_refused(sealed, quote):
    with pytest.raises(Refused, match="authorized exact S1"):
        trial.checked_draft(wire("unaffected", quote), sealed)


@pytest.mark.parametrize("transform", [
    lambda quote: wire("unaffected", quote, "S2"),
    lambda quote: wire("unaffected", quote.replace("plumrill-sheet", "plumrill")),
    lambda quote: wire("unaffected", None),
    lambda quote: wire("unknown", quote),
    lambda quote: canonical({"proposed_outcome": "unaffected", "claims": [
        {"source_id": "S1", "quote": quote, "kind": "impact"},
    ]}),
    lambda quote: canonical({"proposed_outcome": "unaffected", "claims": [
        {"source_id": "S1", "quote": quote}, {"source_id": "S1", "quote": quote},
    ]}),
])
def test_invalid_wire_shape_or_evidence_is_refused(sealed, transform):
    quote = trial.source_evidence(sealed)["affected_row_verbatim"]
    with pytest.raises(Refused):
        trial.checked_draft(transform(quote), sealed)


def test_shape_recorded_in_original_live_draft_is_refused(sealed):
    quote = trial.source_evidence(sealed)["affected_row_verbatim"]
    original_shape = canonical({"proposed_outcome": "unaffected", "claims": [
        {"kind": "applicability", "source_id": "S1", "quote": f'"affected":[{quote}]'},
        {"kind": "applicability", "source_id": "S1", "quote": CONTEXT_QUOTE},
        {"kind": "impact", "source_id": "S1", "quote": SUMMARY_QUOTE},
    ], "uncertainties": []})
    with pytest.raises(Refused, match="exactly one source claim"):
        trial.checked_draft(original_shape, sealed)


def test_raw_responses_envelope_checks_applicability_before_investigator(sealed):
    quote = trial.source_evidence(sealed)["affected_row_verbatim"]
    response = {
        "id": "resp_fixture", "object": "response", "status": "completed",
        "model": trial.MODEL, "service_tier": "default", "store": False,
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": wire("unaffected", quote).decode()}]}],
        "usage": {"input_tokens": 250, "output_tokens": 60, "total_tokens": 310},
    }
    parser = partial(trial.checked_draft, sealed=sealed)
    reply = parse_reply(canonical(response), trial.MODEL, None, 512, draft_parser=parser)
    assert trial.check_projected_draft(reply.draft, sealed)["reportable_outcome"] == "unaffected"
    response["output"][0]["content"][0]["text"] = wire("unaffected", SUMMARY_QUOTE).decode()
    with pytest.raises(Refused, match="authorized exact S1"):
        parse_reply(canonical(response), trial.MODEL, None, 512, draft_parser=parser)


@pytest.mark.parametrize(("case", "reportable"), [("good", "unaffected"), ("abstain", "unknown"),
                                                  ("metadata", None)])
def test_corrected_trial_through_shared_transport_and_local_verifier(sealed, accepted_request, tmp_path,
                                                                  case, reportable):
    from test_openai_one_shot import DUMMY_SECRET, fake_endpoint, observed, response_body

    quote = trial.source_evidence(sealed)["affected_row_verbatim"]
    raw_draft = {
        "good": wire("unaffected", quote), "abstain": wire("unknown"),
        "metadata": wire("unaffected", CONTEXT_QUOTE),
    }[case]
    raw = response_body(output=[{"type": "message", "role": "assistant", "status": "completed",
                                 "content": [{"type": "output_text", "text": raw_draft.decode()}]}])
    connection, log = fake_endpoint(tmp_path, reply=raw)

    def run():
        return trial.complete_m82_applicability(
            sealed, accepted_request=accepted_request, approved_body_sha256=trial.CREATE_SHA256, input_token_limit=10261,
            credential_reader=lambda: DUMMY_SECRET, deadline_seconds=0.5, connection_factory=connection,
        )

    if reportable is None:
        with pytest.raises(Refused, match="authorized exact S1"):
            run()
    else:
        observed_result = run()
        assert observed_result["reportable_outcome"] == reportable
        assert observed_result["dispatched_create_sha256"] == trial.CREATE_SHA256
        assert observed_result["raw_draft_sha256"] == sha256(raw_draft).hexdigest()
        assert observed_result["raw_reply_sha256"] == sha256(raw).hexdigest()
        assert observed_result["billing_verified"] is False
    posts = [event for event in observed(log) if event.get("method") == "POST"]
    assert len(posts) == 1 and posts[0]["digest"] == trial.CREATE_SHA256


@pytest.mark.parametrize("body_sha, limit", [
    (trial.HISTORICAL_BODY_SHA256, 10261),
    (trial.REJECTED_CREATE_SHA256, 10261),
    (trial.CREATE_SHA256, 0),
])
def test_old_approval_or_invalid_local_screen_refuses_before_credentials(sealed, accepted_request, body_sha,
                                                                         limit):
    def forbidden():
        pytest.fail("credential asked for before checking approval and usage screen")

    with pytest.raises(Refused):
        trial.complete_m82_applicability(
            sealed, accepted_request=accepted_request, approved_body_sha256=body_sha,
            input_token_limit=limit, credential_reader=forbidden,
        )


def test_custom_parser_runs_after_envelope_checks():
    from test_openai_one_shot import response_body

    def forbidden(_):
        pytest.fail("decoder invoked for the wrong model or invalid usage")

    for raw in (response_body(model="wrong-model"),
                response_body(usage={"input_tokens": 999, "output_tokens": 1, "total_tokens": 1000})):
        with pytest.raises(Refused, match="envelope"):
            parse_reply(raw, trial.MODEL, 436, 512, draft_parser=forbidden)



def test_opt_in_private_raw_schema_error_capture(sealed, accepted_request, tmp_path):
    from test_openai_one_shot import DUMMY_SECRET, fake_endpoint, observed

    error = (b'{"error":{"code":"invalid_json_schema","param":"text.format.schema",'
             b'"message":"Fixture-only provider error detail."}}')
    connection, log = fake_endpoint(tmp_path, status=400, reply=error)
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    destination = directory / "raw-error.json"
    with pytest.raises(Refused, match="HTTP 400 refused; raw diagnostic retained") as refusal:
        trial.complete_m82_applicability(
            sealed, accepted_request=accepted_request, approved_body_sha256=trial.CREATE_SHA256,
            input_token_limit=10261, credential_reader=lambda: DUMMY_SECRET,
            deadline_seconds=0.5, connection_factory=connection, error_body_path=destination,
        )
    assert "Fixture-only" not in str(refusal.value)
    assert destination.read_bytes() == error and destination.stat().st_mode & 0o777 == 0o600
    assert sum(event.get("method") == "POST" for event in observed(log)) == 1


@pytest.mark.parametrize("error", [
    b"x" * (16_384 + 1),
    b'{"error":{"message":"fake-test-token-never-sent"}}',
])
def test_raw_error_diagnostic_refuses_oversize_or_credential_echo(sealed, accepted_request, tmp_path, error):
    from test_openai_one_shot import DUMMY_SECRET, fake_endpoint, observed

    connection, log = fake_endpoint(tmp_path, status=400, reply=error)
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    destination = directory / "raw-error.json"
    with pytest.raises(Refused, match="HTTP 400 refused; raw diagnostic unavailable"):
        trial.complete_m82_applicability(
            sealed, accepted_request=accepted_request, approved_body_sha256=trial.CREATE_SHA256,
            input_token_limit=10261, credential_reader=lambda: DUMMY_SECRET, deadline_seconds=0.5,
            connection_factory=connection, error_body_path=destination,
        )
    assert not destination.exists()
    calls = observed(log)
    assert sum(event.get("method") == "POST" for event in calls) == 1
    assert [event["read"] for event in calls if "read" in event] == [16_385]
