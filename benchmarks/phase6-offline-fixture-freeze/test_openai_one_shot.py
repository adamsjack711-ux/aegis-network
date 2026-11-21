"""Offline-only checks: every adapter call supplies an in-process fake connection."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from time import monotonic, sleep
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

import openai_one_shot as trial
from openai_responses_adapter import RAW_REPLY_LIMIT, Refused, complete_responses_once
from replay import canonical

DUMMY_SECRET = "fake-test-token-never-sent"


@pytest.fixture
def frozen():
    sealed = trial.load_m82(Path(os.environ["AEGIS_TEST_M82_INPUTS"]))
    body, count = trial.review_body(Path(os.environ["AEGIS_TEST_REVIEW_BODY"]), sealed)
    return sealed, body, count


def response_body(**updates):
    draft = {"proposed_outcome": "unaffected", "claims": [
        {"source_id": "S1", "kind": "applicability", "quote": '"fixed":"8.6"'}], "uncertainties": []}
    reply = {
        "id": "resp_test_fixture", "object": "response", "status": "completed",
        "model": trial.MODEL, "service_tier": "default", "store": False,
        "output": [{"type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": canonical(draft).decode()}]}],
        "usage": {"input_tokens": 436, "output_tokens": 60, "total_tokens": 496},
    }
    return canonical({**reply, **updates})


def fake_endpoint(tmp_path, *, reply=None, status=200, stall_at=None):
    log = tmp_path / "calls.jsonl"

    def record(**event):
        with log.open("ab") as output:
            output.write(canonical(event) + b"\n")

    class FakeResponse:
        length = None

        def getheader(self, name, default):
            return "application/json" if name == "Content-Type" else default

        def read(self, amount):
            record(read=amount)
            if stall_at == "body":
                sleep(5)
            return reply[:amount]

    class FakeConnection:
        def __init__(self, host, *, port, timeout):
            record(host=host, port=port, timeout=timeout)

        def request(self, method, path, body, headers):
            record(method=method, path=path, digest=sha256(body).hexdigest(),
                   auth=headers["Authorization"] == f"Bearer {DUMMY_SECRET}",
                   identity=headers["Accept-Encoding"] == "identity")

        def getresponse(self):
            if stall_at == "headers":
                sleep(5)
            response = FakeResponse()
            response.status = status
            return response

        def close(self):
            record(closed=True)

    return FakeConnection, log


def fake_call(tmp_path, body, *, digest=trial.BODY_SHA256, **options):
    connection_factory, log = fake_endpoint(tmp_path, **options)

    def credential():
        with log.open("ab") as output:
            output.write(b'{"credential":true}\n')
        return DUMMY_SECRET

    def invoke():
        return complete_responses_once(
            body, body_sha256=digest, model=trial.MODEL, input_token_limit=436,
            credential_reader=credential, deadline_seconds=0.4, connection_factory=connection_factory,
        )

    return invoke, log


def observed(log):
    return [json.loads(row) for row in log.read_bytes().splitlines()]


def test_frozen_wire_and_count_projection(frozen):
    _, body, count = frozen
    assert len(body) == 2914
    assert sha256(body).hexdigest() == trial.BODY_SHA256
    assert set(count) == {"input", "instructions", "model", "text", "tool_choice", "tools"}
    logical = json.loads(count["input"])
    assert "baseline_outcome" not in logical and "configuration_present" not in logical["asset"]
    assert count["text"]["format"]["strict"] is True


def test_success_through_reusable_adapter_and_local_checker(frozen, tmp_path):
    sealed, body, _ = frozen
    run, log = fake_call(tmp_path, body, reply=response_body())
    report = trial.check_response(run(), sealed)
    assert report["reportable_outcome"] == "unaffected"
    assert report["applicability_references"][0]["pointer"] == "/affected/0"
    assert report["provider_reported_usage"] == {"input_tokens": 436, "output_tokens": 60, "total_tokens": 496}
    assert report["independently_verified"] is False and report["billing_verified"] is False
    events = observed(log)
    assert events == [
        {"credential": True}, {"host": "api.openai.com", "port": 443, "timeout": 0.4},
        {"method": "POST", "path": "/v1/responses", "digest": trial.BODY_SHA256,
         "auth": True, "identity": True},
        {"read": RAW_REPLY_LIMIT + 1}, {"closed": True},
    ]


@pytest.mark.parametrize("stalled", ["headers", "body"])
def test_supervised_deadline_has_no_retries(frozen, tmp_path, stalled):
    _, body, _ = frozen
    run, log = fake_call(tmp_path, body, stall_at=stalled)
    started = monotonic()
    with pytest.raises(Refused, match="deadline"):
        run()
    elapsed = monotonic() - started
    assert 0.35 <= elapsed <= 1.0
    events = observed(log)
    assert sum("method" in event for event in events) == 1
    assert any("read" in event for event in events) == (stalled == "body")


@pytest.mark.parametrize("status", [307, 429, 503])
def test_failed_http_status_never_reads_reply_or_retries(frozen, tmp_path, status):
    _, body, _ = frozen
    run, log = fake_call(tmp_path, body, status=status)
    with pytest.raises(Refused, match="HTTP"):
        run()
    events = observed(log)
    assert sum("method" in event for event in events) == 1
    assert not any("read" in event for event in events)


@pytest.mark.parametrize("reply", [
    b" " * (RAW_REPLY_LIMIT + 1),
    b'{"malformed":',
    response_body(model="wrong-model"),
    response_body(usage={"input_tokens": 437, "output_tokens": 60, "total_tokens": 497}),
    response_body(usage={"input_tokens": 436, "output_tokens": 513, "total_tokens": 949}),
    response_body(output=[{"type": "message", "role": "assistant", "status": "completed",
                           "content": [{"type": "output_text", "text": " " * 4097}]}]),
    response_body(output=[{"type": "message", "role": "assistant", "status": "completed",
                           "content": [{"type": "refusal", "refusal": "unavailable"}]}]),
    response_body(output=[{"type": "function_call", "name": "unapproved"}]),
    response_body(output=[{"type": "message", "role": "assistant", "status": "completed",
                           "content": [{"type": "output_text", "text": canonical({
                               "proposed_outcome": "affected", "claims": [], "uncertainties": [],
                               "extra": "field",
                           }).decode()}]}]),
    response_body(usage=None),
    response_body(store=True),
    response_body(extra=DUMMY_SECRET),
])
def test_invalid_response_fails_closed(frozen, tmp_path, reply):
    _, body, _ = frozen
    run, log = fake_call(tmp_path, body, reply=reply)
    with pytest.raises(Refused) as outcome:
        run()
    assert DUMMY_SECRET not in str(outcome.value)
    assert sum("method" in event for event in observed(log)) == 1


@pytest.mark.parametrize("replace, use_new_digest", [
    ({"input": "modified"}, False),
    ({"tools": [{"type": "web_search"}]}, True),
    ({"max_output_tokens": 513}, True),
])
def test_refused_request_never_loads_credential(frozen, tmp_path, replace, use_new_digest):
    _, body, _ = frozen
    altered = canonical({**json.loads(body), **replace})
    digest = sha256(altered).hexdigest() if use_new_digest else trial.BODY_SHA256
    run, log = fake_call(tmp_path, altered, digest=digest)
    with pytest.raises(Refused, match="request"):
        run()
    assert not log.exists()


def signed_approval(**update):
    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(minutes=5)).isoformat()
    statement = {
        "plan": trial.PLAN, "operator_uid": os.getuid(), "expires_at": expires,
        "charge_basis": trial.CHARGE_BASIS, "retention_evidence_sha256": "a" * 64,
        **update,
    }
    envelope = {"statement": statement, "signature": key.sign(canonical(statement)).hex()}
    return envelope, key.public_key(), now


@pytest.mark.parametrize("update", [
    {"operator_uid": -1},
    {"expires_at": "2020-01-01T00:00:00Z"},
    {"charge_basis": {**trial.CHARGE_BASIS, "counted_input_tokens": 437}},
    {"charge_basis": {**trial.CHARGE_BASIS, "binding_charge_ceiling_verified": True}},
    {"charge_basis": {**trial.CHARGE_BASIS, "estimated_charge_usd": "0.011"}},
    {"retention_evidence_sha256": ""},
    {"plan": {**trial.PLAN, "method": "GET"}},
])
def test_signed_but_invalid_approval_is_refused(update):
    envelope, key, now = signed_approval(**update)
    with pytest.raises(Refused, match="approval"):
        trial.authorize(envelope, key, now, os.getuid())


def test_approval_signature_is_required_and_binds_caps():
    envelope, key, now = signed_approval()
    bound, _ = trial.authorize(envelope, key, now, os.getuid())
    assert bound == 436
    envelope["statement"]["charge_basis"] = {**trial.CHARGE_BASIS, "counted_input_tokens": 435}
    with pytest.raises(Refused, match="approval"):
        trial.authorize(envelope, key, now, os.getuid())


def test_only_one_attempt_claim_survives_concurrency(tmp_path):
    def claim():
        try:
            trial.claim_attempt(tmp_path, "a" * 64)
            return True
        except Refused:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: claim(), range(2))) == [False, True]
    marker, = tmp_path.iterdir()
    assert marker.stat().st_mode & 0o777 == 0o600
    assert json.loads(marker.read_bytes())["body_sha256"] == trial.BODY_SHA256
    assert claim() is False


def test_cli_default_dispatch_refuses_before_owner_key_or_secret(frozen, monkeypatch, capsys):
    def fail():
        pytest.fail("credential or owner key path was touched")

    monkeypatch.setattr(trial, "load_owner_key", fail)
    monkeypatch.setattr(trial, "complete_responses_once", fail)
    monkeypatch.setattr(sys, "argv", ["openai_one_shot.py", "dispatch",
                                    os.environ["AEGIS_TEST_REVIEW_BODY"], os.environ["AEGIS_TEST_M82_INPUTS"]])
    assert trial.main() == 1
    assert "requires enrolled operator approval" in capsys.readouterr().err



@pytest.mark.parametrize("http_status", [200, 503])
def test_one_shot_cli_uses_adapter_once_with_fake_approval(frozen, tmp_path, monkeypatch, capsys, http_status):
    envelope, key, _ = signed_approval()
    approval_file = tmp_path / "approval.json"
    approval_file.write_bytes(canonical(envelope))
    connection_factory, log = fake_endpoint(tmp_path, reply=response_body(), status=http_status)

    def use_fake(body, **kwargs):
        return complete_responses_once(body, **kwargs, deadline_seconds=0.4,
                                       connection_factory=connection_factory)

    monkeypatch.setattr(trial, "load_owner_key", lambda: key)
    monkeypatch.setattr(trial, "complete_responses_once", use_fake)
    user = SimpleNamespace(pw_dir=str(tmp_path))
    monkeypatch.setattr(trial.pwd, "getpwuid", lambda uid: user)
    monkeypatch.setattr(sys, "argv", ["openai_one_shot.py", "dispatch",
                                    os.environ["AEGIS_TEST_REVIEW_BODY"], os.environ["AEGIS_TEST_M82_INPUTS"],
                                    "--approval", str(approval_file)])
    original = os.dup(0)
    reader, writer = os.pipe()
    try:
        os.write(writer, DUMMY_SECRET.encode() + b"\n")
        os.close(writer)
        os.dup2(reader, 0)
        assert trial.main() == int(http_status != 200)
        stdout, stderr = capsys.readouterr()
        assert DUMMY_SECRET not in stdout + stderr
        if http_status == 200:
            assert stderr == "" and json.loads(stdout)["reportable_outcome"] == "unaffected"
        else:
            assert stdout == "" and "HTTP response refused" in stderr
        assert trial.main() == 1
        assert "already consumed" in capsys.readouterr().err
    finally:
        os.dup2(original, 0)
        os.close(original)
        os.close(reader)
    events = observed(log)
    assert sum("method" in event for event in events) == 1
    assert any(event.get("auth") is True for event in events)



def test_invalid_credential_is_never_forwarded_or_echoed(frozen, tmp_path):
    _, body, _ = frozen
    connection_factory, log = fake_endpoint(tmp_path, reply=response_body())

    def invalid():
        raise Refused(DUMMY_SECRET)

    with pytest.raises(Refused, match="^credential unavailable or invalid$"):
        complete_responses_once(
            body, body_sha256=trial.BODY_SHA256, model=trial.MODEL, input_token_limit=436,
            credential_reader=invalid, deadline_seconds=0.4, connection_factory=connection_factory,
        )
    assert not log.exists()


@pytest.mark.parametrize("installed_matches", [True, False])
def test_owner_signer_waits_for_verifier_readback(frozen, tmp_path, monkeypatch, installed_matches):
    from sign_openai_trial import CONFIRMATION, PLAN_SHA256, review_inputs, run_signing_session

    receipt = Path(os.environ["AEGIS_TEST_COUNT_RECEIPT"])
    review_inputs(Path(os.environ["AEGIS_TEST_REVIEW_BODY"]), Path(os.environ["AEGIS_TEST_M82_INPUTS"]), receipt)
    output = tmp_path / "disposable-signer"
    installed = tmp_path / "simulated-verifier"

    def fake_owner(prompt):
        if prompt.startswith("Verified effective"):
            return "standard"
        if prompt.startswith("Type SHARING OFF"):
            return "SHARING OFF"
        if prompt.startswith("Enter the SHA-256"):
            assert not (output / "phase6-openai-approval.json").exists()
            public = (output / "phase6-openai-operator.pub").read_bytes()
            installed.write_bytes(public if installed_matches else b"different verifier")
            return sha256(installed.read_bytes()).hexdigest()
        assert prompt.startswith("Type APPROVE") and installed_matches
        return CONFIRMATION

    monkeypatch.setattr("builtins.input", fake_owner)
    if not installed_matches:
        with pytest.raises(Refused, match="installed verifier did not match"):
            run_signing_session(output)
        assert sorted(path.name for path in output.iterdir()) == ["phase6-openai-operator.pub"]
        return

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    run_signing_session(output)
    assert sorted(path.name for path in output.iterdir()) == [
        "phase6-openai-approval.json", "phase6-openai-operator.pub", "retention-review.json",
    ]
    envelope = json.loads((output / "phase6-openai-approval.json").read_bytes())
    record = (output / "retention-review.json").read_bytes()
    assert envelope["statement"]["charge_basis"]["binding_charge_ceiling_verified"] is False
    assert envelope["statement"]["charge_basis"]["estimated_charge_usd"] == "0.002631"
    assert envelope["statement"]["retention_evidence_sha256"] == sha256(record).hexdigest()
    assert json.loads(record)["plan_sha256"] == PLAN_SHA256
    assert trial.authorize(envelope, Ed25519PublicKey.from_public_bytes(installed.read_bytes()),
                           datetime.now(timezone.utc), 501)[0] == 436


def test_signer_refuses_modified_count_receipt(frozen, tmp_path):
    from sign_openai_trial import review_inputs

    receipt = tmp_path / "wrong-receipt.json"
    receipt.write_bytes(Path(os.environ["AEGIS_TEST_COUNT_RECEIPT"]).read_bytes() + b"\n")
    with pytest.raises(Refused, match="reviewed 436-token receipt"):
        review_inputs(Path(os.environ["AEGIS_TEST_REVIEW_BODY"]), Path(os.environ["AEGIS_TEST_M82_INPUTS"]), receipt)
