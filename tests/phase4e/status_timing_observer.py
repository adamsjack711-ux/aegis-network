"""Independent deadline checks using a synthetic clock and in-memory anchors."""

import json
from threading import RLock
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from aegis.journal.protocol import Clock, JournalBlocked, digest
from aegis.phase4e import status as shadow
from aegis.phase4e.protocol import SignedStatus, Status, Wire, message


START_UTC = 1_800_000_000.0
START_MONOTONIC = 10.0
ERROR = 0.125
SIGNED_EXPIRY_MS = 1_800_000_000_375
PIN = "a" * 64


@pytest.mark.parametrize("actor", ["refresh", "authorization", "publication"])
@pytest.mark.parametrize(
    ("fault", "utc_change", "monotonic_change", "read_budget", "allows"),
    [
        ("within-bounds", 0.125, 0.125, 1.0, True),
        ("utc-at-exclusive-expiry", 0.25, 0.125, 1.0, False),
        ("earlier-monotonic-at-expiry", -0.125, 0.25, 1.0, False),
        ("earlier-reader-deadline", 0.0, 0.125, 0.125, False),
        ("monotonic-regression", 0.0, -0.125, 1.0, False),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_independent_shadow_deadlines(actor, fault, utc_change, monotonic_change, read_budget, allows,
                                     monkeypatch, record_property):
    utc, monotonic = START_UTC, START_MONOTONIC
    clock = Clock(lambda: utc, lambda: monotonic, error=ERROR)
    key = Ed25519PrivateKey.generate()
    policy = SimpleNamespace(publisher=SimpleNamespace(key=key.public_key()), context=PIN,
                             cohort="lab-blue", trust=None, profiles=())
    history = SimpleNamespace(withdrawal_floor=b"withdrawal")
    read_deadline = START_MONOTONIC + read_budget
    calls = []
    apply_change = actor != "authorization"

    def current(checkpoint, withdrawals):
        nonlocal utc, monotonic
        assert (checkpoint, withdrawals) == (b"checkpoint", b"withdrawal")
        calls.append((utc, monotonic))
        if apply_change:
            utc += utc_change
            monotonic += monotonic_change
        return True

    reader = SimpleNamespace(policy=policy, clock=clock, lock=RLock(), current=current,
                             read=lambda _: (None, history, read_deadline, b"checkpoint"))
    manifest = SimpleNamespace(claim_sha256=PIN)
    monkeypatch.setattr(shadow, "_admit", lambda *_: SimpleNamespace(manifest=manifest))
    monkeypatch.setattr(shadow, "check_bundle", lambda *_: None)
    monkeypatch.setattr(shadow, "finding_wire", lambda _: Wire.from_bytes("mesh", b"timing-only"))
    monkeypatch.setattr(shadow, "material_scope", lambda _: PIN)

    def appraisal(_policy, challenge, _head, _history, _now):
        return Status(challenge=digest(challenge), head=PIN, outcome="reproduced", reason="fixture",
                      attestations=(), expires_ms=SIGNED_EXPIRY_MS)

    monkeypatch.setattr(shadow, "appraise", appraisal)
    publisher = shadow.Publisher(reader, key)

    def signed_fixture(challenge):
        body = appraisal(policy, challenge, None, history, utc)
        return SignedStatus(body=body, signature=key.sign(message("status", body)).hex())

    gate = shadow.Gate(reader, signed_fixture, "timing-fixture")
    finding = SimpleNamespace(finding=None)
    bundle = SimpleNamespace(sha256=PIN)

    def refresh():
        return gate.refresh(finding, bundle, expected_environment=PIN)

    entered = False
    if actor == "authorization":
        verified = refresh()
        assert verified.body.outcome == "reproduced"
        assert verified.deadline == min(read_deadline, START_MONOTONIC + 0.25)
        apply_change = True

    try:
        if actor == "refresh":
            result = refresh()
            assert result.deadline == min(read_deadline, START_MONOTONIC + 0.25)
        elif actor == "authorization":
            with gate.authorize(verified, verified.binding):
                entered = True
        else:
            signed = publisher.publish(None)
            key.public_key().verify(bytes.fromhex(signed.signature), message("status", signed.body))
        outcome = "allowed"
    except JournalBlocked as error:
        outcome = str(error)

    assert len(calls) == (2 if actor == "authorization" else 1)
    record_property("shadow_timing_guard", json.dumps({
        "actor": actor, "fault": fault, "decision": outcome, "authorization_entered": entered,
        "before_final_read": calls[-1], "after_final_read": [utc, monotonic],
        "reader_deadline": read_deadline, "signed_expiry_ms": SIGNED_EXPIRY_MS,
        "clock_error": ERROR, "expected_allow": allows,
    }, sort_keys=True))
    assert (outcome == "allowed") == allows
    assert entered == (actor == "authorization" and allows)
    if not allows:
        assert ("rolled back" if fault == "monotonic-regression" else "expired") in outcome
