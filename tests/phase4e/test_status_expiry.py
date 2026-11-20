"""The final anchor or signer response cannot bring back expired authority."""

from pathlib import Path
from tempfile import TemporaryDirectory
import time

import pytest

from aegis.journal.protocol import JournalBlocked
from aegis.phase4e.service import reader_from_config
from aegis.phase4e.status import Publisher
from scripts.phase4e_lab import Lab


def wait_past(utc):
    time.sleep(max(0, utc - time.time()) + 0.025)


@pytest.fixture
def lab():
    with TemporaryDirectory(prefix="p4e-expiry-", dir="/tmp") as path:
        instance = Lab(Path(path), profile="withdrawal-v2", status_ms=1000)
        independent_publisher = instance.reader_config("slow-publisher")
        with instance:
            finding, bundle = instance.seed()
            instance.seal_latest()
            yield instance, finding, bundle, independent_publisher


def test_relying_status_checks_time_after_final_anchor(lab):
    instance, finding, bundle, _ = lab
    original = instance.reader.pin.read
    publish = instance.gate.fetch_status
    signed = []

    def capture(request):
        signed.append(publish(request))
        return signed[-1]

    def late_anchor():
        if signed:
            wait_past(signed[-1].body.expires_ms / 1000)
        return original()

    instance.gate.fetch_status = capture
    instance.reader.pin.read = late_anchor
    with pytest.raises(JournalBlocked, match="expired during appraisal"):
        instance.status(finding, bundle)
    assert signed[-1].body.outcome == "reproduced"


def test_approval_checks_time_after_final_anchor(lab):
    instance, finding, bundle, _ = lab
    status = instance.status(finding, bundle)
    assert status.body.outcome == "reproduced"
    original = instance.reader.pin.read

    def late_anchor():
        time.sleep(max(0, status.deadline - time.monotonic()) + 0.025)
        return original()

    instance.reader.pin.read = late_anchor
    with pytest.raises(JournalBlocked, match="expired before approval use"):
        with instance.gate.authorize(status, status.binding):
            pytest.fail("expired context opened")


@pytest.mark.parametrize("delay", ["anchor", "signer"])
def test_publisher_checks_time_after_final_io(lab, delay):
    instance, finding, bundle, config = lab
    reader = reader_from_config(config, instance.policy, instance.reader.clock, connect=instance.connect)
    instance.stack.callback(reader.withdrawals.ledger.close)
    key = instance.keys["status"]
    publisher = Publisher(reader, key)
    current = reader.current
    request = None
    checks = 0

    def delayed_current(checkpoint, withdrawals):
        nonlocal checks
        checks += 1
        if checks == 2:
            wait_past((request.issued_ms + instance.policy.status_ms) / 1000)
        return current(checkpoint, withdrawals)

    class SlowSigner:
        def sign(self, body):
            wait_past((request.issued_ms + instance.policy.status_ms) / 1000)
            return key.sign(body)

    if delay == "anchor":
        reader.current = delayed_current
    else:
        publisher.key = SlowSigner()

    def capture(challenge):
        nonlocal request
        request = challenge
        return publisher.publish(challenge)

    instance.gate.fetch_status = capture
    with pytest.raises(JournalBlocked, match="expired before publication"):
        instance.status(finding, bundle)


@pytest.mark.parametrize("actor", ["publisher", "relying reader"])
def test_shorter_signed_expiry_keeps_early_monotonic_bound(monkeypatch, actor):
    from threading import RLock
    from types import SimpleNamespace

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from aegis.journal.protocol import Clock
    from aegis.phase4e import status as shadow
    from aegis.phase4e.protocol import SignedStatus, Status, Wire, message

    utc, monotonic = 1_800_000_000.0, 10.0
    clock = Clock(lambda: utc, lambda: monotonic, error=0.2)
    key = Ed25519PrivateKey.generate()
    pin = "a" * 64
    body = Status(challenge=pin, head=pin, outcome="reproduced", reason="fixture", attestations=(),
                  expires_ms=1_800_000_000_300)
    history = SimpleNamespace(withdrawal_floor=None)
    policy = SimpleNamespace(publisher=SimpleNamespace(key=key.public_key()), context=pin,
                             cohort="lab-blue", trust=None, profiles=())

    def current(_, __):
        nonlocal utc, monotonic
        utc -= 0.15  # Bounded UTC correction.
        monotonic += 0.15  # Past the earlier monotonic bound of 10.10.
        return True

    reader = SimpleNamespace(policy=policy, lock=RLock(), clock=clock,
                             read=lambda _: (None, history, 12.0, b"floor"), current=current)
    monkeypatch.setattr(shadow, "appraise", lambda *_: body)
    if actor == "publisher":
        with pytest.raises(JournalBlocked, match="expired before publication"):
            Publisher(reader, key).publish(None)
    else:
        manifest = SimpleNamespace(claim_sha256=pin)
        monkeypatch.setattr(shadow, "_admit", lambda *_: SimpleNamespace(manifest=manifest))
        monkeypatch.setattr(shadow, "check_bundle", lambda *_: None)
        monkeypatch.setattr(shadow, "finding_wire", lambda _: Wire.from_bytes("mesh", b"test"))
        monkeypatch.setattr(shadow, "material_scope", lambda _: pin)

        def fetch(_):
            return SignedStatus(body=body, signature=key.sign(message("status", body)).hex())

        gate = shadow.Gate(reader, fetch, "lab-writer")
        with pytest.raises(JournalBlocked, match="expired during appraisal"):
            gate.refresh(SimpleNamespace(finding=None), SimpleNamespace(sha256=pin), expected_environment=pin)
