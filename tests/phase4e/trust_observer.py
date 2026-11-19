"""Independent Phase 4E-C readback over the pinned Unix-socket service lab."""

from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time

import httpx
import pytest

from aegis.evidence.runner import ENVIRONMENT_SHA256
from aegis.journal.protocol import JournalBlocked
from aegis.phase4e.protocol import Leaf, SignedStatus
from aegis.phase4e.status import Gate
from scripts.phase4e_lab import Lab


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def read_db(path, query, parameters=()):
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as db:
        return db.execute(query, parameters).fetchall()


def read_http(remote, route, data=None):
    path = Path(remote["socket"])
    assert path.is_socket()
    with httpx.Client(transport=httpx.HTTPTransport(uds=str(path)), trust_env=False, timeout=2,
                      base_url="http://phase4e.local",
                      headers={"Authorization": "Bearer " + remote["token"]}) as client:
        if data is None:
            response = client.get(route)
        else:
            response = client.post(route, content=canonical(data))
        assert response.status_code == 200
        return response.json()


def verify_signature(key, domain, body, signature):
    key.verify(bytes.fromhex(signature), domain + b"\0" + canonical(body))


def verify_cut(lab, cut):
    data = cut.model_dump(mode="json")
    signed = data["signed"]
    policy = lab.policy.journal
    verify_signature(policy.coordinator, b"aegis-journal-v1/head", signed["head"], signed["signature"])
    assert len({vote["operator"] for vote in data["votes"]}) == len(data["votes"]) >= 3
    for vote in data["votes"]:
        verify_signature(policy.operators[vote["operator"]], b"aegis-journal-v1/coverage",
                         signed, vote["signature"])
    return signed


def test_E03_E05_independent_mirror_persists_revocation_after_witness_outage(record_property):
    with TemporaryDirectory(prefix="aegis-4ec-", dir="/tmp") as scratch, Lab(Path(scratch)) as lab:
        finding, bundle = lab.seed()
        first = verify_cut(lab, lab.seal_latest())
        publisher_key = lab.policy.publisher.key
        observed_status = []

        def fetch(challenge):
            request = challenge.model_dump(mode="json")
            wire = read_http(lab.status_remote, "/status", request)
            verify_signature(publisher_key, b"aegis-phase4e-v1/status", wire["body"], wire["signature"])
            assert wire["body"]["challenge"] == sha256(canonical(request)).hexdigest()
            assert request["subject"]["scope"]["bundle_sha256"] == bundle.sha256
            assert request["subject"]["audience"] == "lab-writer"
            observed_status.append({"challenge": request, "wire": wire,
                                    "key": publisher_key.public_bytes_raw().hex()})
            return SignedStatus.model_validate(wire)

        gate = Gate(lab.reader, fetch, "lab-writer")

        def status(current_gate):
            return current_gate.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256)

        database = lab.path / "test-writer.sqlite"
        expires = time.monotonic_ns() + 30_000_000_000
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("CREATE TABLE restrictions (target TEXT PRIMARY KEY, expires_ns INTEGER)")
        healthy = status(gate)
        reviewed = healthy.binding

        def commit_fixture(current_gate, target):
            current = status(current_gate)
            with current_gate.authorize(current, reviewed), closing(sqlite3.connect(database)) as db, db:
                db.execute("INSERT INTO restrictions VALUES (?, ?)", (target, expires))
                current_gate.require_current(current)

        # This writer is a test fixture and the row models a restrictive marker.
        commit_fixture(gate, "canary")
        assert read_db(database, "SELECT * FROM restrictions") == [("canary", expires)]
        withdrawal = lab.evidence_withdrawal(bundle)
        admitted = lab.receive(withdrawal, ("review", "lab-v1"))
        receipt = admitted.receipt.model_dump(mode="json")
        assert receipt["admission"]["event"] == sha256(canonical(withdrawal.model_dump(mode="json"))).hexdigest()
        assert len({vote["operator"] for vote in receipt["votes"]}) == len(receipt["votes"]) >= 3
        for vote in receipt["votes"]:
            verify_signature(lab.policy.journal.operators[vote["operator"]], b"aegis-journal-v1/admission",
                             receipt["admission"], vote["signature"])
        # Delay normal archive intake after quorum admission. The known canary
        # remains restrictive and the incomplete view cannot grant a peer write.
        with pytest.raises(JournalBlocked):
            commit_fixture(gate, "peer")
        held = read_db(database, "SELECT * FROM restrictions")
        assert held == [("canary", expires)]
        record_property("receipt_before_archive", json.dumps({"receipt": receipt, "restrictions": held}))
        lab.append(admitted)
        sealed = verify_cut(lab, lab.seal(lab.propose(admitted.receipt.admission.epoch)))
        assert sealed["head"]["size"] == first["head"]["size"] + 1
        assert sealed["head"]["epoch"] > first["head"]["epoch"]

        lab.stop("arc")
        lab.stop("w3")
        mirror = read_http(lab.reader_settings["archives"][1], f'/snapshot/{sealed["head"]["size"]}')
        assert mirror["leaves"][-1] == admitted.model_dump(mode="json")
        current = status(gate)
        assert (current.body.outcome, current.body.reason) == ("inconclusive", "revoked")
        with pytest.raises(JournalBlocked):
            commit_fixture(gate, "peer")
        lab.stop("w2")
        with pytest.raises(JournalBlocked):
            commit_fixture(gate, "peer")
        lab.start("w2")
        restarted = Gate(lab.new_reader(), fetch, "lab-writer")
        assert status(restarted).body.reason == "revoked"
        with pytest.raises(JournalBlocked):
            commit_fixture(restarted, "peer")

        pin, = read_db(lab.path / "anchor.db", "SELECT value FROM pins WHERE name = ?", ("writer",))
        floor = json.loads(pin[0])
        restrictions = read_db(database, "SELECT * FROM restrictions")
        record_property("verified_trust", json.dumps({
            "statuses": observed_status, "floor": floor, "mirror_leaf": mirror["leaves"][-1],
            "restrictions": restrictions,
        }, sort_keys=True))
        assert floor["verified"] == sealed and floor["pending"] is None
        assert restrictions == [("canary", expires)] and expires > time.monotonic_ns()


def test_W03_single_direct_admission_does_not_leave_positive_appraisal(record_property):
    """Strict release guard. Appraisal only, with no fixture write attempted."""
    with TemporaryDirectory(prefix="aegis-4ec-one-", dir="/tmp") as scratch, Lab(Path(scratch)) as lab:
        finding, bundle = lab.seed()
        cut = verify_cut(lab, lab.seal_latest())
        assert lab.status(finding, bundle).body.outcome == "reproduced"
        withdrawal = lab.evidence_withdrawal(bundle)
        one = lab.admissions["review", "lab-v1"]["w0"].call("/admit", Leaf, withdrawal)
        receipt = one.receipt.model_dump(mode="json")
        assert len(receipt["votes"]) == 1
        vote, = receipt["votes"]
        verify_signature(lab.policy.journal.operators["w0"], b"aegis-journal-v1/admission",
                         receipt["admission"], vote["signature"])
        assert receipt["admission"]["event"] == sha256(canonical(withdrawal.model_dump(mode="json"))).hexdigest()
        ledger = read_db(lab.path / "w0.db", "SELECT wire FROM ops ORDER BY position")
        assert any(receipt["admission"]["event"].encode() in wire for wire, in ledger)

        try:
            outcome = lab.status(finding, bundle).body.outcome
        except JournalBlocked:
            outcome = "unavailable"
        record_property("single_witness_admission", json.dumps({
            "outcome": outcome, "prior_head": cut, "direct_durable_receipt": receipt,
            "target_write_attempted": False,
        }, sort_keys=True))
        assert outcome != "reproduced", "one independently admitted withdrawal left a positive appraisal"
