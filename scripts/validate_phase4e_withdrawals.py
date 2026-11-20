"""Independent withdrawal status oracle. Run from an archived Phase 4E-C checkout."""

import argparse
import base64
from collections import Counter
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
import secrets
import sqlite3
from tempfile import TemporaryDirectory
import time

from aegis.evidence.records import SignedWithdrawal, sign_record
from aegis.evidence.runner import ENVIRONMENT_SHA256
from aegis.journal.protocol import JournalBlocked
from aegis.phase4e.protocol import Leaf, Wire
from scripts.phase4e_lab import Lab


def data(value):
    return value.model_dump(mode="json") if hasattr(value, "model_dump") else value


def encoded(value, *, ascii_only=False):
    return json.dumps(data(value), ensure_ascii=ascii_only, separators=(",", ":"), sort_keys=True).encode()


def sha(value):
    return sha256(encoded(value)).hexdigest()


def check_signature(key, domain, body, signature):
    key.public_key().verify(bytes.fromhex(signature), domain + b"\0" + encoded(body))


def verify_receipt(lab, witness, leaf):
    receipt = leaf.receipt
    assert len(receipt.votes) == 1 and receipt.votes[0].operator == witness
    assert receipt.admission.context == lab.policy.context and receipt.admission.event == sha(leaf.wire)
    check_signature(lab.keys[witness], b"aegis-journal-v1/admission", receipt.admission, receipt.votes[0].signature)
    record = json.loads(leaf.wire.raw)
    body = record["body"]
    assert leaf.wire.lane == "evidence" and body["kind"] == "aegis.evidence.withdrawal.v1"
    assert body["cohort"] == lab.config["cohort"]
    grant, = (row for row in lab.config["evidence"] if (row["issuer"], row["key_id"]) ==
              (body["issuer"], body["key_id"]))
    key = lab.evidence.revoker.public_key()
    assert key.public_bytes_raw().hex() == grant["public_key"] and grant["role"] == "revoker"
    assert body["cohort"] in grant["cohorts"] and body["target_issuer"] in grant["withdrawal_issuers"]
    assert body["target_kind"] in grant["withdrawal_kinds"]
    start = lab.epoch_width * receipt.admission.epoch
    earliest = max(start, body["issued_at"], grant["not_before"])
    assert earliest < min(start + lab.epoch_width, body["expires_at"], grant["expires_at"])
    key.verify(base64.b64decode(record["signature"], validate=True),
               b"AEGIS-EVIDENCE\0" + encoded(body, ascii_only=True))
    return body


def verify_view(lab, witness, request, view):
    assert view.witness == witness
    payload = [sha(request), witness, [sha(leaf) for leaf in view.leaves]]
    check_signature(lab.keys[witness], b"aegis-phase4e-v1/withdrawal-view.v2", payload, view.signature)
    return [verify_receipt(lab, witness, leaf) for leaf in view.leaves]


def verify_cut(lab, cut):
    assert len(cut.votes) >= 3 and len({v.operator for v in cut.votes}) == len(cut.votes)
    check_signature(lab.keys["cp"], b"aegis-journal-v1/head", cut.head, cut.signed.signature)
    for vote in cut.votes:
        check_signature(lab.keys[vote.operator], b"aegis-journal-v1/coverage", cut.signed, vote.signature)
    snapshot = lab.archive[0].snapshot(cut.head.size)

    def root(leaves):
        if len(leaves) == 1:
            return sha256(b"\x00" + encoded(leaves[0])).digest()
        split = 1 << ((len(leaves) - 1).bit_length() - 1)
        return sha256(b"\x01" + root(leaves[:split]) + root(leaves[split:])).digest()

    assert len(snapshot.leaves) == cut.head.size and root(snapshot.leaves).hex() == cut.head.root


def submit(lab, wire, witness="w0"):
    leaf = lab.admissions["review", "lab-v1"][witness].call("/admit", Leaf, wire)
    verify_receipt(lab, witness, leaf)
    return leaf


def change_withdrawal(lab, wire, **changes):
    body = SignedWithdrawal.model_validate_json(wire.raw).body.model_copy(update=changes)
    return Wire.from_bytes("evidence", sign_record(body, lab.evidence.revoker))


def outcome(call):
    started = time.perf_counter_ns()
    try:
        status = call()
        body = status.body if hasattr(status, "body") else status
        result = {"outcome": body.outcome, "reason": body.reason}
    except (JournalBlocked, OSError) as exc:
        result = {"outcome": "held", "reason": str(exc).split("\n", 1)[0]}
    result["ms"] = (time.perf_counter_ns() - started) / 1_000_000
    return result


@contextmanager
def fixture(**kwargs):
    with TemporaryDirectory(prefix="p4e-review-", dir="/tmp") as path:
        with Lab(Path(path), **kwargs) as lab:
            yield lab


def historical():
    with fixture() as lab:
        finding, bundle = lab.seed()
        cut = lab.seal_latest()
        verify_cut(lab, cut)
        assert lab.status(finding, bundle).body.outcome == "reproduced"
        leaf = submit(lab, lab.evidence_withdrawal(bundle))
        refreshed = lab.status(finding, bundle)
        assert refreshed.body.head == sha(cut.head)
        assert all(x.receipt.admission.event != leaf.receipt.admission.event
                   for x in lab.archive[0].snapshot(cut.head.size).leaves)
        assert refreshed.body.outcome == "reproduced"
        return {"historical_prediction_after_one_receipt": refreshed.body.outcome}


def availability_and_latency(size, profile, repeats):
    with fixture(profile=profile) as lab:
        finding, bundle = lab.seed()
        for index in range(size - 4):
            padding = lab.evidence.bundle(f"independent validation unrelated {index}")
            lab.append(lab.receive(Wire.from_bytes("evidence", padding.manifest), ("research", "lab-v1")))
        cut = lab.seal_latest()
        verify_cut(lab, cut)
        refresh = lambda: lab.status(finding, bundle)
        observations = {}
        captured_requests = {}
        if profile == "withdrawal-v2":
            lane = lab.reader.withdrawals
            for name, source in tuple(lane.sources.items()):
                def capture(request, name=name, source=source):
                    view = source(request)
                    verify_view(lab, name, request, view)
                    observed = time.time_ns() // 1_000_000
                    assert request.issued_ms <= observed < request.issued_ms + lab.policy.status_ms
                    captured_requests.setdefault(request.nonce, set()).add(name)
                    return view

                lane.sources[name] = capture
        observations["healthy"] = [outcome(refresh) for _ in range(repeats)]
        assert all(row["outcome"] == "reproduced" for row in observations["healthy"])
        if profile == "withdrawal-v2":
            assert len(captured_requests) == repeats
            assert all(names == set(lab.names) for names in captured_requests.values())
        lab.stop("w0")
        observations["one_lane_down"] = [outcome(refresh) for _ in range(repeats)]
        expected = "reproduced" if profile == "checkpoint-v1" else "held"
        assert all(row["outcome"] == expected for row in observations["one_lane_down"])
        lab.start("w0")
        lab.seal_latest()
        another_bundle = lab.evidence.bundle("unrelated bundle with authorized revocation")
        submit(lab, lab.evidence_withdrawal(another_bundle))
        observations["valid_unrelated"] = [outcome(refresh) for _ in range(repeats)]
        assert all(row["outcome"] == "reproduced" for row in observations["valid_unrelated"])
        submit(lab, lab.evidence_withdrawal(bundle))
        observations["exact_pre_inclusion"] = [outcome(refresh) for _ in range(repeats)]
        expected = "reproduced" if profile == "checkpoint-v1" else "inconclusive"
        assert all(row["outcome"] == expected for row in observations["exact_pre_inclusion"])
        return {"records": size, "profile": profile, "observations": observations}


def retained(path):
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as db:
        return [json.loads(wire) for wire, in db.execute("SELECT wire FROM ops ORDER BY position")]


def rejection(call, code):
    try:
        call()
    except OSError as exc:
        assert f"HTTP/{code}" in str(exc) or f"'{code} " in str(exc) or f" {code} " in str(exc), str(exc)
        return code
    raise AssertionError(f"expected HTTP {code}")


def ordering_and_restore():
    with fixture(profile="withdrawal-v2") as lab:
        finding, bundle = lab.seed()
        cut = lab.seal_latest()
        verify_cut(lab, cut)
        latest = lambda: lab.status(finding, bundle)
        assert latest().body.outcome == "reproduced"
        reader_db = Path(lab.reader_settings["withdrawals"]["db"])
        old = reader_db.read_bytes()
        wire = lab.evidence_withdrawal(bundle)
        wrong_issuer = change_withdrawal(lab, wire, target_issuer="ungranted-issuer")
        wrong_cohort = change_withdrawal(lab, wire, cohort="lab-green")
        credential = lab.admissions["research", "lab-v1"]["w0"]
        failures = [rejection(lambda: credential.call("/admit", Leaf, wire), 403),
                    rejection(lambda: submit(lab, wrong_issuer), 409),
                    rejection(lambda: submit(lab, wrong_cohort), 409)]
        assert latest().body.outcome == "reproduced" and retained(reader_db) == []

        # Delay an older-issued record, then submit it after a newer unrelated one.
        time.sleep(1.05)
        other_bundle = lab.evidence.bundle("newer unrelated record")
        newer = submit(lab, lab.evidence_withdrawal(other_bundle))
        earlier = submit(lab, wire)
        # This vote may fall in the same or next admission epoch. Both bind exact bytes.
        repeat = submit(lab, wire)
        assert earlier.receipt.admission.event == repeat.receipt.admission.event
        assert verify_receipt(lab, "w0", earlier)["issued_at"] < verify_receipt(lab, "w0", newer)["issued_at"]
        lane = lab.reader.withdrawals
        original = lane.sources["w0"]
        lane.sources["w0"] = lambda request: signed_view(lab, request, "w0", (earlier, newer))
        result = latest()
        assert result.body.reason == "revoked" and result.body.head == sha(cut.head)
        lane.sources["w0"] = lambda request: signed_view(lab, request, "w0", (newer, earlier))
        assert latest().body.reason == "revoked"
        lane.sources["w0"] = lambda request: signed_view(lab, request, "w0", (earlier, earlier))
        assert outcome(latest)["outcome"] == "held"
        lane.sources["w0"] = original
        assert latest().body.reason == "revoked"
        assert len(retained(reader_db)) == 2

        lab.stop("w0")
        lab.start("w0")
        lab.stop("status")
        lab.start("status")
        stored = lab.operators["w0"].call(
            f"/receipts/{earlier.receipt.admission.epoch}/{earlier.receipt.admission.event}", Leaf,
        )
        assert stored == earlier
        restarted = lab.new_reader()
        from aegis.phase4e.status import Gate

        restart_gate = Gate(restarted, lab.publisher.status, "lab-writer")
        restart = lambda: restart_gate.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256)
        assert restart().body.reason == "revoked"
        exact = reader_db.read_bytes()
        restarted.withdrawals.ledger.close()
        lab.reader.withdrawals.ledger.close()
        reader_db.write_bytes(old)
        try:
            lab.new_reader()
        except JournalBlocked:
            pass
        else:
            raise AssertionError("stale denial store reopened")
        reader_db.write_bytes(exact)
        restored = Gate(lab.new_reader(), lab.publisher.status, "lab-writer")
        assert restored.refresh(finding, bundle, expected_environment=ENVIRONMENT_SHA256).body.reason == "revoked"
        return {"unauthorized_http_codes": failures, "unique_durable_receipts": 2,
                "delayed_older_issue": "revoked", "reordered_view": "revoked", "duplicate_view_entries": "held",
                "repeated_admission": "deduplicated", "witness_publisher_reader_restart": "revoked",
                "stale_store_restore": "held", "exact_store_restore": "revoked"}


def signed_view(lab, request, name, leaves):
    from aegis.phase4e.protocol import WithdrawalView

    payload = [sha(request), name, [sha(leaf) for leaf in leaves]]
    signature = lab.keys[name].sign(b"aegis-phase4e-v1/withdrawal-view.v2\0" + encoded(payload)).hex()
    return WithdrawalView(witness=name, leaves=leaves, signature=signature)


def stale_and_conflicts():
    from aegis.phase4e.service import reader_from_config
    from aegis.phase4e.status import Publisher

    with TemporaryDirectory(prefix="p4e-split-", dir="/tmp") as path:
        lab = Lab(Path(path), profile="withdrawal-v2", status_ms=1000)
        alternate = lab.reader_config("alternate-status")
        with lab:
            finding, bundle = lab.seed()
            lab.seal_latest()
            refresh = lambda: lab.status(finding, bundle)
            assert refresh().body.outcome == "reproduced"
            genuine = lab.reader.withdrawals.sources["w0"]
            captured = []

            def capture(request):
                view = genuine(request)
                verify_view(lab, "w0", request, view)
                captured.append((request, view))
                return view

            lab.reader.withdrawals.sources["w0"] = capture
            assert refresh().body.outcome == "reproduced"
            lab.reader.withdrawals.sources["w0"] = lambda _: captured[-1][1]
            assert outcome(refresh)["outcome"] == "held"

            def delayed(request):
                view = genuine(request)
                sleep_past(request.issued_ms / 1000 + 1)
                return view

            lab.reader.withdrawals.sources["w0"] = delayed
            assert outcome(refresh)["outcome"] == "held"
            lab.reader.withdrawals.sources["w0"] = capture
            publisher = Publisher(reader_from_config(alternate, lab.policy, lab.reader.clock, connect=lab.connect),
                                  lab.keys["status"])
            lab.stack.callback(publisher.reader.withdrawals.ledger.close)
            sent = []

            def split(request):
                view = signed_view(lab, request, "w0", ())
                verify_view(lab, "w0", request, view)
                sent.append((request, view))
                return view

            publisher.reader.withdrawals.sources["w0"] = split
            lab.gate.fetch_status = publisher.publish
            other = lab.evidence.bundle("unrelated for split-view diagnosis")
            submit(lab, lab.evidence_withdrawal(other))
            assert refresh().body.outcome == "reproduced"
            assert sent[-1][0] == captured[-1][0] and sent[-1][1].leaves != captured[-1][1].leaves
            submit(lab, lab.evidence_withdrawal(bundle))
            blocked = outcome(refresh)
            assert blocked["outcome"] == "held" and "disagrees" in blocked["reason"]

            # Check the publisher endpoint directly. No relying gate can short-circuit this check.
            lab.stop("w3")
            request = captured[-1][0].model_copy(update={"nonce": secrets.token_hex(32),
                                                        "issued_ms": time.time_ns() // 1_000_000})
            assert outcome(lambda: lab.publisher.status(request))["outcome"] == "held"
            return {"old_nonce": "held", "delayed_valid_view": "held",
                    "relevant_same_nonce_conflict": "held", "unrelated_same_nonce_conflict": "reproduced",
                    "publisher_alone_missing_lane": "held"}


def approval_schedules():
    with fixture(profile="withdrawal-v2") as lab:
        finding, bundle = lab.seed()
        lab.seal_latest()
        approved = lab.status(finding, bundle)
        normal = lab.gate.fetch_status

        def between(request):
            submit(lab, lab.evidence_withdrawal(bundle))
            return normal(request)

        lab.gate.fetch_status = between
        hold = outcome(lambda: lab.status(finding, bundle))
        assert hold["outcome"] == "held" and "disagrees" in hold["reason"]
        try:
            with lab.gate.authorize(approved, approved.binding):
                raise AssertionError("previous approval survived observed refresh interruption")
        except JournalBlocked:
            pass
    with fixture(profile="withdrawal-v2") as lab:
        finding, bundle = lab.seed()
        lab.seal_latest()
        reviewed_binding = lab.status(finding, bundle).binding
        normal = lab.gate.fetch_status

        def after(request):
            result = normal(request)
            submit(lab, lab.evidence_withdrawal(bundle))
            return result

        lab.gate.fetch_status = after
        sampled = lab.status(finding, bundle)
        assert sampled.body.outcome == "reproduced"
        with lab.gate.authorize(sampled, reviewed_binding):
            entered_before_deadline = time.monotonic() < sampled.deadline
        assert entered_before_deadline
        lab.gate.fetch_status = normal
        assert lab.status(finding, bundle).body.reason == "revoked"
    return {"receipt_between_reader_and_publisher_samples": "held",
            "old_approval_after_observed_interruption": "held",
            "receipt_after_both_samples": "no-effect approval accepted within deadline",
            "retry_with_fresh_views": "revoked"}


def sleep_past(when, now=time.time):
    time.sleep(max(0, when - now()) + 0.030)


def expiry_probes():
    from aegis.phase4e.service import reader_from_config
    from aegis.phase4e.status import Publisher

    results = {}
    with TemporaryDirectory(prefix="p4e-deadline-", dir="/tmp") as path:
        lab = Lab(Path(path), profile="withdrawal-v2", status_ms=1000)
        alternate = lab.reader_config("clock-status")
        with lab:
            finding, bundle = lab.seed()
            lab.seal_latest()
            reader_pin = lab.reader.pin.read
            publish = lab.gate.fetch_status
            issued = []
            lab.gate.fetch_status = lambda request: issued.append(publish(request)) or issued[-1]

            def reader_delay():
                if issued:
                    sleep_past(issued[-1].body.expires_ms / 1000)
                return reader_pin()

            lab.reader.pin.read = reader_delay
            results["final_relying_anchor"] = outcome(lambda: lab.status(finding, bundle))
            results["final_relying_anchor"]["ms_after_signed_expiry"] = (
                time.time_ns() / 1_000_000 - issued[-1].body.expires_ms
            )
            lab.reader.pin.read, lab.gate.fetch_status = reader_pin, publish
            valid = lab.status(finding, bundle)

            def approval_delay():
                sleep_past(valid.deadline, time.monotonic)
                return reader_pin()

            lab.reader.pin.read = approval_delay
            try:
                with lab.gate.authorize(valid, valid.binding):
                    approval = "no-effect context entered"
            except JournalBlocked:
                approval = "held"
            results["approval_anchor"] = {"outcome": approval, "ms_after_deadline": (
                time.monotonic() - valid.deadline
            ) * 1000}
            lab.reader.pin.read = reader_pin

            pub_reader = reader_from_config(alternate, lab.policy, lab.reader.clock, connect=lab.connect)
            lab.stack.callback(pub_reader.withdrawals.ledger.close)
            publisher = Publisher(pub_reader, lab.keys["status"])
            pin_current = pub_reader.current
            checks = 0

            def delay_publisher(checkpoint, withdrawals):
                nonlocal checks
                checks += 1
                if checks == 2:
                    sleep_past(request.issued_ms / 1000 + 1)
                return pin_current(checkpoint, withdrawals)

            request = captured_request(lab, finding, bundle)
            pub_reader.current = delay_publisher
            results["final_publisher_anchor"] = outcome(lambda: publisher.publish(request))
            results["final_publisher_anchor"]["ms_after_signed_expiry"] = (
                time.time_ns() / 1_000_000 - (request.issued_ms + 1000)
            )
            assert checks == 2
    return results


def captured_request(lab, finding, bundle):
    seen = []
    original = lab.gate.fetch_status

    def capture(request):
        seen.append(request)
        return original(request)

    lab.gate.fetch_status = capture
    try:
        assert lab.status(finding, bundle).body.outcome == "reproduced"
    finally:
        lab.gate.fetch_status = original
    return seen[0].model_copy(update={"nonce": secrets.token_hex(32), "issued_ms": time.time_ns() // 1_000_000})


def summarize(rows):
    return {"/".join((str(row["records"]), row["profile"])): {
        case: dict(Counter(sample["outcome"] for sample in samples))
        for case, samples in row["observations"].items()
    } for row in rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--historical", action="store_true")
    parser.add_argument("--repeats", type=int, default=12)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("at least one sample is required")
    report = {"revision": args.revision, "recorded_utc": datetime.now(timezone.utc).isoformat(),
              "platform": platform.platform(), "python": platform.python_version(),
              "oracle_sha256": sha256(Path(__file__).read_bytes()).hexdigest(), "violations": []}
    if args.historical:
        report.update(historical())
    else:
        trials = [availability_and_latency(size, profile, args.repeats)
                  for size, profiles in ((4, ("checkpoint-v1", "withdrawal-v2")),
                                         (128, ("withdrawal-v2", "checkpoint-v1")))
                  for profile in profiles]
        report.update(trials=trials, totals=summarize(trials), ordering_and_restore=ordering_and_restore(),
                      stale_and_conflicts=stale_and_conflicts(), approval_schedules=approval_schedules(),
                      expiry=expiry_probes())
        report["violations"] = [probe for probe, observation in report["expiry"].items()
                                if observation["outcome"] != "held"]
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "trials"}, indent=2))
    raise SystemExit(1 if report["violations"] else 0)


if __name__ == "__main__":
    main()
