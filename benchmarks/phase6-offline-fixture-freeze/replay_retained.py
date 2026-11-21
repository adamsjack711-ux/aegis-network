"""Replay the retained synthetic h28 and h53 drafts in disposable SQLite."""

import argparse
from contextlib import closing
from dataclasses import asdict
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

from aegis.intelligence.feeds import FeedClient, snapshot
from aegis.intelligence.handoff import read_history
from aegis.intelligence.models import Asset
from aegis.intelligence.report import read_asset_report
from osv_row_selection import canonical, load_target
from osv_two_stage import check_b, prepare_b
import scratch_history_admission as benchmark
import two_stage_trial as bridge


def digest(raw):
    return sha256(raw).hexdigest()


def retained(receipts, case, stage):
    base = receipts / f"{case}-two-stage-{stage}"
    attempt = json.loads(Path(str(base) + ".attempt.json").read_bytes())
    http = json.loads(Path(str(base) + ".http.json").read_bytes())
    recorded = json.loads(Path(str(base) + ".transport.json").read_bytes())
    with Path(str(base) + ".response.json").open("rb") as response:
        raw = response.read(bridge.RAW_REPLY_LIMIT + 1)
    expected_body = bridge.request_body(stage, case=case)
    replayed = bridge.replay(stage, raw, case=case)
    assert type(attempt["attempt"]) is int and attempt["attempt"] == 1
    assert http["http_status"] == 200 and attempt["request_sha256"] == digest(expected_body)
    assert recorded == replayed
    assert recorded["evaluated_contract_body_sha256"] == digest(expected_body)
    assert recorded["input_request_provenance"] == "unverified"
    message, = (item for item in json.loads(raw)["output"] if item["type"] == "message")
    part, = message["content"]
    draft = part["text"].encode("utf-8")
    assert recorded["draft_sha256"] == digest(draft) and recorded["response_sha256"] == digest(raw)
    return draft, replayed["check"], {"http_status": 200, "attempt": 1, "wire_sha256": digest(expected_body),
                                      "response_sha256": digest(raw), "draft_sha256": digest(draft)}


def prepare_retained_case(receipts, case):
    source, target = bridge.fixture(case)
    identity, a_result, a_receipt = retained(receipts, case, "A")
    version, b_result, b_receipt = retained(receipts, case, "B")
    assert a_result["status"] == "verified" and a_result["identity_outcome"] == "match"
    assert b_result["status"] == "verified"
    oracle = prepare_b(source, target, bridge.CASES[case][2], arm="oracle")
    linked = prepare_b(source, target, identity, arm="linked")
    assert oracle["status"] == linked["status"] == "prepared"
    assert linked["request_sha256"] == oracle["request_sha256"]
    assert linked["instructions"] == oracle["instructions"] and linked["payload"] == oracle["payload"]
    linked_wire = bridge.build_request("B", linked)
    assert linked_wire == bridge.build_request("B", oracle) == bridge.request_body("B", case=case)
    assert digest(linked_wire) == b_receipt["wire_sha256"]
    linked_result = check_b(source, target, identity, version, arm="linked")
    assert linked_result["status"] == "verified"
    assert {key: value for key, value in linked_result.items() if key != "arm"} == {
        key: value for key, value in b_result.items() if key != "arm"
    }
    return source, target, identity, version, a_result, linked_result, a_receipt, b_receipt


def native_rows(path, advisory, subject, sequence):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as reader:
        return reader.execute("""
            SELECT investigation FROM research_results
            WHERE sequence=? AND vulnerability_id=? AND asset_digest=?
        """, (sequence, advisory, subject)).fetchall()


def admit_retained(trial, case, pack, now):
    raw, target_bytes, a_draft, b_draft, a_result, b_result, a_proof, b_proof = pack
    target = load_target(target_bytes)
    ecosystem = {"PyPI": "pypi", "npm": "npm"}[target.ecosystem]
    asset = Asset(asset_id=f"retained-{case}", identity_kind="purl",
                  identity=f"pkg:{ecosystem}/{target.package}", version=target.version)
    subject = benchmark.asset_digest(asset)
    advisory = json.loads(raw)["id"]
    uri = FeedClient().canonical_uri("osv", advisory)
    source = snapshot("osv", uri, raw, retrieved_at=now)
    event, = trial.scout.ingest(source)
    before = read_history(trial.path, "osv", advisory)
    assert before == []
    args = (event.sequence, advisory, source.sha256, asset, target_bytes, a_draft, b_draft)
    first = trial.admit(*args, now=now)
    assert first.outcome == "committed"
    history = read_history(trial.path, "osv", advisory)
    row, = history
    assert row["asset_digest"] == subject and row["revision"] == source.sha256 and row["status"] == "current"
    native = native_rows(trial.path, advisory, subject, event.sequence)
    assert len(native) == 1 and json.loads(native[0][0]) == row["research"]
    candidate = row["research"]["candidate"]
    audit = row["research"]["audit"]
    reported = read_asset_report(trial.path, "osv", advisory, advisory, subject)
    assert candidate["reportable_outcome"] == b_result["reportable_outcome"]
    assert reported["current"]["reportable_outcome"] == b_result["reportable_outcome"]
    assert reported["current"]["check_status"] == "research-consistent"
    assert candidate["provider"] == "scripted" and candidate["model"] == "scripted-v1"
    assert candidate["independently_verified"] is False and audit["cost_usd"] is None
    assert (audit["input_tokens"], audit["output_tokens"]) == (0, 0)
    refs = {(item["pointer"], item["sha256"]) for item in candidate["applicability_references"]}
    assert refs == {(item["pointer"], item["source_sha256"]) for item in b_result["references"]}
    witnesses = []
    for saved, expected in zip(candidate["excerpts"], b_result["references"], strict=True):
        begin, end = expected["byte_start"], expected["byte_end"]
        assert saved["source_sha256"] == source.sha256 == expected["source_sha256"]
        assert (saved["byte_start"], saved["byte_end"]) == (begin, end)
        assert raw[begin:end] == saved["quote"].encode() == expected["osv_row"].encode()
        witnesses.append({"pointer": expected["pointer"], "byte_start": begin, "byte_end": end,
                          "row_sha256": digest(raw[begin:end])})
    encoded = native[0][0]
    for proof in (a_proof, b_proof):
        assert all(proof[key] not in encoded for key in ("wire_sha256", "response_sha256", "draft_sha256"))
    assert "response_id" not in encoded and "provider_reported_usage" not in encoded
    repeat = trial.admit(*args, now=now)
    assert repeat.outcome == "duplicate"
    assert read_history(trial.path, "osv", advisory) == history
    assert native_rows(trial.path, advisory, subject, event.sequence) == native

    return {
        "identity_outcome": a_result["identity_outcome"],
        "reportable_outcome": candidate["reportable_outcome"], "source_sha256": row["revision"],
        "accepted_spans": witnesses, "linked_wire_equals_oracle": True,
        "first_receipt": asdict(first), "repeat_receipt": asdict(repeat),
        "results_before": 0, "results_after": 1, "results_after_duplicate": 1,
        "duplicate_preserved_raw_native_json": True, "stored_provider": candidate["provider"],
        "stored_model": candidate["model"], "stored_verification": candidate["independently_verified"],
        "stored_input_tokens": audit["input_tokens"], "stored_output_tokens": audit["output_tokens"],
        "stored_cost_usd": audit["cost_usd"], "stored_schema": candidate["schema_version"],
        "retained_receipts": {"A": a_proof, "B": b_proof},
    }


def run(receipts):
    packed = {case: prepare_retained_case(receipts, case) for case in ("h28", "h53")}
    freeze, _ = benchmark.sealed_inputs()
    now = datetime.fromisoformat(freeze["clock"])
    with benchmark.scratch() as trial:
        path = trial.path
        observed = {case: admit_retained(trial, case, value, now) for case, value in packed.items()}
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as fresh:
            count, = fresh.execute("SELECT count(*) FROM research_results").fetchone()
        assert count == 2
    assert not path.parent.exists()
    return {"scratch_rows_total": count, "scratch_removed": True,
            "clock": now.isoformat(), "cases": observed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipts_dir", type=Path, help="operator's private retained receipt directory")
    args = parser.parse_args()
    if not __debug__:
        parser.error("run with Python assertions enabled")
    if not args.receipts_dir.is_dir():
        parser.error("the private receipt directory is unavailable")
    print(json.dumps(run(args.receipts_dir), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
