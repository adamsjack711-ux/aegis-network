"""Exercise the frozen synthetic h84 gate with scripted drafts and no provider."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from score import case_inputs, load, pack, raw_hash


def review_entrypoint(checkout, trial, a_wire, b_wire, raw_a, invalid_a):
    from openai_responses_adapter import parse_reply
    from osv_row_selection import DRAFT_LIMIT

    entrypoint = checkout / "benchmarks/phase6-offline-fixture-freeze/h84_linked_trial.py"

    def invoke(*args):
        return subprocess.run(
            [sys.executable, "-B", str(entrypoint), *args],
            check=False,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": str(checkout / "src")},
            timeout=5,
        )

    a_result = invoke("A")
    assert a_result.returncode == 0 and a_result.stderr == b"" and a_result.stdout == a_wire
    wire = json.loads(a_wire)
    message = {
        "type": "message", "role": "assistant", "status": "completed",
        "content": [{"type": "output_text", "text": raw_a.decode()}],
    }
    retained_envelope = pack({
        "id": "resp_h84_scripted_review", "object": "response", "status": "completed",
        "model": wire["model"], "service_tier": wire["service_tier"], "store": wire["store"],
        "output": [message], "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
    })
    reply = parse_reply(retained_envelope, wire["model"], 10261, wire["max_output_tokens"],
                        draft_type=trial.DRAFT_TYPES["A"])
    extracted = json.loads(retained_envelope)["output"][0]["content"][0]["text"].encode()
    assert extracted == raw_a and raw_hash(extracted) == reply.draft_sha256

    with TemporaryDirectory(prefix="aegis-h84-cli-") as folder:
        draft_path = Path(folder) / "stage-a-draft.json"
        draft_path.write_bytes(extracted)
        b_result = invoke("B", str(draft_path))
        assert b_result.returncode == 0 and b_result.stderr == b"" and b_result.stdout == b_wire

        refused = {}
        for name, raw in {**invalid_a, "full-envelope": retained_envelope}.items():
            draft_path.write_bytes(raw)
            result = invoke("B", str(draft_path))
            assert result.returncode == 2 and result.stdout == b"" and result.stderr.startswith(b"h84: ")
            refused[name] = {"exit": result.returncode, "stdout_bytes": len(result.stdout),
                             "diagnostic": result.stderr.decode().strip()}

        missing = invoke("B", str(Path(folder) / "missing.json"))
        assert missing.returncode == 2 and missing.stdout == b""
        assert missing.stderr == b"h84: local input unavailable\n"
        draft_path.write_bytes(raw_a + b" " * DRAFT_LIMIT)
        oversized = invoke("B", str(draft_path))
        assert oversized.returncode == 2 and oversized.stdout == b""
        assert oversized.stderr == b"h84: identity-draft-byte-limit\n"

    return {
        "A_wire_sha256": raw_hash(a_result.stdout),
        "scripted_A_envelope_sha256": reply.reply_sha256,
        "extracted_A_draft_sha256": reply.draft_sha256,
        "linked_B_wire_sha256": raw_hash(b_result.stdout),
        "blocked_A_controls": refused,
        "oversized_A_draft": "blocked with zero stdout bytes",
        "missing_A_draft_file": "blocked with zero stdout bytes",
    }


def replay(checkout, check_entrypoint=False):
    sys.path[:0] = [
        str(checkout / "src"),
        str(checkout / "benchmarks/phase6-offline-fixture-freeze"),
    ]
    import osv_two_stage as checker
    import two_stage_trial as trial

    frozen = load("preselection-h84.json")
    labels = Path("seal/oracle/labels.json").read_bytes()
    assert raw_hash(labels) == frozen["labels_sha256"]
    label, = (
        item for item in json.loads(labels)
        if (item["case"], item["variant"]) == (frozen["case"], frozen["variant"])
    )
    assert raw_hash(pack(label)) == frozen["case_gold_sha256"]
    source, target = case_inputs(label)
    assert raw_hash(source) == frozen["source_sha256"]
    assert raw_hash(target) == frozen["target_sha256"]
    asset = json.loads(target)
    expected_a = frozen["A"]
    expected_b = frozen["linked_B"]

    stage_a = checker.prepare_a(source, target)
    assert stage_a["status"] == "prepared"
    assert stage_a["request_sha256"] == expected_a["prepared_sha256"]
    a_wire = trial.build_request("A", stage_a)
    a_payload = json.loads(json.loads(a_wire)["input"])
    assert set(a_payload) == {"asset_context", "candidate_rows"}
    assert a_payload["asset_context"] == {key: asset[key] for key in ("ecosystem", "package")}
    a_rows = a_payload["candidate_rows"]
    originals = json.loads(source)["affected"]
    for row, original in zip(a_rows, originals, strict=True):
        package = original["package"]
        assert set(row) == {"row_id", "ecosystem", "package", "purl", "purl_present"}
        assert row["ecosystem"] == package["ecosystem"]
        assert row["package"] == package["name"]
        assert row["purl"] == package.get("purl")
        assert row["purl_present"] == ("purl" in package)
    first, decoy, last = (row["row_id"] for row in a_rows)
    assert [first, last] == expected_a["row_ids"]
    assert len({first, decoy, last}) == 3

    def identity(outcome, *ids):
        return pack({"identity_outcome": outcome, "selected_row_ids": ids})

    def version(outcome, *ids):
        return pack({"proposed_outcome": outcome, "selected_row_ids": ids})

    controls = {}
    invalid_a = {}
    for name, raw_a, a_status in (
        ("first-singleton", identity("match", first), "refused"),
        ("last-singleton", identity("match", last), "refused"),
        ("decoy-only", identity("match", decoy), "refused"),
        ("decoy-substitution", identity("match", first, decoy), "refused"),
        ("decoy-extra", identity("match", first, decoy, last), "refused"),
        ("unknown", identity("unknown"), "abstained"),
    ):
        observed_a = checker.check_a(source, target, raw_a)
        linked_b = checker.prepare_b(source, target, raw_a, arm="linked")
        assert observed_a["status"] == a_status and observed_a["matched_pointers"] == []
        assert linked_b["status"] == "blocked" and linked_b["upstream_status"] == a_status
        assert "payload" not in linked_b and "request_sha256" not in linked_b
        assert not linked_b["references"]
        invalid_a[name] = raw_a
        controls[name] = {
            "A": a_status,
            "B": linked_b["status"],
            "reason": linked_b["reason"],
            "B_decision_opportunities": 0,
        }

    # Reverse the draft IDs to check set equality and pass the actual draft bytes to B.
    raw_a = b" " + identity("match", last, first) + b"\n"
    observed_a = checker.check_a(source, target, raw_a)
    assert observed_a["status"] == "verified"
    assert observed_a["identity_outcome"] == expected_a["expected"]
    assert sorted(observed_a["matched_pointers"]) == sorted(expected_a["complete_set"])
    linked_b = checker.prepare_b(source, target, raw_a, arm="linked")
    assert linked_b["status"] == "prepared" and linked_b["arm"] == "linked"
    assert linked_b["request_sha256"] == expected_b["prepared_sha256"]
    b_wire = trial.build_request("B", linked_b)
    b_payload = json.loads(json.loads(b_wire)["input"])
    assert set(b_payload) == {"asset_context", "candidate_rows"}
    assert b_payload["asset_context"] == {"version": asset["version"]}
    for row, row_id, reference in zip(
        b_payload["candidate_rows"], expected_b["row_ids"], expected_b["expected_refs"], strict=True
    ):
        assert set(row) == {"row_id", "osv_row"} and row["row_id"] == row_id
        span = source[reference["byte_start"]:reference["byte_end"]]
        assert row["osv_row"].encode() == span
        assert raw_hash(span) == reference["row_sha256"]

    observed_b = checker.check_b(
        source, target, raw_a, version("unaffected", *expected_b["row_ids"]), arm="linked"
    )
    assert observed_b["status"] == "verified"
    assert observed_b["reportable_outcome"] == expected_b["expected"]
    for actual, expected in zip(observed_b["references"], expected_b["expected_refs"], strict=True):
        assert actual["source_sha256"] == frozen["source_sha256"]
        for key in ("pointer", "byte_start", "byte_end"):
            assert actual[key] == expected[key]
        raw_row = actual["osv_row"].encode()
        assert raw_row == source[expected["byte_start"]:expected["byte_end"]]
        assert raw_hash(raw_row) == expected["row_sha256"]

    b_controls = {}
    for name, raw_b, status in (
        ("unknown", version("unknown"), "abstained"),
        ("one-support-reference", version("unaffected", expected_b["row_ids"][0]), "refused"),
        ("incorrect-decision", version("affected", *expected_b["row_ids"]), "refused"),
    ):
        observed = checker.check_b(source, target, raw_a, raw_b, arm="linked")
        assert observed["status"] == status
        assert observed["reportable_outcome"] == "unknown" and observed["references"] == []
        b_controls[name] = {"status": status, "precision": None, "support": [0, 2]}

    report = {
        "case": "original/h84",
        "draft_source": "independent scripted controls",
        "A": {
            "status": observed_a["status"],
            "exact_set": observed_a["matched_pointers"],
            "prepared_sha256": stage_a["request_sha256"],
            "wire_sha256": raw_hash(a_wire),
        },
        "B": {
            "arm": "linked",
            "decision": observed_b["reportable_outcome"],
            "prepared_sha256": linked_b["request_sha256"],
            "wire_sha256": raw_hash(b_wire),
            "reference_precision": [2, 2],
            "support_coverage": [2, 2],
        },
        "blocked_A_controls": controls,
        "B_controls_after_admission": b_controls,
    }
    if check_entrypoint:
        invalid_a["oracle-admission"] = pack({"matched_pointers": expected_a["complete_set"]})
        report["candidate_CLI"] = review_entrypoint(
            checkout, trial, a_wire, b_wire, raw_a, invalid_a,
        )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("--check-entrypoint", action="store_true")
    args = parser.parse_args()
    print(json.dumps(replay(args.checkout.resolve(), args.check_entrypoint), indent=2))
