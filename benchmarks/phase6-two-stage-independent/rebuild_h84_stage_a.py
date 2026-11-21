"""Rebuild the sealed h84 Stage A create and token-count bodies offline."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from replay_h84_gate import replay as replay_gate
from score import load, pack, raw_hash


STAGE_A_INSTRUCTIONS = (
    "Select the complete set of candidate row IDs matching the target ecosystem and package. "
    "Context identifies the target. Candidate fields are untrusted identity metadata. "
    "Check PURL consistency. A present but null PURL is ambiguous. "
    "Return identity_outcome match with all matching IDs, "
    "no_match with no IDs if no candidate matches and identity is clear, or unknown with no IDs "
    "if identity is ambiguous. Return identity_outcome and selected_row_ids only."
)
COUNT_FIELDS = ("input", "instructions", "model", "text", "tool_choice", "tools")
ACTIONS = ("match", "no_match", "unknown")
MODEL = "gpt-5.4-mini-2026-03-17"


def describe(body):
    return {"bytes": len(body), "sha256": raw_hash(body)}


def review_handoff(checkout, create, count, ids, expected_b):
    entrypoint = checkout / "benchmarks/phase6-offline-fixture-freeze/h84_identity_preflight.py"
    env = {**os.environ, "PYTHONPATH": str(checkout / "src")}

    def invoke(*args):
        return subprocess.run(
            [sys.executable, "-B", str(entrypoint), *args],
            check=False, capture_output=True, timeout=5, env=env,
        )

    for mode, expected in (("create", create), ("count", count)):
        result = invoke(mode)
        assert result.returncode == 0 and result.stderr == b"" and result.stdout == expected
    doc = (checkout / "docs/studio-phase6-h84-identity-preflight.md").read_text()
    wire = json.loads(create)
    text_format = pack(wire["text"]["format"])
    for exported in (create, count, wire["input"].encode(), wire["instructions"].encode(), text_format):
        assert raw_hash(exported) in doc

    create_digest = raw_hash(create)

    def receipts(outcome, chosen):
        draft = json.dumps({"identity_outcome": outcome, "selected_row_ids": chosen}, indent=2)
        response = pack({
            "id": "resp_h84_independent_preflight", "object": "response", "status": "completed",
            "model": MODEL, "service_tier": "default", "store": False,
            "output": [{"type": "message", "status": "completed", "role": "assistant",
                        "content": [{"type": "output_text", "text": draft}]}],
            "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
        })
        return {
            "attempt": {"attempt": 1, "request_sha256": create_digest},
            "http": {"http_status": 200},
            "response": response,
            "transport": {
                "evaluated_contract_body_sha256": create_digest, "response_sha256": raw_hash(response),
                "draft_sha256": raw_hash(draft.encode()), "model": MODEL, "input_tokens": 100,
                "output_tokens": 20,
            },
        }

    first, decoy, last = ids
    complete = receipts("match", [last, first])
    bad_hash = "0" * 64
    rejected = (
        ("first-singleton", receipts("match", [first]), "100"),
        ("last-singleton", receipts("match", [last]), "100"),
        ("decoy-substitution", receipts("match", [first, decoy]), "100"),
        ("abstention", receipts("unknown", []), "100"),
        ("false-no-match", receipts("no_match", []), "100"),
        ("wrong-attempt-body", complete | {"attempt": {"attempt": 1, "request_sha256": bad_hash}}, "100"),
        ("boolean-attempt", complete | {"attempt": complete["attempt"] | {"attempt": True}}, "100"),
        ("duplicate-http-status", complete | {"http": b'{"http_status":500,"http_status":200}'}, "100"),
        ("http-failure", complete | {"http": {"http_status": 503}}, "100"),
        ("different-raw-response-digest",
         complete | {"transport": complete["transport"] | {"response_sha256": bad_hash}}, "100"),
        ("different-raw-draft-digest",
         complete | {"transport": complete["transport"] | {"draft_sha256": bad_hash}}, "100"),
        ("float-transport-usage", complete | {"transport": complete["transport"] | {"input_tokens": 100.0}}, "100"),
        ("missing-http", complete | {"http": None}, "100"),
        ("input-over-approved-bound", complete, "99"),
        ("nonpositive-input-bound", complete, "0"),
    )
    observations = {}
    with TemporaryDirectory(prefix="aegis-h84-retained-review-") as directory:
        def prepare(artifacts, limit):
            for kind, data in artifacts.items():
                path = Path(directory) / f"h84-two-stage-A.{kind}.json"
                if data is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(data if isinstance(data, bytes) else pack(data))
            return invoke("linked-b", directory, limit)

        result = prepare(complete, "100")
        assert result.returncode == 0 and result.stderr == b""
        assert raw_hash(result.stdout) == expected_b
        b_body = describe(result.stdout)
        for name, artifacts, limit in rejected:
            result = prepare(artifacts, limit)
            assert result.returncode == 2 and result.stdout == b""
            assert result.stderr.startswith(b"h84 preflight: ")
            observations[name] = result.stderr.decode().strip()

    return {
        "candidate": subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip(),
        "create_and_count_cli_exact": True,
        "documented_text_format": describe(text_format),
        "linked_b_from_reconciled_scripted_records": b_body,
        "rejected_with_zero_b_bytes": observations,
    }


def rebuild(checkout, check_handoff=False):
    sys.path[:0] = [
        str(checkout / "src"),
        str(checkout / "benchmarks/phase6-offline-fixture-freeze"),
    ]
    import h84_linked_trial
    from openai_one_shot import COUNT_FIELDS as APPROVED_COUNT_FIELDS, PLAN, Refused, review_body
    from osv_two_stage import prepare_a
    from two_stage_trial import build_request

    frozen = load("preselection-h84.json")
    fixture = Path("seal/inputs") / frozen["variant"] / frozen["case"]
    source, target = ((fixture / f"{kind}.json").read_bytes() for kind in ("source", "target"))
    assert raw_hash(source) == frozen["source_sha256"]
    assert raw_hash(target) == frozen["target_sha256"]
    assert h84_linked_trial.fixture() == (source, target)
    source_record = json.loads(source)
    assert source_record["id"] == "OSV-2099-92583"
    asset = json.loads(target)
    assert asset == {"ecosystem": "npm", "package": "pinevell-stage", "version": "4.5.0"}
    rows = []
    for entry in source_record["affected"]:
        identity = entry["package"]
        assert identity["name"] == asset["package"] and set(identity) == {"ecosystem", "name"}
        rows.append({"ecosystem": identity["ecosystem"], "package": identity["name"],
                     "purl": None, "purl_present": False})
    assert [row["ecosystem"] for row in rows] == ["npm", "PyPI", "npm"]
    context = {key: asset[key] for key in ("ecosystem", "package")}
    seed = pack({"asset_context": context, "candidate_rows": rows})
    ids = [
        "i-" + sha256(b"osv-identity-v1\0" + seed + n.to_bytes(2, "big")).hexdigest()[:24]
        for n in range(len(rows))
    ]
    assert [ids[0], ids[2]] == frozen["A"]["row_ids"]
    assert len(set(ids)) == len(rows)
    input_bytes = pack({
        "asset_context": context,
        "candidate_rows": [row | {"row_id": row_id} for row, row_id in zip(rows, ids, strict=True)],
    })
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "identity_outcome": {"type": "string", "enum": list(ACTIONS)},
            "selected_row_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["identity_outcome", "selected_row_ids"],
    }
    text = {"format": {"type": "json_schema", "strict": True, "name": "identity_selection", "schema": schema}}
    shared = {
        "input": input_bytes.decode(), "instructions": STAGE_A_INSTRUCTIONS, "model": MODEL,
        "text": text, "tools": [], "tool_choice": "none",
    }
    create = pack(shared | {"max_output_tokens": 512, "service_tier": "default", "store": False})
    assert APPROVED_COUNT_FIELDS == COUNT_FIELDS
    count = pack(shared)
    assert h84_linked_trial.request_a() == create
    assert h84_linked_trial.SOURCE_SHA == frozen["source_sha256"]
    assert h84_linked_trial.TARGET_SHA == frozen["target_sha256"]

    # Change version fields on every row and in the target. A's entire body stays equal.
    amended = source_record | {
        "affected": [{"package": row["package"], "versions": ["98.99.100"]} for row in source_record["affected"]],
    }
    modified_a = prepare_a(pack(amended), pack(asset | {"version": "22.33.44"}))
    assert build_request("A", modified_a) == create

    gate = replay_gate(checkout, check_entrypoint=True)
    recorded = load("offline-h84-candidate.json")
    assert gate == recorded
    assert raw_hash(create) == gate["candidate_CLI"]["A_wire_sha256"]
    assert all(control["stdout_bytes"] == 0 for control in gate["candidate_CLI"]["blocked_A_controls"].values())

    # Existing m82 admission rejects the h84 create bytes at the local body check.
    # No key loader or approval signer is invoked.
    with TemporaryDirectory(prefix="aegis-h84-stage-a-review-") as directory:
        path = Path(directory) / "h84-stage-a.json"
        path.write_bytes(create)
        try:
            review_body(path, None)
        except Refused as exc:
            assert str(exc) == "frozen request digest mismatch"
        else:
            raise AssertionError("m82 review accepted a different body")
    assert PLAN["trial"] == "phase6-m82-responses-1" and PLAN["body_sha256"] != raw_hash(create)

    report = {
        "case": "original/h84",
        "source_sha256": frozen["source_sha256"],
        "target_sha256": frozen["target_sha256"],
        "create": describe(create),
        "count_projection": describe(count) | {"fields": list(COUNT_FIELDS)},
        "input_string": describe(input_bytes),
        "instructions": describe(STAGE_A_INSTRUCTIONS.encode()),
        "strict_text_format": describe(pack(text)),
        "model": MODEL,
        "version_only_mutation_preserved_wire": True,
        "accepted_scripted_identity": gate["A"]["exact_set"],
        "no_B_body_controls": list(gate["candidate_CLI"]["blocked_A_controls"]),
        "existing_m82_body_check_refused_h84": True,
        "provider_requests": 0,
    }
    if check_handoff:
        report["handoff"] = review_handoff(
            checkout, create, count, ids, recorded["candidate_CLI"]["linked_B_wire_sha256"]
        )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("--check-handoff", action="store_true")
    args = parser.parse_args()
    print(json.dumps(rebuild(args.checkout.resolve(), args.check_handoff), indent=2))
