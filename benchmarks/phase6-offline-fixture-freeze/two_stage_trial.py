"""Rebuild and check independently admitted synthetic two-stage requests offline."""

import argparse
from hashlib import sha256
from pathlib import Path

from openai_one_shot import MODEL
from openai_responses_adapter import RAW_REPLY_LIMIT, REQUEST_LIMIT, decode_json, parse_reply
from osv_row_selection import Selection, canonical
from osv_two_stage import IdentityDraft, check_a, check_b, prepare_a, prepare_b


FIXTURE = Path(__file__).resolve().parents[1] / "phase6-two-stage-independent/seal/inputs/original/h28"
SOURCE_SHA = "81f9150c58f408a6768de70bde9de09d1098c9c2741b008614708d132f2517d5"
TARGET_SHA = "86a6f71341ed3d775bbe58115346b129dcea54f033167be59a3e43107a757cce"
ADMISSION = canonical({"matched_pointers": ["/affected/1"]})
DRAFT_TYPES = {"A": IdentityDraft, "B": Selection}
H53_SOURCE_SHA = "d4e658704f4c8b1946a231f06157815a24c8a7a5bfe3d5e33f6beeb6e6a01b22"
H53_TARGET_SHA = "b0d348e1e1e2c5e97dfdffd6f2dbbeac9b45499eb22ff88f36f4d14a67537b54"
# Admission only, from f0c6330:benchmarks/phase6-two-stage-independent/preselection-h53.json.
H53_ADMISSION = canonical({"matched_pointers": ["/affected/2"]})
CASES = {
    "h28": (SOURCE_SHA, TARGET_SHA, ADMISSION),
    "h53": (H53_SOURCE_SHA, H53_TARGET_SHA, H53_ADMISSION),
}


def fixture(case="h28"):
    source_sha, target_sha, _ = CASES[case]
    folder = FIXTURE.with_name(case)
    source = (folder / "source.json").read_bytes()
    target = (folder / "target.json").read_bytes()
    if sha256(source).hexdigest() != source_sha or sha256(target).hexdigest() != target_sha:
        raise ValueError(f"{case} fixture digest mismatch")
    return source, target


def build_request(stage, prepared):
    if prepared["status"] != "prepared" or prepared["stage"] != stage:
        raise ValueError("stage did not prepare a request")
    draft_schema = DRAFT_TYPES[stage].model_json_schema()
    field = "identity_outcome" if stage == "A" else "proposed_outcome"
    schema = {
        "type": "object", "additionalProperties": False,
        "properties": {
            field: {"type": "string", "enum": draft_schema["properties"][field]["enum"]},
            "selected_row_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": [field, "selected_row_ids"],
    }
    body = canonical({
        "model": MODEL, "service_tier": "default", "store": False,
        "max_output_tokens": 512, "tools": [], "tool_choice": "none",
        "instructions": prepared["instructions"], "input": canonical(prepared["payload"]).decode(),
        "text": {"format": {"type": "json_schema", "strict": True, "schema": schema,
                            "name": "identity_selection" if stage == "A" else "version_selection"}},
    })
    if len(body) > REQUEST_LIMIT:
        raise ValueError("wire body exceeds transport limit")
    return body


def request_body(stage, *, case="h28"):
    source, target = fixture(case)
    admission = CASES[case][2]
    prepared = prepare_a(source, target) if stage == "A" else prepare_b(source, target, admission, arm="oracle")
    return build_request(stage, prepared)


def replay(stage, raw, *, case="h28"):
    if len(raw) > RAW_REPLY_LIMIT:
        raise ValueError("saved response exceeds the transport limit")
    reply = parse_reply(raw, MODEL, 10261, 512, draft_type=DRAFT_TYPES[stage])
    message, = (item for item in decode_json(raw)["output"] if item["type"] == "message")
    draft_bytes = message["content"][0]["text"].encode()
    source, target = fixture(case)
    admission = CASES[case][2]
    result = (check_a(source, target, draft_bytes) if stage == "A"
              else check_b(source, target, admission, draft_bytes, arm="oracle"))
    return {"check": result, "draft": reply.draft.model_dump(mode="json"),
            "draft_sha256": reply.draft_sha256, "response_sha256": reply.reply_sha256,
            "evaluated_contract_body_sha256": sha256(request_body(stage, case=case)).hexdigest(),
            "input_request_provenance": "unverified", "model": reply.model,
            "input_tokens": reply.input_tokens, "output_tokens": reply.output_tokens}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=DRAFT_TYPES)
    parser.add_argument("--case", choices=CASES, default="h28")
    parser.add_argument("--response", type=Path, help="saved raw Responses API JSON for offline scoring")
    args = parser.parse_args()
    import sys
    if args.response:
        with args.response.open("rb") as saved:
            result = replay(args.stage, saved.read(RAW_REPLY_LIMIT + 1), case=args.case)
        sys.stdout.buffer.write(canonical(result) + b"\n")
    else:
        sys.stdout.buffer.write(request_body(args.stage, case=args.case))
