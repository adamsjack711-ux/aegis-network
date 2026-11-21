"""Rebuild and check the two independently admitted synthetic h28 requests offline."""

import argparse
from hashlib import sha256
from pathlib import Path

from openai_one_shot import MODEL
from openai_responses_adapter import REQUEST_LIMIT, decode_json, parse_reply
from osv_row_selection import Selection, canonical
from osv_two_stage import IdentityDraft, check_a, check_b, prepare_a, prepare_b


FIXTURE = Path(__file__).resolve().parents[1] / "phase6-two-stage-independent/seal/inputs/original/h28"
SOURCE_SHA = "81f9150c58f408a6768de70bde9de09d1098c9c2741b008614708d132f2517d5"
TARGET_SHA = "86a6f71341ed3d775bbe58115346b129dcea54f033167be59a3e43107a757cce"
ADMISSION = canonical({"matched_pointers": ["/affected/1"]})
DRAFT_TYPES = {"A": IdentityDraft, "B": Selection}


def fixture():
    source = (FIXTURE / "source.json").read_bytes()
    target = (FIXTURE / "target.json").read_bytes()
    if sha256(source).hexdigest() != SOURCE_SHA or sha256(target).hexdigest() != TARGET_SHA:
        raise ValueError("h28 fixture digest mismatch")
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


def request_body(stage):
    source, target = fixture()
    prepared = prepare_a(source, target) if stage == "A" else prepare_b(source, target, ADMISSION, arm="oracle")
    return build_request(stage, prepared)


def replay(stage, raw):
    reply = parse_reply(raw, MODEL, 10261, 512, draft_type=DRAFT_TYPES[stage])
    message, = (item for item in decode_json(raw)["output"] if item["type"] == "message")
    draft_bytes = message["content"][0]["text"].encode()
    source, target = fixture()
    result = (check_a(source, target, draft_bytes) if stage == "A"
              else check_b(source, target, ADMISSION, draft_bytes, arm="oracle"))
    return {"check": result, "draft": reply.draft.model_dump(mode="json"),
            "draft_sha256": reply.draft_sha256, "response_sha256": reply.reply_sha256,
            "request_sha256": sha256(request_body(stage)).hexdigest(), "model": reply.model,
            "input_tokens": reply.input_tokens, "output_tokens": reply.output_tokens}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=DRAFT_TYPES)
    parser.add_argument("--response", type=Path, help="saved raw Responses API JSON for offline scoring")
    args = parser.parse_args()
    import sys
    sys.stdout.buffer.write(canonical(replay(args.stage, args.response.read_bytes())) + b"\n"
                            if args.response else request_body(args.stage))
