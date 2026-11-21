"""Render the h84 identity preflight and review a retained Stage A reply offline."""

import argparse
from hashlib import sha256
from pathlib import Path
import sys

import h84_linked_trial as h84
from openai_one_shot import COUNT_FIELDS, MODEL, read_bounded
from openai_responses_adapter import OUTPUT_TOKENS, RAW_REPLY_LIMIT, Refused, decode_json, parse_reply
from osv_row_selection import canonical
from osv_two_stage import IdentityDraft


A_CREATE = (1450, "92b5e3a2318e5221b11749e2e536efc183b034a4b7dbabd07d58fb6cfd622e20")
A_COUNT = (1387, "2decf8568cdda2ac4d1933cb642c49d82d780701bd9f72123df568f862f8cd25")


def frozen_a():
    create = h84.request_a()
    wire = decode_json(create)
    count = canonical({field: wire[field] for field in COUNT_FIELDS})
    for data, expected in ((create, A_CREATE), (count, A_COUNT)):
        if (len(data), sha256(data).hexdigest()) != expected:
            raise Refused("Stage A preflight bytes differ from the review pin")
    return create, count


def linked_b(receipts, input_token_limit):
    """Reconcile the operator's local records before passing raw A draft bytes to linked B."""
    if type(input_token_limit) is not int or input_token_limit < 1:
        raise Refused("Stage A needs the approved positive input-token limit")
    frozen_a()
    prefix = "h84-two-stage-A"
    attempt = decode_json(read_bounded(receipts / f"{prefix}.attempt.json", 2048))
    http = decode_json(read_bounded(receipts / f"{prefix}.http.json", 2048))
    if (type(attempt["attempt"]) is not int or attempt["attempt"] != 1
            or attempt["request_sha256"] != A_CREATE[1]
            or type(http["http_status"]) is not int or http["http_status"] != 200):
        raise Refused("Stage A attempt or HTTP receipt mismatch")

    raw = read_bounded(receipts / f"{prefix}.response.json", RAW_REPLY_LIMIT)
    reply = parse_reply(raw, MODEL, input_token_limit, OUTPUT_TOKENS, draft_type=IdentityDraft)
    recorded = decode_json(read_bounded(receipts / f"{prefix}.transport.json", RAW_REPLY_LIMIT))
    evidence = {
        "evaluated_contract_body_sha256": A_CREATE[1],
        "response_sha256": reply.reply_sha256,
        "draft_sha256": reply.draft_sha256,
        "model": reply.model,
        "input_tokens": reply.input_tokens,
        "output_tokens": reply.output_tokens,
    }
    if any(recorded[field] != value or type(recorded[field]) is not type(value)
           for field, value in evidence.items()):
        raise Refused("Stage A transport receipt mismatch")

    message, = (item for item in decode_json(raw)["output"] if item["type"] == "message")
    part, = message["content"]
    return h84.request_b(part["text"].encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("create", help="write the pinned Stage A create bytes")
    modes.add_parser("count", help="write the pinned Stage A count projection")
    review = modes.add_parser("linked-b", help="prepare Stage B for separate review")
    review.add_argument("receipts", type=Path, help="owner's retained Stage A receipt directory")
    review.add_argument("input_token_limit", type=int, help="Stage A limit from the reviewed owner approval")
    args = parser.parse_args()

    try:
        if args.mode == "linked-b":
            output = linked_b(args.receipts, args.input_token_limit)
        else:
            create, count = frozen_a()
            output = create if args.mode == "create" else count
    except (Refused, h84.Refused) as exc:
        parser.exit(2, f"h84 preflight: {exc}\n")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        parser.exit(2, "h84 preflight: retained input unavailable or invalid\n")
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
