"""Prepare the frozen h84 A and linked B request bodies offline."""

import argparse
from hashlib import sha256
from pathlib import Path
import sys

from osv_row_selection import DRAFT_LIMIT, SOURCE_LIMIT, TARGET_LIMIT, Refused, read_bounded
from osv_two_stage import prepare_a, prepare_b
from two_stage_trial import build_request


FIXTURE = Path(__file__).resolve().parents[1] / "phase6-two-stage-independent/seal/inputs/original/h84"
SOURCE_SHA = "0747257e6a8891f95ec563365fe262a608cd3c9e2d81860a45ee5a7b0498c104"
TARGET_SHA = "df600d9dde6dfa01012d056b615e238b45e75d05a6f1b58dc5b925c0d26f7954"


def fixture():
    source = read_bounded(FIXTURE / "source.json", SOURCE_LIMIT)
    target = read_bounded(FIXTURE / "target.json", TARGET_LIMIT)
    if sha256(source).hexdigest() != SOURCE_SHA or sha256(target).hexdigest() != TARGET_SHA:
        raise Refused("h84-fixture-digest-mismatch")
    return source, target


def request_a():
    prepared = prepare_a(*fixture())
    if prepared["status"] != "prepared":
        raise Refused(prepared["reason"])
    return build_request("A", prepared)


def request_b(identity_draft: bytes):
    """Build B only from a draft that verifies as a complete identity match."""
    prepared = prepare_b(*fixture(), identity_draft, arm="linked")
    if prepared["status"] != "prepared":
        raise Refused(prepared["reason"])
    return build_request("B", prepared)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    stages = parser.add_subparsers(dest="stage", required=True)
    stages.add_parser("A", help="write the identity request body")
    linked = stages.add_parser("B", help="verify the supplied A draft and write the version request body")
    linked.add_argument("identity_draft", type=Path, help="raw Stage A identity draft JSON file")
    args = parser.parse_args()

    try:
        if args.stage == "A":
            body = request_a()
        else:
            draft = read_bounded(args.identity_draft, DRAFT_LIMIT)
            body = request_b(draft)
    except OSError:
        parser.exit(2, "h84: local input unavailable\n")
    except ValueError as exc:
        parser.exit(2, f"h84: {exc}\n")
    sys.stdout.buffer.write(body)


if __name__ == "__main__":
    main()
