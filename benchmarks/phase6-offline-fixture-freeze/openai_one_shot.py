"""Explicit, one-attempt OpenAI Responses trial for the sealed synthetic m82 case."""

import argparse
from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha256
import json
import os
import pwd
from pathlib import Path
import re
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis.intelligence.investigator import INSTRUCTIONS, ScriptedProvider, investigate, verify_investigation

from fake_transport_check import load_m82, project
from openai_responses_adapter import (
    DEADLINE_SECONDS, DRAFT_LIMIT, HOST, OUTPUT_TOKENS, PATH, RAW_REPLY_LIMIT,
    Refused, complete_responses_once, decode_json,
)
from replay import NOW, canonical

MODEL = "gpt-5.4-mini-2026-03-17"
BODY_SHA256 = "ca82ce718189b2d7ba48137b0220391b09038fa6bbf2d794d825e6b72121085b"
BODY_BYTES = 2914
COUNTED_INPUT_TOKENS = 436
COUNT_PROJECTION_SHA256 = "bc320ef005cafeae439d0eb80dc5411a9b4e50248a8a46fa5ce25afef0184d3b"
COUNT_RECEIPT_SHA256 = "c0c512bb78db723a3beeccde629ee7edd844853c5e6f768ef4ab9d3f3f956984"
USD_REVIEW_THRESHOLD = Decimal("0.01")
INPUT_USD_PER_MILLION = Decimal("0.75")
OUTPUT_USD_PER_MILLION = Decimal("4.50")
ESTIMATED_CHARGE = (COUNTED_INPUT_TOKENS * INPUT_USD_PER_MILLION
                    + OUTPUT_TOKENS * OUTPUT_USD_PER_MILLION) / Decimal(1_000_000)
CHARGE_BASIS = {
    "kind": "owner-accepted-count-estimate",
    "count_projection_sha256": COUNT_PROJECTION_SHA256, "count_receipt_sha256": COUNT_RECEIPT_SHA256,
    "counted_input_tokens": COUNTED_INPUT_TOKENS, "max_output_tokens": OUTPUT_TOKENS,
    "uncached_input_usd_per_million": str(INPUT_USD_PER_MILLION),
    "output_usd_per_million": str(OUTPUT_USD_PER_MILLION),
    "estimated_charge_usd": str(ESTIMATED_CHARGE), "binding_charge_ceiling_verified": False,
    "residual_risk": "Create usage, applicable rates or fees may differ; response checks occur after dispatch.",
}
COUNT_FIELDS = ("input", "instructions", "model", "text", "tool_choice", "tools")
PLAN = {
    "trial": "phase6-m82-responses-1", "method": "POST", "endpoint": f"https://{HOST}{PATH}",
    "model": MODEL, "service_tier": "default", "store": False, "body_sha256": BODY_SHA256,
    "credential_ref": "studio-phase6-openai/project-key", "total_attempts": 1,
    "deadline_seconds": DEADLINE_SECONDS, "request_bytes": BODY_BYTES, "raw_reply_bytes": RAW_REPLY_LIMIT,
    "draft_bytes": DRAFT_LIMIT, "max_output_tokens": OUTPUT_TOKENS,
    "usd_review_threshold": str(USD_REVIEW_THRESHOLD),
}


def read_bounded(path, limit):
    with path.open("rb") as content:
        blob = content.read(limit + 1)
    if len(blob) > limit:
        raise Refused("input byte limit")
    return blob


def review_body(body_path, sealed):
    body = read_bounded(body_path, BODY_BYTES)
    if len(body) != BODY_BYTES or sha256(body).hexdigest() != BODY_SHA256:
        raise Refused("frozen request digest mismatch")
    parsed = decode_json(body)
    if parsed["input"].encode() != project(sealed, sealed) or parsed["instructions"] != INSTRUCTIONS:
        raise Refused("logical request differs from the sealed projection")
    count = {field: parsed[field] for field in COUNT_FIELDS}
    if sha256(canonical(count)).hexdigest() != COUNT_PROJECTION_SHA256:
        raise Refused("count projection differs from the reviewed request")
    return body, count


def load_owner_key():
    # The configured root of trust lives outside the requesting checkout and home.
    etc = Path("/private/etc") if sys.platform == "darwin" else Path("/etc")
    path = etc / "aegis" / "phase6-openai-operator.pub"
    try:
        for directory in path.parents:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise Refused("operator trust path is writable or redirected")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused("operator trust key is writable or redirected")
        return Ed25519PublicKey.from_public_bytes(read_bounded(path, 32))
    except (OSError, ValueError):
        raise Refused("operator trust key unavailable") from None


def authorize(envelope, owner_key, now, operator_uid):
    # The signer accepts the exact estimate and its residual billing risk.
    try:
        if set(envelope) != {"statement", "signature"}:
            raise ValueError()
        statement = envelope["statement"]
        owner_key.verify(bytes.fromhex(envelope["signature"]), canonical(statement))
        if set(statement) != {
            "plan", "expires_at", "operator_uid", "charge_basis", "retention_evidence_sha256",
        } or canonical(statement["plan"]) != canonical(PLAN):
            raise ValueError()
        if type(statement["operator_uid"]) is not int or statement["operator_uid"] != operator_uid:
            raise ValueError()
        expiration = datetime.fromisoformat(statement["expires_at"])
        if (expiration <= now or not 0 < ESTIMATED_CHARGE <= USD_REVIEW_THRESHOLD
                or canonical(statement["charge_basis"]) != canonical(CHARGE_BASIS)
                or re.fullmatch(r"[a-f0-9]{64}", statement["retention_evidence_sha256"]) is None):
            raise ValueError()
        return COUNTED_INPUT_TOKENS, expiration
    except (InvalidSignature, KeyError, TypeError, ValueError):
        raise Refused("approval absent, invalid, expired or outside the fixed caps") from None


def claim_attempt(home, approval_digest):
    marker = home / f".aegis-phase6-openai-{BODY_SHA256[:12]}.attempt"
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise Refused("the one attempt is already consumed") from None
    with os.fdopen(fd, "wb") as record:
        record.write(canonical({"body_sha256": BODY_SHA256, "approval_sha256": approval_digest}) + b"\n")
        record.flush()
        os.fsync(record.fileno())
    directory_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def credential_from_pipe(fd, expiration):
    if datetime.now(timezone.utc) >= expiration:
        raise Refused("approval expired before dispatch")
    with os.fdopen(fd, "rb") as pipe:
        line = pipe.readline(1026)
    if datetime.now(timezone.utc) >= expiration:
        raise Refused("approval expired before dispatch")
    value = line.removesuffix(b"\n")
    if re.fullmatch(rb"[A-Za-z0-9_-]{16,1024}", value) is None:
        raise Refused("credential pipe did not contain one valid token")
    return value.decode("ascii")


def check_response(reply, sealed):
    checked = investigate(sealed, ScriptedProvider(reply.draft.model_dump(mode="json")), now=NOW)
    verify_investigation(sealed, checked, now=NOW)
    candidate = checked.candidate
    if candidate.baseline_outcome != "unaffected" or candidate.reportable_outcome == "affected":
        raise Refused("local structured guard failed")
    return {
        "response_id": reply.response_id, "model": reply.model, "body_sha256": BODY_SHA256,
        "reply_sha256": reply.reply_sha256, "draft_sha256": reply.draft_sha256,
        "provider_reported_usage": {
            "input_tokens": reply.input_tokens, "output_tokens": reply.output_tokens,
            "total_tokens": reply.input_tokens + reply.output_tokens,
        },
        "draft": reply.draft.model_dump(mode="json"), "local_check": checked.check.model_dump(mode="json"),
        "reportable_outcome": candidate.reportable_outcome, "independently_verified": False,
        "applicability_references": [ref.model_dump(mode="json") for ref in candidate.applicability_references],
        "billing_verified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "dispatch"))
    parser.add_argument("body", type=Path, help="exact frozen Responses create body")
    parser.add_argument("inputs", type=Path, help="exact Phase 6 inputs artifact")
    parser.add_argument("--approval", type=Path, help="operator-signed approval envelope for dispatch")
    args = parser.parse_args()
    try:
        sealed = load_m82(args.inputs)
        body, count = review_body(args.body, sealed)
        if args.mode == "check":
            print(json.dumps({"status": "offline-check", "plan": PLAN, "charge_basis": CHARGE_BASIS,
                              "count_projection_sha256": sha256(canonical(count)).hexdigest(),
                              "count_projection_bytes": len(canonical(count))}, sort_keys=True))
            return 0
        if args.approval is None:
            raise Refused("dispatch requires enrolled operator approval")
        if os.getuid() == 0:
            raise Refused("dispatch requires an unprivileged operator session")
        envelope = read_bounded(args.approval, 8192)
        bound, expiration = authorize(
            decode_json(envelope), load_owner_key(), datetime.now(timezone.utc), os.getuid()
        )
        if not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise Refused("dispatch requires a prearranged credential pipe on stdin")
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        claim_attempt(home, sha256(envelope).hexdigest())
        fd = os.dup(0)
        try:
            reply = complete_responses_once(
                body, body_sha256=BODY_SHA256, model=MODEL, input_token_limit=bound,
                credential_reader=lambda: credential_from_pipe(fd, expiration),
            )
        finally:
            os.close(fd)
        print(json.dumps(check_response(reply, sealed), sort_keys=True))
        return 0
    except Refused as exc:
        print(f"phase6: {exc}", file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print("phase6: local preflight or result check failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
