"""Prepare the one m82 approval offline in Jack's independent signing session."""

import argparse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openai_one_shot import (
    BODY_SHA256, CHARGE_BASIS, COUNT_RECEIPT_SHA256, MODEL, PLAN, Refused, authorize,
    decode_json, load_m82, read_bounded, review_body,
)
from replay import canonical

STUDIO_UID = 501
PLAN_SHA256 = "452361fc865c1e270ef5d90075d4f577a22085e2268b8c78f7d8eeb25f84d05b"
CONFIRMATION = "APPROVE M82 ESTIMATE AND EXPORT"


def review_inputs(body, inputs, receipt):
    if sha256(canonical(PLAN)).hexdigest() != PLAN_SHA256:
        raise Refused("launcher plan differs from the independently reviewed plan")
    review_body(body, load_m82(inputs))
    receipt_bytes = read_bounded(receipt, 2048)
    expected = {
        "attempts": 1, "endpoint": "/v1/responses/input_tokens", "http_status": 200,
        "input_tokens": CHARGE_BASIS["counted_input_tokens"], "model": MODEL, "outcome": "counted",
        "request_sha256": CHARGE_BASIS["count_projection_sha256"],
    }
    if sha256(receipt_bytes).hexdigest() != COUNT_RECEIPT_SHA256 or decode_json(receipt_bytes) != expected:
        raise Refused("the reviewed 436-token receipt is required")


def write_record(output, name, data):
    with (output / name).open("xb") as file:
        file.write(data)
    return sha256(data).hexdigest()


def run_signing_session(output):
    print(f"Studio UID {STUDIO_UID} | {MODEL} | one attempt | store=false")
    print(f"Request SHA-256 {BODY_SHA256}")
    print(f"Canonical PLAN SHA-256 {PLAN_SHA256}")
    print("Estimated charge USD", CHARGE_BASIS["estimated_charge_usd"])
    print(CHARGE_BASIS["residual_risk"])
    retention = input("Verified effective project retention (standard / MAM / ZDR): ").strip()
    if retention not in {"standard", "MAM", "ZDR"}:
        raise Refused("verify the project's effective retention before continuing")
    if input("Type SHARING OFF after confirming the project does not opt in to data sharing: ") != "SHARING OFF":
        raise Refused("project data-sharing setting not accepted")

    output.mkdir(mode=0o700)
    # The signing key stays in this process and is never written to disk.
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    public_bytes = public.public_bytes_raw()
    public_digest = write_record(output, "phase6-openai-operator.pub", public_bytes)
    print(f"Public verifier hex {public_bytes.hex()}")
    print(f"Public verifier SHA-256 {public_digest}")
    print("Enroll this public key on Studio from the owner-controlled administrator session.")
    if input("Enter the SHA-256 read back from the installed Studio verifier: ").strip() != public_digest:
        raise Refused("installed verifier did not match; no approval signed")
    if input(f"Type {CONFIRMATION} to sign this trial's approval: ") != CONFIRMATION:
        raise Refused("owner approval was not confirmed")

    record = {
        "body_sha256": BODY_SHA256, "plan_sha256": PLAN_SHA256, "operator_uid": STUDIO_UID,
        "decision": "one synthetic m82 request to the reviewed Responses endpoint",
        "project_credential_ref": PLAN["credential_ref"], "effective_project_retention": retention,
        "normal_response_storage": False, "training_data_sharing_opt_in": False,
    }
    retention_digest = write_record(output, "retention-review.json", canonical(record) + b"\n")
    now = datetime.now(timezone.utc)
    statement = {
        "plan": PLAN, "operator_uid": STUDIO_UID, "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "charge_basis": CHARGE_BASIS, "retention_evidence_sha256": retention_digest,
    }
    envelope = {"statement": statement, "signature": key.sign(canonical(statement)).hex()}
    authorize(envelope, public, now, STUDIO_UID)
    digest = write_record(output, "phase6-openai-approval.json", canonical(envelope) + b"\n")
    print(f"Approval SHA-256 {digest}")
    print(f"Retention record SHA-256 {retention_digest}")
    print(f"Approval expiry {statement['expires_at']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("body", type=Path, help="frozen create request")
    parser.add_argument("inputs", type=Path, help="exact sealed inputs artifact")
    parser.add_argument("receipt", type=Path, help="reviewed replacement count receipt")
    parser.add_argument("output", type=Path, help="new private directory for public artifacts")
    args = parser.parse_args()
    try:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise Refused("run in the owner's interactive signing session")
        if args.output.exists() or args.output.is_symlink():
            raise Refused("output directory must be new")
        review_inputs(args.body, args.inputs, args.receipt)
        run_signing_session(args.output)
        return 0
    except (Refused, OSError, ValueError, EOFError) as exc:
        print(f"phase6 owner signing: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
