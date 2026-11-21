"""Exercise the one sealed m82 projection using a bounded local fake."""

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from time import monotonic

from pydantic import ValidationError

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.investigator import (
    AdvisoryInput, Draft, INSTRUCTIONS, Limits, ScriptedProvider, investigate, verify_investigation,
)
from aegis.intelligence.models import Asset

from replay import MANIFEST, MANIFEST_SHA256, NOW, canonical, verified_bytes

PAYLOAD_SHA256 = "6e60ed975685835100f6d7f21cee5575b2ffb2f842b1b5d67b77aa7b63d1578d"
INSTRUCTIONS_SHA256 = "d52bda54c58a136266f94246e6064e22733cf812fd7d0fda1c3ec082a07d2a3f"
RAW_REPLY_LIMIT = 16_384
DRAFT_LIMIT = Limits().max_output_bytes
FAKE_DEADLINE_SECONDS = 1
FAKE_STALL_SECONDS = 5
SCHEDULING_TOLERANCE_MS = 250
FAKE_MAX_CHARGE_CENTS = 2

# The child accepts only the harness's fixed scenarios. It has no socket or
# provider code. stdout carries the reply, stderr acknowledges the input bytes.
FAKE_CHILD = r"""
from hashlib import sha256
import json
import sys
from time import sleep

mode = sys.argv[1]
request = json.load(sys.stdin)
payload = request["payload"].encode("ascii")
instructions = request["instructions"].encode("ascii")
print(json.dumps({"payload_sha256": sha256(payload).hexdigest(),
                  "instructions_sha256": sha256(instructions).hexdigest()}),
      file=sys.stderr, flush=True)
claim = {"kind": "applicability", "source_id": "S1", "quote": '"fixed":"8.6"'}
reply = {"proposed_outcome": "unaffected", "claims": [claim], "uncertainties": []}
if mode == "disagreement":
    source = json.loads(json.loads(payload)["sources"][0]["content"])
    claim["quote"] = source["summary"]
    reply["proposed_outcome"] = "affected"
elif mode == "malformed":
    reply["extra"] = "unauthorized"
elif mode in ("oversized-draft", "oversized-raw"):
    sys.stdout.buffer.write(b" " * int(sys.argv[2]))
    sys.exit(0)
elif mode == "stall":
    sys.stdout.write('{"proposed_outcome":')
    sys.stdout.flush()
    sleep(int(sys.argv[2]))
    sys.stdout.write('"unaffected","claims":[],"uncertainties":[]}')
    sys.exit(0)
elif mode != "success":
    sys.exit(2)
print(json.dumps(reply))
"""


def load_m82(inputs):
    manifest = json.loads(verified_bytes(MANIFEST, MANIFEST_SHA256))
    cases = json.loads(verified_bytes(inputs, manifest["artifacts"]["inputs"]["sha256"]))
    case, = (c for c in cases if c["id"] == "m82")
    plan, = (p for p in manifest["cases"] if p["id"] == "m82")
    step, = case["steps"]
    expected, = plan["steps"]
    body = canonical(step["body"])
    if (sha256(canonical(case)).hexdigest() != plan["case_sha256"]
            or sha256(body).hexdigest() != expected["body_sha256"]):
        raise ValueError("sealed m82 fixture mismatch")
    source = snapshot("osv", step["uri"], body, retrieved_at=NOW)
    return AdvisoryInput(advisory_id=step["body"]["id"], vulnerability_id=case["vid"],
                         asset=Asset.model_validate(case["asset"]), sources=(source,))


def project(advisory, sealed):
    if advisory != sealed:
        raise ValueError("only the exact sealed m82 fixture is allowed")
    source, = advisory.sources
    if source.acquisition != "fixture":
        raise ValueError("only fixture acquisition is allowed")
    payload = canonical({
        "schema_version": advisory.schema_version,
        "vulnerability_id": advisory.vulnerability_id,
        "asset": {"alias": "asset-1", "version": advisory.asset.version},
        "sources": [{"source_id": "S1", "kind": source.kind, "sha256": source.sha256,
                     "content": source.content.decode("ascii")}],
    })
    if len(payload) != 640 or sha256(payload).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("m82 projection differs from the preflight")
    if sha256(INSTRUCTIONS.encode()).hexdigest() != INSTRUCTIONS_SHA256:
        raise ValueError("instructions differ from the preflight")
    return payload


@dataclass(frozen=True)
class FakeResponse:
    body: bytes
    witness: bytes
    timed_out: bool
    decision_ms: float
    reaped_ms: float
    exit_code: int


def dispatch_fake(mode, payload):
    parameter = {
        "oversized-draft": DRAFT_LIMIT + 1,
        "oversized-raw": RAW_REPLY_LIMIT + 1,
        "stall": FAKE_STALL_SECONDS,
    }.get(mode, 0)
    command = [sys.executable, "-IB", "-c", FAKE_CHILD, mode, str(parameter)]
    frame = canonical({"instructions": INSTRUCTIONS, "payload": payload.decode("ascii")})
    start = monotonic()
    deadline = start + FAKE_DEADLINE_SECONDS
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env={}) as child:
        try:
            body, witness = child.communicate(frame, timeout=max(0, deadline - monotonic()))
        except subprocess.TimeoutExpired as exc:
            decision_ms = (monotonic() - start) * 1000
            child.kill()
            child.communicate()
            return FakeResponse(exc.output or b"", exc.stderr or b"", True, decision_ms,
                                (monotonic() - start) * 1000, child.returncode)
        elapsed_ms = (monotonic() - start) * 1000
        return FakeResponse(body, witness, elapsed_ms >= FAKE_DEADLINE_SECONDS * 1000,
                            elapsed_ms, elapsed_ms, child.returncode)


def run_case(advisory, sealed, mode, cap_cents):
    result = {"dispatches": 0, "cap_cents": cap_cents, "reserved_fake_cents": 0}
    try:
        payload = project(advisory, sealed)
    except ValueError:
        return {**result, "status": "refused-input"}
    if FAKE_MAX_CHARGE_CENTS > cap_cents:
        return {**result, "status": "refused-cap"}

    response = dispatch_fake(mode, payload)
    result.update(dispatches=1, reserved_fake_cents=FAKE_MAX_CHARGE_CENTS,
                  captured_bytes=len(response.body), deadline_decision_ms=response.decision_ms,
                  reaped_ms=response.reaped_ms, child_exit=response.exit_code,
                  witness=json.loads(response.witness) if response.witness else None)
    if response.timed_out:
        return {**result, "status": "deadline"}
    if response.exit_code != 0:
        return {**result, "status": "child-failure"}
    if len(response.body) > RAW_REPLY_LIMIT:
        return {**result, "status": "oversized-raw"}
    if len(response.body) > DRAFT_LIMIT:
        return {**result, "status": "oversized-draft"}
    try:
        draft = Draft.model_validate_json(response.body)
    except ValidationError:
        return {**result, "status": "malformed"}

    # Apply the existing local checker to the parsed fake draft. Neither
    # Investigator nor OfflineHandoff receives a new provider implementation.
    checked = investigate(advisory, ScriptedProvider(draft.model_dump(mode="json")), now=NOW)
    verify_investigation(advisory, checked, now=NOW)
    return {**result, "status": "checked", "research": checked.model_dump(mode="json")}


def conforms(results):
    expected = {
        "success": "checked", "disagreement": "checked", "malformed": "malformed",
        "oversized-draft": "oversized-draft", "oversized-raw": "oversized-raw",
        "refused-cap": "refused-cap", "non-fixture": "refused-input",
        "altered-fixture": "refused-input", "stall": "deadline",
    }
    witness = {"payload_sha256": PAYLOAD_SHA256, "instructions_sha256": INSTRUCTIONS_SHA256}
    for label, status in expected.items():
        row = results[label]
        if row["status"] != status or ("research" in row) != (status == "checked"):
            return False
        refused = status.startswith("refused-")
        if row["dispatches"] != int(not refused) or row["reserved_fake_cents"] != (
            0 if refused else FAKE_MAX_CHARGE_CENTS
        ):
            return False
        if not refused and row["witness"] != witness:
            return False
    for label, reportable in (("success", "unaffected"), ("disagreement", "unknown")):
        candidate = results[label]["research"]["candidate"]
        if (candidate["baseline_outcome"] != "unaffected"
                or candidate["reportable_outcome"] != reportable
                or candidate["independently_verified"]
                or [ref["pointer"] for ref in candidate["applicability_references"]] != ["/affected/0"]):
            return False
    stall = results["stall"]
    deadline_ms = FAKE_DEADLINE_SECONDS * 1000
    return (results["oversized-raw"]["captured_bytes"] == RAW_REPLY_LIMIT + 1
            and results["oversized-draft"]["captured_bytes"] == DRAFT_LIMIT + 1
            and 0 < stall["captured_bytes"] < DRAFT_LIMIT and stall["child_exit"] < 0
            and deadline_ms <= stall["deadline_decision_ms"] <= stall["reaped_ms"]
            <= deadline_ms + SCHEDULING_TOLERANCE_MS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path, help="exact inputs artifact named by the Phase 6 manifest")
    args = parser.parse_args()
    sealed = load_m82(args.inputs)
    payload = project(sealed, sealed)
    source, = sealed.sources
    non_fixture = sealed.model_copy(update={
        "sources": (source.model_copy(update={"acquisition": "https"}),),
    })
    altered = sealed.model_copy(update={
        "asset": sealed.asset.model_copy(update={"asset_id": "different-fixture"}),
    })
    modes = ("success", "disagreement", "malformed", "oversized-draft", "oversized-raw", "stall")
    results = {mode: run_case(sealed, sealed, mode, FAKE_MAX_CHARGE_CENTS) for mode in modes}
    results["refused-cap"] = run_case(sealed, sealed, "success", FAKE_MAX_CHARGE_CENTS - 1)
    results["non-fixture"] = run_case(non_fixture, sealed, "success", FAKE_MAX_CHARGE_CENTS)
    results["altered-fixture"] = run_case(altered, sealed, "success", FAKE_MAX_CHARGE_CENTS)
    matched = conforms(results)
    print(json.dumps({
        "matched": matched, "synthetic_only": True, "payload": payload.decode("ascii"),
        "instructions_sha256": INSTRUCTIONS_SHA256, "payload_sha256": PAYLOAD_SHA256,
        "fake_deadline_seconds": FAKE_DEADLINE_SECONDS, "fake_stall_seconds": FAKE_STALL_SECONDS,
        "scheduling_tolerance_ms": SCHEDULING_TOLERANCE_MS,
        "cases": results,
    }, sort_keys=True, indent=2))
    return int(not matched)


if __name__ == "__main__":
    raise SystemExit(main())
