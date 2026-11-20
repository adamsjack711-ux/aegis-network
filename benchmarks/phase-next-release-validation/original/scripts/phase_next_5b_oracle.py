"""Score retained offline Linux CLI output against independent safety expectations."""

import argparse
from hashlib import sha256
import json
from pathlib import Path


EXPECT = {
    "signed-current": (0, "matched", "current"),
    "signed-expired": (2, "unknown", "expired"),
    "signed-withdrawn": (2, "unknown", "withdrawn"),
    "signed-unsupported-range": (2, "unknown", "current"),
}


def sections(raw):
    blocks = {}
    for item in raw.split("CASE=")[1:]:
        name, _, remainder = item.partition("\n")
        body, _, tail = remainder.partition("\nEXIT=")
        blocks[name.strip()] = (json.loads(body), int(tail.splitlines()[0]))
    return blocks


def score_signed(raw):
    blocks = sections(raw)
    rows = []
    for name, (exit_code, expected_result, expected_status) in EXPECT.items():
        body, actual_exit = blocks[name]
        claim = body["findings"][0]
        safe = (actual_exit == exit_code and claim["result"] == expected_result
                and claim["claim_status"] == expected_status and bool(claim.get("uncertainty"))
                and body["observation_count"] == 1
                and not any(field in claim for field in ("approval", "mitigation", "write_target")))
        rows.append({"case": name, "status": "pass" if safe else "fail", "exit_code": actual_exit,
                     "result": claim["result"], "claim_status": claim["claim_status"]})
    body, actual_exit = blocks["unsigned-observation"]
    safe = actual_exit == 2 and body.get("status") == "unknown" and "unsupported" in body.get("error", "")
    rows.append({"case": "unsigned-observation", "status": "pass" if safe else "fail",
                 "exit_code": actual_exit, "error": body.get("error")})
    return rows


def score_partial(raw):
    body_text, _, tail = raw.partition("\nCLI_EXIT=")
    body = json.loads(body_text)
    exit_code = int(tail.splitlines()[0])
    claim = body["findings"][0]
    safe = (exit_code == 2 and body["inventory_complete"] is False and
            claim["result"] == "unknown" and claim["reason_code"] == "INVENTORY_INCOMPLETE")
    return {"case": "partial-inventory", "status": "pass" if safe else "fail",
            "exit_code": exit_code, "result": claim["result"], "reason": claim["reason_code"]}


def score_default(raw):
    _, _, tail = raw.partition("\nCLI_EXIT=")
    exit_code = int(tail.splitlines()[0])
    writes = [line for line in tail.splitlines()[1:] if line.startswith("/tmp/state/")]
    return {"case": "default-state-write", "status": "fail" if writes else "pass",
            "exit_code": exit_code, "unexpected_files": writes}


def score_malformed(raw):
    body_text, _, tail = raw.partition("\nCLI_EXIT=")
    body = json.loads(body_text)
    exit_code = int(tail.splitlines()[0])
    safe = exit_code == 2 and body.get("status") == "unknown" and "cannot read" in body.get("error", "")
    return {"case": "malformed-feed", "status": "pass" if safe else "fail",
            "exit_code": exit_code, "error": body.get("error")}


def score_duplicate(raw):
    body_text, _, tail = raw.partition("\nCLI_EXIT=")
    body = json.loads(body_text)
    exit_code = int(tail.splitlines()[0])
    claim = body["findings"][0]
    safe = (exit_code == 2 and body["inventory_complete"] is False and
            "duplicate" in body["inventory_reason"] and claim["result"] == "unknown")
    return {"case": "duplicate-inventory", "status": "pass" if safe else "fail",
            "exit_code": exit_code, "result": claim["result"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--source-pin", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    paths = {name: args.raw_dir / f"cli-5b-linux-{name}.txt" for name in
             ("default-state", "signed-cases", "partial", "malformed", "duplicate")}
    rows = [score_default(paths["default-state"].read_text()),
            *score_signed(paths["signed-cases"].read_text()),
            score_partial(paths["partial"].read_text()),
            score_malformed(paths["malformed"].read_text()),
            score_duplicate(paths["duplicate"].read_text())]
    result = {"source_pin": args.source_pin, "image_digest": args.image_digest,
              "topology": "one-host offline disposable Linux container, UID 65534, no capabilities",
              "raw_sha256": {name: sha256(path.read_bytes()).hexdigest() for name, path in paths.items()},
              "cases": rows, "summary": {status: sum(row["status"] == status for row in rows)
                                      for status in ("pass", "fail", "inconclusive")}}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()
