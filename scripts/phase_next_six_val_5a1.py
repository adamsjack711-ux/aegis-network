"""Independently rescore exact-source Phase 5A-1 private evaluation raw."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _source_bytes(root: Path, source: dict) -> bytes:
    if "raw_path" in source:
        path = (root / source["raw_path"]).resolve()
        allowed = (root / "fixtures/phase-next-alpha-ai/sources").resolve()
        if not path.is_relative_to(allowed):
            raise ValueError("source escapes sealed root")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != source["sha256"] or len(raw) != source["bytes"]:
            raise ValueError("sealed source mismatch")
        return raw
    return source["text"].encode()


def _claim_errors(root: Path, source: dict, claim: dict) -> list[str]:
    raw = _source_bytes(root, source)
    start, end = claim["byte_start"], claim["byte_end"]
    errors = []
    if claim["source_sha256"] != hashlib.sha256(raw).hexdigest():
        errors.append("source digest")
    if claim["source_id"] != source["id"]:
        errors.append("source id")
    if claim["source_locator"] != f"utf8-byte:{start}:{end}" or raw[start:end].decode() != claim["quote"]:
        errors.append("byte locator")
    if claim["support"] != "fixture-parser-consistent" or claim["independently_verified"] is not False:
        errors.append("authority label")
    return errors


def score(root: Path, report: dict) -> dict:
    v_raw = (root / "benchmarks/phase-next-r-validation/5a-r/retained-v01-v12.json").read_bytes()
    v = {case["id"]: case for case in json.loads(v_raw)["cases"]}
    visible = {}
    for name in ("fixtures/phase-next-ai-holdout-v1.json", "fixtures/phase-next-alpha-ai/holdout-v1.json"):
        visible.update({case["id"]: case for case in json.loads((root / name).read_bytes())["cases"]})
    result = {"source_pin": report["source_pin"], "v_corpus_sha256": hashlib.sha256(v_raw).hexdigest(),
              "v_planned": 0, "v_eligible": 0, "v_exact_eligible": 0, "v_false_affected": 0,
              "v_claims": 0, "visible_planned": 0, "visible_eligible": 0,
              "visible_exact_eligible": 0, "visible_false_affected": 0, "visible_claims": 0,
              "claim_errors": [], "raw_points_reportable": 0, "real_model_attempted": report["real_model"]["attempted_units"]}
    for trial in report["v_trials"]:
        if len(trial["rows"]) != 12 or {r["id"] for r in trial["rows"]} != set(v):
            result["claim_errors"].append("V case denominator/identity")
        for row in trial["rows"]:
            case = v[row["id"]]
            result["v_planned"] += 1
            result["v_eligible"] += row["status"] == "completed"
            result["v_exact_eligible"] += row["status"] == "completed" and row["observed"] == case["expected"]
            result["v_false_affected"] += row["observed"] == "affected" and case["expected"] != "affected"
            result["raw_points_reportable"] += bool(row["raw_point"] and row["raw_point"]["reportable"])
            source_map = {source["id"]: source for source in case["sources"]}
            for source_row in row["sources"]:
                claim = source_row["claim"]
                if claim is None:
                    continue
                result["v_claims"] += 1
                result["claim_errors"].extend(_claim_errors(root, source_map[source_row["id"]], claim))
    for trial in report["visible36_trials"]:
        if len(trial["rows"]) != 36 or {r["id"] for r in trial["rows"]} != set(visible):
            result["claim_errors"].append("visible case denominator/identity")
        for row in trial["rows"]:
            case = visible[row["id"]]
            result["visible_planned"] += 1
            result["visible_eligible"] += row["status"] == "completed"
            result["visible_exact_eligible"] += row["status"] == "completed" and row["baseline"] == case["expected"]
            result["visible_false_affected"] += row["baseline"] == "affected" and case["expected"] != "affected"
            source_map = {source["id"]: source for source in case["sources"]}
            for claim in row["source_claims_emitted"]:
                result["visible_claims"] += 1
                result["claim_errors"].extend(_claim_errors(root, source_map[claim["source_id"]], claim))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    print(json.dumps(score(args.root.resolve(), json.loads(args.report.read_bytes())), sort_keys=True))
