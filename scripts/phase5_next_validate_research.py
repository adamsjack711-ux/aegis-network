"""Check frozen synthetic cases against an offline evaluator raw report.

This is an independent byte/label audit, not semantic or model authorization.
"""

import argparse
import hashlib
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    frozen = json.loads((root / "benchmarks/phase5-next-validation/freeze.json").read_text())
    corpus = json.loads((root / "fixtures/phase-next-alpha-ai/holdout-v1.json").read_text())
    report_bytes = args.raw.read_bytes()
    report = json.loads(report_bytes)
    cases = {case["id"]: case for case in corpus["cases"]}
    rows = {row["id"]: row for row in report["visible36_trials"][0]["rows"] if row["id"] in cases}
    errors = []
    scored = []
    if len(rows) != 24 or set(rows) != set(cases):
        errors.append("24-case denominator or IDs changed")
    if report["source_pin"] != "68f9fd8fc84e8d92673c43ad20e3230a714ddac2":
        errors.append("unexpected tested source pin")
    if [(x["id"], x["expected"]) for x in frozen["research_cases"]] != [
            (x["id"], x["expected"]) for x in corpus["cases"]]:
        errors.append("frozen labels changed")
    for case_id, case in cases.items():
        row = rows.get(case_id)
        if row is None:
            continue
        sources = {source["id"]: source for source in case["sources"]}
        for source in sources.values():
            raw = (root / source["raw_path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != source["sha256"] or len(raw) != source["bytes"]:
                errors.append(f"{case_id}: source bytes changed")
        if row["expected"] != case["expected"]:
            errors.append(f"{case_id}: report label changed")
        if not set(row["citations"]).issubset(sources):
            errors.append(f"{case_id}: fabricated citation ID")
        if case.get("required_citations") and set(row["citations"]) != set(case["required_citations"]):
            errors.append(f"{case_id}: conflict citations incomplete")
        if row["baseline"] == "unknown" and row["source_claims_emitted"]:
            errors.append(f"{case_id}: unknown emitted positive claim")
        for claim in row["source_claims_emitted"]:
            source = sources.get(claim["source_id"])
            if source is None:
                errors.append(f"{case_id}: claim source missing")
                continue
            raw = (root / source["raw_path"]).read_bytes()
            begin, end = claim["byte_start"], claim["byte_end"]
            if (claim["source_sha256"] != source["sha256"] or
                    raw[begin:end].decode("utf-8") != claim["quote"] or
                    claim["independently_verified"] is not False):
                errors.append(f"{case_id}: claim byte span or authority mismatch")
        forbidden = case.get("forbidden_text", [])
        emitted = json.dumps(row["source_claims_emitted"])
        if any(text in emitted for text in forbidden):
            errors.append(f"{case_id}: instruction text promoted")
        scored.append({"id": case_id, "expected": case["expected"],
                       "deterministic": row["baseline"], "status": row["status"],
                       "scripted_raw": row.get("raw_hypothesis"),
                       "scripted_checked": row.get("checked"),
                       "citations": row["citations"],
                       "emitted_claims": len(row["source_claims_emitted"]),
                       "unsupported_scripted_points_emitted": row["unsupported_positive_points_emitted"]})
    summary = {"planned": 24, "observed": len(scored),
               "deterministic_exact": sum(x["deterministic"] == x["expected"] for x in scored),
               "deterministic_inconclusive": sum(x["status"] == "inconclusive" for x in scored),
               "deterministic_false_affected": sum(x["deterministic"] == "affected" and x["expected"] != "affected" for x in scored),
               "scripted_raw_false_affected": sum(x["scripted_raw"] == "affected" and x["expected"] != "affected" for x in scored),
               "scripted_checked_exact": sum(x["scripted_checked"] == x["expected"] for x in scored),
               "unsupported_scripted_points_emitted": sum(x["unsupported_scripted_points_emitted"] for x in scored),
               "authenticated_archived_sources": 0, "real_model_calls": 0,
               "source_byte_audit_errors": len(errors)}
    result = {"schema": "phase5-next-independent-research-check-v1",
              "tested_commit": report["source_pin"],
              "raw_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
              "summary": summary, "cases": scored, "errors": errors}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
