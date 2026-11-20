"""Score author-labeled synthetic Debian backport controls separately from sealed holdout."""

import argparse
import hashlib
import json
from pathlib import Path

from aegis.intelligence.alpha_eval import _source_decision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = (args.root / "fixtures/phase5a-backport-supplement-v1.json").read_bytes()
    corpus = json.loads(raw)
    rows = []
    for case in corpus["cases"]:
        decisions = [_source_decision(s["text"], case["asset"]) for s in case["sources"]]
        candidates = {decision for decision, _ in decisions if decision != "unknown"}
        actual = next(iter(candidates)) if len(candidates) == 1 else "unknown"
        rows.append({"id": case["id"], "expected": case["expected"], "baseline": actual,
                     "correct": actual == case["expected"], "source_ids": [s["id"] for s in case["sources"]],
                     "source_sha256": {s["id"]: hashlib.sha256(s["text"].encode()).hexdigest()
                                       for s in case["sources"]},
                     "reason_codes": [reason for _, reason in decisions],
                     "conflict": len(candidates) > 1})
    result = {"schema_version": "phase5a-backport-development-v1",
              "corpus_sha256": hashlib.sha256(raw).hexdigest(),
              "label_status": "author-labeled; independent review pending",
              "planned": len(rows), "exact": sum(row["correct"] for row in rows),
              "real_model": "skipped", "rows": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"{result['exact']}/{result['planned']} author-labeled controls; real model skipped")


if __name__ == "__main__":
    main()
