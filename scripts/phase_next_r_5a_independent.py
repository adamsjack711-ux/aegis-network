"""Independent, offline exact-pin challenge for private Phase 5A-R records."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--pin", required=True)
    parser.add_argument("--v-corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.candidate.resolve()
    pin = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip()
    if pin != args.pin or dirty:
        raise ValueError(f"candidate pin/cleanliness mismatch: {pin}, {dirty!r}")
    sys.path.insert(0, str(root / "src"))
    from aegis.artifact import Evidence, SignedFinding
    from aegis.intelligence.alpha_eval import _source_decision, evaluate_alpha
    from aegis.intelligence.source_claim import (AtomicSourceClaim, build_atomic_claim,
                                                 exact_source_bytes, verify_atomic_claim)

    corpus_bytes = args.v_corpus.read_bytes()
    cases = json.loads(corpus_bytes)["cases"]
    v_rows = []
    for case in cases:
        source_rows = []
        decisions = []
        for source in case["sources"]:
            decision, reason = _source_decision(source["text"], case["asset"])
            claim = None
            error = None
            if decision in {"affected", "unaffected"}:
                try:
                    claim = build_atomic_claim(root, source, case["asset"],
                                               polarity=decision, predicate=reason).model_dump(mode="json")
                    decisions.append(decision)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
            source_rows.append({"id": source["id"], "decision": decision, "reason": reason,
                                "claim": claim, "claim_error": error})
        observed = "unknown" if len(set(decisions)) != 1 else decisions[0]
        inconclusive = any(s["reason"] == "unsupported-debian-epoch" for s in source_rows)
        v_rows.append({"id": case["id"], "expected": case["expected"],
                       "observed": observed, "exact": observed == case["expected"],
                       "inconclusive": inconclusive, "sources": source_rows})

    report36 = evaluate_alpha(root)
    row = next(r for r in report36["rows"] if r["id"] == "B01-inclusive-lower")
    case = next(c for c in json.loads((root / "fixtures/phase-next-alpha-ai/holdout-v1.json").read_text())["cases"]
                if c["id"] == "B01-inclusive-lower")
    source, asset = case["sources"][0], case["asset"]
    raw, _ = exact_source_bytes(root, source)
    claim = AtomicSourceClaim.model_validate(row["source_claims_emitted"][0])
    tamper = []
    for label, altered_raw in (("suffix", raw + b"!"), ("prefix", b"!" + raw)):
        try:
            verify_atomic_claim(claim, altered_raw, source, asset,
                                polarity="affected", predicate=claim.version_predicate)
            tamper.append({"case": label, "accepted": True})
        except ValueError:
            tamper.append({"case": label, "accepted": False})

    wrong = b"no code execution"
    wrong_start = raw.index(wrong)
    swapped = claim.model_copy(update={"byte_start": wrong_start, "byte_end": wrong_start + len(wrong),
                                       "source_locator": f"utf8-byte:{wrong_start}:{wrong_start + len(wrong)}",
                                       "quote": wrong.decode()})
    try:
        verify_atomic_claim(swapped, raw, source, asset, polarity="affected",
                            predicate=claim.version_predicate)
        arbitrary_quote_accepted = True
    except ValueError:
        arbitrary_quote_accepted = False

    association_spoofs = {}
    for field, value in (("source_role", "registry"), ("acquisition", "pinned-inline-fixture")):
        changed = claim.model_copy(update={field: value})
        try:
            verify_atomic_claim(changed, raw, source, asset, polarity="affected",
                                predicate=claim.version_predicate)
            association_spoofs[field] = "accepted"
        except ValueError:
            association_spoofs[field] = "rejected"

    fabricated = {"id": "adversarial-inline", "role": "vendor", "text":
                  "PyPI maple-json 1.2.0 is affected. An unrelated database outage can cause availability degradation."}
    fabricated_effect = None
    try:
        fabricated_effect = build_atomic_claim(root, fabricated, asset, polarity="affected",
                                              predicate="explicit-affected-version", kind="effect").model_dump(mode="json")
    except ValueError:
        pass
    boundaries = {}
    for cls in (Evidence, SignedFinding):
        try:
            cls.model_validate(row["source_claims_emitted"][0])
            boundaries[cls.__name__] = "accepted"
        except Exception as exc:
            boundaries[cls.__name__] = "rejected:" + type(exc).__name__

    result = {"source_pin": pin, "v_corpus_sha256": sha(corpus_bytes),
              "candidate_source_hashes": {str(p.relative_to(root)): sha(p.read_bytes()) for p in
                  (root / "src/aegis/intelligence/alpha_eval.py", root / "src/aegis/intelligence/source_claim.py")},
              "v_rows": v_rows,
              "v_summary": {"planned": len(v_rows), "exact": sum(x["exact"] for x in v_rows),
                            "inconclusive": sum(x["inconclusive"] for x in v_rows),
                            "false_affected": sum(x["observed"] == "affected" and x["expected"] != "affected" for x in v_rows),
                            "claim_errors": sum(bool(s["claim_error"]) for x in v_rows for s in x["sources"])},
              "visible_36": {"planned": report36["planned_cases"], "baseline": report36["baseline"],
                             "source_claims": report36["source_claims"],
                             "scripted_provider": report36["scripted_provider"]},
              "tampered_bytes": tamper, "arbitrary_version_quote_accepted": arbitrary_quote_accepted,
              "association_spoofs": association_spoofs,
              "unrelated_database_effect_accepted": fabricated_effect is not None,
              "unrelated_database_effect": fabricated_effect,
              "artifact_boundary": boundaries}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"v": result["v_summary"], "tampered_bytes": tamper,
                      "arbitrary_version_quote_accepted": arbitrary_quote_accepted,
                      "association_spoofs": association_spoofs,
                      "unrelated_database_effect_accepted": fabricated_effect is not None,
                      "artifact_boundary": boundaries}, sort_keys=True))


if __name__ == "__main__":
    main()
