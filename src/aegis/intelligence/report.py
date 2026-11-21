"""Read the current private research result for one advisory and asset."""

import argparse
import json
from pathlib import Path
import re
import sqlite3
import sys

from .handoff import read_history
from .investigator import Investigation, StructuredResearchCandidate


def read_asset_report(path: Path, source_kind: str, advisory_id: str,
                      vulnerability_id: str, asset_digest: str) -> dict:
    """Project one fresh history snapshot onto the exact research subject."""
    if not re.fullmatch(r"[0-9a-f]{64}", asset_digest):
        raise ValueError("asset_digest must be the 64-character lowercase SHA-256 from research history")
    rows = read_history(path, source_kind, advisory_id)
    history = []
    current = None
    for row in rows:
        if row["vulnerability_id"] != vulnerability_id or row["asset_digest"] != asset_digest:
            continue
        revision = {key: row[key] for key in ("sequence", "revision", "status")}
        history.append(revision)
        if row["status"] != "current":
            continue
        if current is not None:
            raise ValueError("multiple current research results for the selected subject")
        research = Investigation.model_validate_json(json.dumps(row["research"]))
        candidate = research.candidate
        if (candidate.advisory_id != advisory_id or candidate.vulnerability_id != vulnerability_id
                or research.check.source_digests != (row["revision"],)):
            raise ValueError("current research does not match its advisory, vulnerability and revision")
        references = None
        if isinstance(candidate, StructuredResearchCandidate):
            references = [ref.model_dump(mode="json") for ref in candidate.applicability_references]
        current = {
            "sequence": row["sequence"], "revision": row["revision"],
            "reportable_outcome": candidate.reportable_outcome, "check_status": research.check.status,
            "reason_codes": list(research.check.reason_codes), "applicability_references": references,
            "independently_verified": candidate.independently_verified,
        }
    return {"source_kind": source_kind, "advisory_id": advisory_id, "vulnerability_id": vulnerability_id,
            "asset_digest": asset_digest, "current": current, "history": history}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path, help="existing Scout and OfflineHandoff SQLite database")
    parser.add_argument("source_kind", help="source kind recorded by Scout")
    parser.add_argument("advisory_id")
    parser.add_argument("vulnerability_id")
    parser.add_argument("asset_digest", help="asset SHA-256 recorded by read_history")
    args = parser.parse_args(argv)
    try:
        report = read_asset_report(args.database, args.source_kind, args.advisory_id,
                                   args.vulnerability_id, args.asset_digest)
    except (sqlite3.Error, ValueError) as exc:
        print(f"research report: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
