"""Run the pinned Phase 5A parser and matcher on independent synthetic advisories."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def make_source(case_id, source, spec, vulnerability_id):
    ghsa = "GHSA-aaaa-bbbb-cccc"
    identity = spec["identity"]
    if identity.startswith("pkg:"):
        ecosystem, name = identity[4:].split("/", 1)
        mapped = {"pypi": "pip", "npm": "npm", "maven": "maven", "deb": "debian"}.get(ecosystem, ecosystem)
    else:
        mapped, name = "", ""
    version = spec["versions"][0]
    expression = version.get("value", "")
    if version["scheme"] == "exact":
        expression = "=" + expression
    body = {"ghsa_id": ghsa, "cve_id": vulnerability_id,
            "summary": source["text"], "withdrawn_at": spec.get("withdrawn_at"),
            "vulnerabilities": [{"package": {"ecosystem": mapped, "name": name},
                                 "vulnerable_version_range": expression}]}
    uri = f"https://fixture.invalid/{source['id']}/{ghsa}"
    return uri, json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-pin", required=True)
    args = parser.parse_args()
    candidate = args.candidate_root.resolve()
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=candidate, text=True).strip()
    if actual != args.source_pin or subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=candidate, text=True).strip():
        raise ValueError("candidate is not the requested clean exact pin")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.path.insert(0, str(candidate / "src"))
    from aegis.intelligence import Asset, assess, normalize, snapshot

    data = json.load(sys.stdin)
    case_id = data["case_id"]
    specs = json.loads((ROOT / "fixtures/phase-next-ai-claim-map-v1.json").read_text())["cases"][case_id]
    if case_id == "H11-epoch-boundary":
        raise ValueError("unmappable: Debian epoch range has no enrolled 5A comparator")
    sources = {item["id"]: item for item in data["sources"]}
    vulnerability_id = "AEGIS-ADV-" + str(100 + int(case_id[1:3]))
    claims = []
    for spec in specs:
        source = sources[spec["source_id"]]
        uri, raw = make_source(case_id, source, spec, vulnerability_id)
        claims.extend(normalize(snapshot("vendor-ghsa", uri, raw,
                                         retrieved_at=datetime.now(timezone.utc))))
    asset_data = data["asset"]
    asset = Asset(asset_id=case_id, identity_kind="purl",
                  identity=f"pkg:{asset_data['ecosystem']}/{asset_data['name']}",
                  version=asset_data["version"])
    assessment = assess(asset, tuple(claims), vulnerability_id)
    citations = sorted({ref.uri.split("/")[-2] for ref in assessment.references})
    print(json.dumps({"decision": "unknown" if assessment.outcome == "conflicting" else assessment.outcome,
                      "native_outcome": assessment.outcome, "citations": citations,
                      "claims": [], "normalized_claim_count": len(claims),
                      "reasons": assessment.reasons}, sort_keys=True))


if __name__ == "__main__":
    main()
