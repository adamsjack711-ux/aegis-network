"""Explicit-target, read-only intelligence CLI. See docs/phase5a-intelligence.md."""

import argparse
import json
from pathlib import Path

from aegis.intelligence import Asset, archive_snapshot, assess, normalize, snapshot
from aegis.intelligence.feeds import MAX_BYTES


REQUEST_MAX_BYTES = 64 * 1024


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"local input exceeds {limit} byte limit")
    return content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("request", type=Path, help="local JSON request with an authorized target")
    parser.add_argument("--output", type=Path, help="local JSON report path; stdout by default")
    args = parser.parse_args()
    request = json.loads(read_bounded(args.request, REQUEST_MAX_BYTES))
    asset = Asset.model_validate(request["asset"])
    if request.get("authorized_target") != asset.asset_id:
        raise ValueError("explicit authorized_target must match asset_id")
    feeds = request.get("sources") or []
    if not 1 <= len(feeds) <= 8:
        raise ValueError("request requires 1-8 sources")
    if request.get("research_provider", "none") != "none":
        raise ValueError("CLI only accepts offline deterministic requests")
    snapshots = []
    for item in feeds:
        if item.get("mode") == "fixture":
            raw = read_bounded(Path(item["path"]), MAX_BYTES)
            snapshots.append(snapshot(item["kind"], item["uri"], raw))
        else:
            raise ValueError("source mode must be fixture")
    if request.get("archive_dir"):
        for source in snapshots:
            archive_snapshot(source, Path(request["archive_dir"]))
    claims = tuple(claim for source in snapshots for claim in normalize(source))
    assessment = assess(asset, claims, request["vulnerability_id"])
    report = {"schema_version": "phase5a-report-v1", "target": asset.asset_id,
              "assessment": assessment.model_dump(mode="json"),
              "claims": [claim.model_dump(mode="json") for claim in claims],
              "sources": [{"kind": source.kind, "acquisition": source.acquisition,
                           "uri": source.uri, "retrieved_at": source.retrieved_at.isoformat(),
                           "sha256": source.sha256} for source in snapshots]}
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized)
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
