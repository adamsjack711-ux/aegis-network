"""The on-demand, offline Aegis observation CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .intelligence_adapter import load_intelligence
from .local_observer import (
    ObservationError, asset_identity, collect_snapshot, distribution,
    match_findings,
)

CLI_VERSION = "0.1.0"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Offline, observation-only local exposure inspection")
    parser.add_argument("--state-dir", type=Path, help="opt in to a private persistent random local asset ID")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "inventory", "findings", "explain", "doctor"):
        command = sub.add_parser(name)
        command.add_argument("--json", action="store_true", help="print machine-readable JSON")
        if name in {"status", "findings", "explain", "doctor"}:
            command.add_argument("--feed", type=Path, help="local signed Mesh event JSON; never fetched")
            command.add_argument("--trust", type=Path, help="locally pinned publisher grants for a signed Mesh feed")
        if name == "explain":
            command.add_argument("finding_id", help="ID printed by aegis findings")
    return parser


def _emit(data: object, json_output: bool, command: str) -> None:
    def safe(value: object) -> str:
        return json.dumps(str(value), ensure_ascii=True)[1:-1]

    if json_output:
        # json.dumps materializes the entire pretty-printed inventory and
        # transiently doubles peak memory at the 100,000-package input bound.
        # json.dump uses the same encoder and output contract incrementally.
        json.dump(data, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
        return
    if command == "inventory":
        assert isinstance(data, dict)
        asset = data["asset_id"] or "unspecified (no persisted identity)"
        print(f"Asset {asset} · {data['distribution']} · {data['package_count']} installed binary packages · complete={data['inventory_complete']}")
        if not data["inventory_complete"]:
            print(f"unknown: {safe(data['inventory_reason'])}")
        for item in data["packages"]:
            print(f"{safe(item['purl'])} {safe(item['version'])} [{safe(item['architecture'])}]")
    elif command == "findings":
        assert isinstance(data, dict)
        print(f"{data['current_exact_package_match_count']} current local claims with exact package matches; {data['observation_count']} signed claims observed; independent Evidence status unknown")
        for item in data["findings"]:
            print(" ".join(safe(item[key]) for key in
                           ("finding_id", "software_match", "vulnerability_id", "purl", "installed_version")))
    elif command == "explain":
        assert isinstance(data, dict)
        for key, value in data.items():
            print(f"{safe(key)}: {safe(value)}")
    else:
        assert isinstance(data, dict)
        for key, value in data.items():
            print(f"{safe(key)}: {safe(value)}")


def run(args: argparse.Namespace) -> tuple[object, int]:
    identity_scope = "explicit-local" if args.state_dir is not None else "none"
    if args.command == "doctor":
        checks: dict[str, object] = {}
        ready = True
        try:
            checks["distribution"] = distribution()
        except ObservationError as exc:
            checks["distribution"] = str(exc)
            ready = False
        try:
            asset_id = asset_identity(args.state_dir) if args.state_dir is not None else None
            checks["asset_id"] = asset_id
            if asset_id is None:
                checks["identity_note"] = "not persisted (pass --state-dir to opt in)"
            try:
                snapshot = collect_snapshot(asset_id)
                checks["inventory"] = (f"{len(snapshot.packages)} installed binary packages" if snapshot.complete
                                       else f"unknown: {snapshot.reason}")
                if not snapshot.complete:
                    ready = False
            except OSError as exc:
                checks["inventory"] = str(exc)
                ready = False
        except (ObservationError, OSError) as exc:
            checks["asset_id"] = str(exc)
            ready = False
        if getattr(args, "feed", None):
            try:
                checks["advisories"] = f"{len(load_intelligence(args.feed, trust_path=args.trust))} loaded"
            except ObservationError as exc:
                checks["advisories"] = str(exc)
                ready = False
        else:
            checks["advisories"] = "not configured (pass --feed to findings)"
        checks["network"] = "disabled; no sockets or listeners"
        checks["enforcement"] = "unavailable"
        checks["schema_version"] = "doctor-v2"
        checks["identity_scope"] = identity_scope
        checks["independent_status"] = "unknown"
        checks["ready"] = "yes" if ready else "no"
        return checks, 0 if checks["ready"] == "yes" else 2

    asset_id = asset_identity(args.state_dir) if args.state_dir is not None else None
    snapshot = collect_snapshot(asset_id)
    packages = snapshot.packages
    distro = packages[0].purl.split("/")[1] if packages else "unknown"
    if args.command == "inventory":
        return {"schema_version": "inventory-v2", "cli_version": CLI_VERSION,
                "asset_id": asset_id, "snapshot_id": snapshot.snapshot_id,
                "identity_scope": identity_scope,
                "captured_at": snapshot.captured_at, "distribution": distro,
                "inventory_complete": snapshot.complete, "inventory_reason": snapshot.reason,
                "package_count": len(packages), "packages": [item.as_dict() for item in packages]}, 0 if snapshot.complete else 2
    if args.command == "status":
        data: dict[str, object] = {"schema_version": "status-v2", "asset_id": asset_id,
                                   "identity_scope": identity_scope, "cli_version": CLI_VERSION,
                                   "distribution": distro, "intelligence_scope": "supplied-signed-events-only",
                                   "package_count": len(packages), "inventory_complete": snapshot.complete,
                                   "inventory_reason": snapshot.reason, "network": "offline",
                                   "mode": "observation-only", "independent_status": "unknown",
                                   "independent_status_reason": "NO_VERIFIABLE_T4_T5_PROOF",
                                   "overall_assessment": "unknown"}
        if args.feed:
            claims = load_intelligence(args.feed, trust_path=args.trust)
            findings = match_findings(packages, claims,
                                      inventory_complete=snapshot.complete, asset_id=asset_id)
            data["claim_count"] = len(claims)
            data["potential_findings"] = sum(item["software_match"] == "matched" and
                                              item["local_claim_status"] == "current-in-supplied-file"
                                              for item in findings)
            data["unknown_claims"] = sum(item["software_match"] == "unknown" or
                                         item["local_claim_status"] != "current-in-supplied-file"
                                         for item in findings)
        else:
            data["potential_findings"] = "unknown; no signed local finding file supplied"
        return data, 0 if snapshot.complete and args.feed and data.get("claim_count", 0) and data.get("unknown_claims", 0) == 0 else 2
    if not args.feed:
        raise ObservationError("--feed is required for findings and explain")
    claims = load_intelligence(args.feed, trust_path=args.trust)
    findings = match_findings(packages, claims,
                              inventory_complete=snapshot.complete, asset_id=asset_id)
    if args.command == "findings":
        return {"schema_version": "observation-results-v2", "cli_version": CLI_VERSION,
                "asset_id": asset_id, "intelligence_scope": "supplied-signed-events-only",
                "identity_scope": identity_scope,
                "snapshot_id": snapshot.snapshot_id, "inventory_complete": snapshot.complete,
                "inventory_reason": snapshot.reason,
                "claim_count": len(claims),
                "current_exact_package_match_count": sum(
                    item["software_match"] == "matched" and
                    item["local_claim_status"] == "current-in-supplied-file" for item in findings),
                "observation_count": len(findings), "findings": findings}, 0 if snapshot.complete and claims and not any(
                    item["software_match"] == "unknown" or
                    item["local_claim_status"] != "current-in-supplied-file" for item in findings) else 2
    for finding in findings:
        if finding["finding_id"] == args.finding_id:
            return {"schema_version": "exposure-observation-v2", "identity_scope": identity_scope,
                    **finding}, 0 if snapshot.complete and finding["software_match"] != "unknown" and \
                    finding["local_claim_status"] == "current-in-supplied-file" else 2
    raise ObservationError("finding ID not present in current inventory and signed event file")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        data, code = run(args)
    except (ObservationError, OSError) as exc:
        if args.json:
            print(json.dumps({"schema_version": "observation-error-v2", "status": "unknown",
                              "independent_status": "unknown", "error": str(exc)}))
        else:
            print(f"aegis: {exc}", file=sys.stderr)
        return 2
    try:
        _emit(data, args.json, args.command)
    except BrokenPipeError:
        # A closed output consumer is a bounded observation failure, not a
        # reason to retry, persist state or show a traceback at interpreter
        # shutdown when stdout is flushed again.
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
