"""Independently score fixed signed CLI v2 observations without a writer."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate-root", type=Path, required=True)
    p.add_argument("--source-pin", required=True)
    p.add_argument("--fixture-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    root, fixture = a.candidate_root.resolve(), a.fixture_root.resolve()
    pin = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip()
    if pin != a.source_pin or dirty:
        raise ValueError("candidate is not the clean exact pin")
    sys.path.insert(0, str(root / "src"))
    import aegis.cli as cli
    from aegis.intelligence_adapter import load_intelligence
    from aegis.local_observer import ObservationError, asset_identity, collect_snapshot, match_findings
    cases = []

    def add(name, okay, observed):
        cases.append({"case": name, "status": "pass" if okay else "fail", "observed": observed})

    now = datetime(2026, 11, 20, tzinfo=timezone.utc)
    snap = collect_snapshot(None, os_release=fixture / "os-release",
                            dpkg_status=fixture / "dpkg-status", now=now)
    original = cli.collect_snapshot
    originals = {"socket": socket.socket, "popen": subprocess.Popen,
                 "system": os.system, "setuid": os.setuid, "setgid": os.setgid}
    blocked_calls = []

    def deny(name):
        def blocked(*_args, **_kwargs):
            blocked_calls.append(name)
            raise AssertionError("forbidden observation API: " + name)
        return blocked

    cli.collect_snapshot = lambda asset_id: snap
    socket.socket = deny("socket.socket")
    subprocess.Popen = deny("subprocess.Popen")
    os.system = deny("os.system")
    os.setuid = deny("os.setuid")
    os.setgid = deny("os.setgid")
    try:
        for name, local, match, exit_code in (
            ("signed-current", "current-in-supplied-file", "matched", 0),
            ("signed-expired", "expired", "matched", 2),
            ("signed-withdrawn", "withdrawn-in-supplied-file", "matched", 2),
            ("signed-unsupported-range", "current-in-supplied-file", "unknown", 2),
        ):
            args = argparse.Namespace(command="findings", state_dir=None, feed=fixture / f"{name}.json",
                                      trust=fixture / "trust.json", finding_id=None, json=True)
            data, code = cli.run(args)
            row = data["findings"][0]
            okay = (code == exit_code and data["schema_version"] == "observation-results-v2" and
                    data["asset_id"] is None and data["identity_scope"] == "none" and
                    row["publisher_authenticity"] == "verified" and
                    row["local_claim_status"] == local and row["software_match"] == match and
                    row["independent_status"] == row["overall_assessment"] == "unknown" and
                    row["independent_status_reason"] == "NO_VERIFIABLE_T4_T5_PROOF" and
                    "result" not in row and "claim_status" not in row)
            add(name, okay, {"exit": code, "row": row})
        args = argparse.Namespace(command="status", state_dir=None,
                                  feed=fixture / "signed-current.json", trust=fixture / "trust.json",
                                  finding_id=None, json=True)
        data, code = cli.run(args)
        add("status_v2_unknown_independent",
            code == 0 and data["schema_version"] == "status-v2" and
            data["independent_status"] == data["overall_assessment"] == "unknown" and
            data["potential_findings"] == 1, {"exit": code, "data": data})
    finally:
        cli.collect_snapshot = original
        socket.socket = originals["socket"]
        subprocess.Popen = originals["popen"]
        os.system = originals["system"]
        os.setuid = originals["setuid"]
        os.setgid = originals["setgid"]
    add("signed_observation_api_guard", not blocked_calls, {"blocked_calls": blocked_calls,
        "scope": "Python-level network, subprocess and privilege APIs; not syscall trace"})

    advisories = load_intelligence(fixture / "signed-current.json", trust_path=fixture / "trust.json", now=now)
    for name, path in (("partial_inventory", fixture / "dpkg-truncated"),
                       ("duplicate_inventory", fixture / "dpkg-duplicate")):
        partial = collect_snapshot(None, os_release=fixture / "os-release", dpkg_status=path, now=now)
        row = match_findings(partial.packages, advisories, now=now, inventory_complete=partial.complete)[0]
        add(name, not partial.complete and row["software_match"] == "unknown" and
            row["match_reason"] == "INVENTORY_INCOMPLETE" and row["independent_status"] == "unknown",
            {"inventory_complete": partial.complete, "inventory_reason": partial.reason, "row": row})
    try:
        load_intelligence(fixture / "malformed-feed.json", trust_path=fixture / "trust.json", now=now)
    except ObservationError as exc:
        add("malformed_feed_rejected", True, {"error": str(exc)})
    else:
        add("malformed_feed_rejected", False, {"accepted": True})

    with TemporaryDirectory(prefix="aegis-cli-state-challenge-") as scratch:
        base = Path(scratch)
        outside = base / "outside"
        outside.mkdir()
        alias = base / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        for name, target in (("ancestor_symlink", alias / "aegis"),
                             ("final_symlink", alias)):
            try:
                asset_identity(target)
            except ObservationError as exc:
                add(name, not (outside / "identity.json").exists() and
                    not (outside / "aegis").exists(), {"error": str(exc)})
            else:
                add(name, False, {"unexpected_identity": True})

    output = {"source_pin": pin, "topology": "one-process fixed signed local fixture; no target writer",
              "cases": cases, "summary": {s: sum(c["status"] == s for c in cases)
                                   for s in ("pass", "fail", "inconclusive", "skipped")},
              "limitations": ["Inventory collection redirected to independent fixed fixture",
                              "No syscall tracer, wheel install, or connected-network consent trial"]}
    a.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps(output["summary"]))


if __name__ == "__main__":
    main()
