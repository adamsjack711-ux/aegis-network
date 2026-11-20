"""Freeze prior validation bytes at the Alpha Readiness integration parent."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = "29455087922a728a41936d8c5c79ff9942e1e3df"
PRIOR = Path("benchmarks/phase-next-six-validation/original-evidence-manifest.json")
OUT = ROOT / "benchmarks/alpha-readiness-validation/prior-evidence-manifest.json"
PATHS = (
    "benchmarks/phase-next-six-validation/5b2/baseline-path-races.txt",
    "benchmarks/phase-next-six-validation/5b2/grant-race-open.txt",
    "benchmarks/phase-next-six-validation/5b2/focused.txt",
    "benchmarks/phase-next-six-validation/5b2/linux-parent-race.json",
    "benchmarks/phase-next-six-validation/5b2/linux-source-path-controls.json",
    "benchmarks/phase-next-six-validation/5b1/fail-closed-preflight.json",
    "benchmarks/phase-next-six-validation/5b1/focused.txt",
    "benchmarks/phase-next-six-validation/5a1/offline-exact-pin.json",
    "benchmarks/phase-next-six-validation/5a1/independent-rescore.json",
    "benchmarks/phase-next-six-validation/5a1/negative-controls.txt",
)


def git_bytes(path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT)


def manifest() -> dict:
    prior_raw = (ROOT / PRIOR).read_bytes()
    prior = json.loads(prior_raw)
    if prior["baseline"] != "ec939e14a5acd438ff0d5fa562ed61a70b68f3c9" or len(prior["entries"]) != 44:
        raise ValueError("prior 44-file seal changed")
    for entry in prior["entries"]:
        raw = (ROOT / entry["copy_path"]).read_bytes()
        if (hashlib.sha256(raw).hexdigest() != entry["sha256"] or
                len(raw) != entry["bytes"] or raw != git_bytes_from(entry["baseline_blob"])):
            raise ValueError(f"prior retained bytes changed: {entry['copy_path']}")
    entries = []
    for path in PATHS:
        raw = (ROOT / path).read_bytes()
        if raw != git_bytes(path):
            raise ValueError(f"new retained bytes changed: {path}")
        blob = subprocess.check_output(["git", "rev-parse", f"{BASE}:{path}"], cwd=ROOT, text=True).strip()
        entries.append({"path": path, "git_blob": blob, "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest()})
    return {"schema_version": "alpha-readiness-prior-evidence-v1", "baseline": BASE,
            "prior_manifest_path": str(PRIOR), "prior_manifest_sha256": hashlib.sha256(prior_raw).hexdigest(),
            "prior_original_count": 44, "additional_count": len(entries), "entries": entries}


def git_bytes_from(blob: str) -> bytes:
    return subprocess.check_output(["git", "show", blob], cwd=ROOT)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    expected = manifest()
    if args.verify:
        if json.loads(OUT.read_bytes()) != expected:
            raise SystemExit("alpha readiness prior evidence manifest changed")
    else:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if head != BASE or OUT.exists():
            raise SystemExit("freeze only from exact clean parent with absent output")
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(expected, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"baseline": BASE, "prior_original_verified": 44,
                      "additional_verified": len(expected["entries"]),
                      "manifest_sha256": hashlib.sha256(OUT.read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()
