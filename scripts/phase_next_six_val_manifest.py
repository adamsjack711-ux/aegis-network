"""Seal prior validation artifacts before reviewing successor implementation."""

from __future__ import annotations

from hashlib import sha256
import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASELINE = "ec939e14a5acd438ff0d5fa562ed61a70b68f3c9"
OLD_MANIFEST = Path("benchmarks/phase-next-r-validation/original-evidence-manifest.json")
OUT = ROOT / "benchmarks/phase-next-six-validation"

EXTRAS = (
    "benchmarks/phase4e/integrated-final-348.xml",
    "benchmarks/phase-next-r-validation/original-evidence-manifest.json",
    "benchmarks/phase-next-r-validation/5a-r/independent-challenge.json",
    "benchmarks/phase-next-r-validation/5a-r/repair-ebcc30c/independent-challenge.json",
    "benchmarks/phase-next-r-validation/5b-r/baseline-512m-100k-kali-debian-fixture.json",
    "benchmarks/phase-next-r-validation/5b-r/candidate-256m-100k-kali-debian-fixture.json",
    "benchmarks/phase-next-r-validation/5b-r/byte-equivalence-kali-fixed-fixture.json",
    "benchmarks/phase-next-r-validation/integration-5a-pytest.xml",
    "benchmarks/phase-next-r-validation/retained-b81/benchmarks/phase-next-alpha-validation/withdrawal-baseline-fresh-1.json",
    "fixtures/phase-next-ai-holdout-v1.json",
    "fixtures/phase-next-alpha-ai/holdout-v1.json",
    "fixtures/phase-next-alpha-ai/seal-manifest.json",
)


def git_bytes(path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{BASELINE}:{path}"], cwd=ROOT)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true", help="check the retained copies without writing")
    args = parser.parse_args()
    if args.verify:
        manifest = json.loads((OUT / "original-evidence-manifest.json").read_bytes())
        if manifest["baseline"] != BASELINE:
            raise SystemExit("manifest baseline changed")
        for entry in manifest["entries"]:
            raw = (ROOT / entry["copy_path"]).read_bytes()
            if (raw != git_bytes(entry["source_path"]) or len(raw) != entry["bytes"] or
                    sha256(raw).hexdigest() != entry["sha256"]):
                raise SystemExit(f"retained bytes changed: {entry['source_path']}")
        print(json.dumps({"verified": len(manifest["entries"]), "baseline": BASELINE}, sort_keys=True))
        return
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if head != BASELINE:
        raise SystemExit(f"wrong freeze baseline: {head}")
    prior = json.loads((ROOT / OLD_MANIFEST).read_bytes())
    expected = {entry["retained_path"]: entry for entry in prior["entries"]}
    paths = sorted(set(expected) | set(EXTRAS))
    entries = []
    for source in paths:
        raw = (ROOT / source).read_bytes()
        if raw != git_bytes(source):
            raise SystemExit(f"baseline blob mismatch: {source}")
        old = expected.get(source)
        pin = sha256(raw).hexdigest()
        if old and (pin != old["sha256"] or len(raw) != old["bytes"]):
            raise SystemExit(f"prior seal mismatch: {source}")
        destination = OUT / "original" / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and destination.read_bytes() != raw:
            raise SystemExit(f"existing retained copy mismatch: {destination}")
        destination.write_bytes(raw)
        blob = subprocess.check_output(["git", "rev-parse", f"{BASELINE}:{source}"],
                                       cwd=ROOT, text=True).strip()
        entries.append({"source_path": source, "copy_path": str(destination.relative_to(ROOT)),
                        "baseline_blob": blob, "sha256": pin, "bytes": len(raw),
                        "earlier_origin_commit": old["origin_commit"] if old else BASELINE,
                        "earlier_source_path": old["source_path"] if old else source})
    manifest = {"schema_version": "phase-next-six-original-evidence-v1", "baseline": BASELINE,
                "prior_manifest_sha256": sha256((ROOT / OLD_MANIFEST).read_bytes()).hexdigest(),
                "prior_retained_count": len(expected), "unique_retained_count": len(entries),
                "entries": entries}
    path = OUT / "original-evidence-manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    assert all((ROOT / entry["copy_path"]).read_bytes() == (ROOT / entry["source_path"]).read_bytes()
               for entry in entries)
    print(json.dumps({"baseline": BASELINE, "retained": len(entries),
                      "manifest_sha256": sha256(path.read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()
