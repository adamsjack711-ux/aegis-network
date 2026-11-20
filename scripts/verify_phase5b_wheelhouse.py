"""Fail closed on an incomplete or unreviewed offline runtime wheelhouse.

The manifest is supplied by the dependency review process. Every wheel must
have an exact SHA-256 and a provenance reference; this script never downloads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

REQUIRED = {"aegis_network", "cryptography", "cffi", "pycparser", "pydantic", "pydantic_core", "annotated_types", "typing_extensions", "typing_inspection"}


def verify(directory: Path, manifest_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != "phase5b-wheelhouse-v1":
        raise ValueError("unsupported wheelhouse manifest")
    entries = manifest.get("wheels")
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty wheelhouse manifest")
    names = set()
    files = set()
    for entry in entries:
        filename = entry["filename"]
        if Path(filename).name != filename or not filename.endswith(".whl"):
            raise ValueError(f"invalid wheel filename: {filename}")
        if not isinstance(entry.get("sha256"), str) or len(entry["sha256"]) != 64:
            raise ValueError(f"missing SHA-256: {filename}")
        if not entry.get("provenance") or not entry.get("reviewer"):
            raise ValueError(f"missing provenance or review: {filename}")
        if filename in files:
            raise ValueError(f"duplicate wheel: {filename}")
        if (directory / filename).is_symlink():
            raise ValueError(f"wheel must be a regular file: {filename}")
        files.add(filename)
        names.add(filename.split("-")[0].lower())
        digest = hashlib.sha256((directory / filename).read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError(f"SHA-256 mismatch: {filename}")
    if missing := REQUIRED - names:
        raise ValueError(f"missing runtime distributions: {', '.join(sorted(missing))}")
    if extra := {p.name for p in directory.glob("*.whl")} - files:
        raise ValueError(f"unreviewed wheels: {', '.join(sorted(extra))}")
    print(f"verified {len(files)} reviewed wheels in {directory}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("wheelhouse", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    verify(args.wheelhouse, args.manifest)
