"""Verify the byte-for-byte frozen release-validation inputs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    manifest_path = root / "benchmarks/phase-next-release-validation/freeze-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures = []
    for item in manifest["files"]:
        path = root / "benchmarks/phase-next-release-validation" / item["copy"]
        try:
            data = path.read_bytes()
        except OSError as exc:
            failures.append(f"{item['copy']}: {exc}")
            continue
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != item["bytes"] or digest != item["sha256"]:
            failures.append(f"{item['copy']}: size or SHA-256 mismatch")
    if failures:
        print("\n".join(failures))
        return 1
    print(f"verified {len(manifest['files'])} frozen files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
