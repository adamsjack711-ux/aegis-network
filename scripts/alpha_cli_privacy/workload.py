"""Generate and independently check the frozen synthetic dpkg workload."""

import argparse
import hashlib
import json
from pathlib import Path


def generate(path: Path, rows: int) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for number in range(rows):
            stream.write(
                f"Package: package{number:06d}\n"
                "Status: install ok installed\n"
                "Architecture: amd64\n"
                f"Version: 1:{number}.0-1\n\n"
            )


def verify(path: Path, rows: int) -> dict:
    raw = path.read_bytes()
    body = json.loads(raw)
    packages = body.get("packages", [])
    discrepancies = []
    if body.get("package_count") != rows or len(packages) != rows:
        discrepancies.append("package count")
    for number, package in enumerate(packages):
        expected = {
            "name": f"package{number:06d}",
            "purl": f"pkg:deb/debian/package{number:06d}",
            "version": f"1:{number}.0-1",
            "architecture": "amd64",
            "source": "dpkg-status",
        }
        if any(package.get(key) != value for key, value in expected.items()):
            discrepancies.append(number)
    return {
        "expected_rows": rows,
        "observed_rows": len(packages),
        "checked_rows": min(rows, len(packages)),
        "discrepancies": discrepancies[:20],
        "discrepancy_count": len(discrepancies),
        "inventory_complete": body.get("inventory_complete"),
        "identity_scope": body.get("identity_scope"),
        "asset_id": body.get("asset_id"),
        "stdout_bytes": len(raw),
        "stdout_sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("generate", "verify"))
    parser.add_argument("path", type=Path)
    parser.add_argument("rows", type=int)
    args = parser.parse_args()
    if args.action == "generate":
        generate(args.path, args.rows)
    else:
        print(json.dumps(verify(args.path, args.rows), sort_keys=True))


if __name__ == "__main__":
    main()
