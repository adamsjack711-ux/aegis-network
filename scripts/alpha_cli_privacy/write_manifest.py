"""Hash retained alpha CLI privacy evidence without rewriting the evidence."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "benchmarks/alpha-cli-privacy"
MANIFEST = EVIDENCE / "sha256-manifest.json"


def main() -> None:
    records = []
    for path in sorted(EVIDENCE.rglob("*")):
        if not path.is_file() or path == MANIFEST:
            continue
        raw = path.read_bytes()
        records.append({
            "path": str(path.relative_to(ROOT)),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    MANIFEST.write_text(json.dumps({"source_commit": "29455087922a728a41936d8c5c79ff9942e1e3df",
                                   "files": records}, indent=2) + "\n")


if __name__ == "__main__":
    main()
