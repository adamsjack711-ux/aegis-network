"""Independently rescore a sealed Phase 5A offline benchmark."""

import argparse
import json
from pathlib import Path

from aegis.intelligence.independent_validation import validate_offline_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    scored = validate_offline_report(args.root, json.loads(args.input.read_bytes()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(scored, indent=2, sort_keys=True) + "\n")
    first = scored["trials"][0]
    print(f"{first['planned']} planned; {first['eligible']} eligible; {first['exact']} exact; "
          f"{first['inconclusive']} inconclusive; real model skipped")


if __name__ == "__main__":
    main()
