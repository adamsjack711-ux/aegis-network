"""Measure bounded offline collection and exact matching on synthetic dpkg data."""

import argparse
import json
import platform
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

from datetime import datetime, timezone

from aegis.local_observer import Advisory, collect_inventory, match_findings


def measure(package_count: int, advisory_count: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="aegis-phase5b-") as directory:
        root = Path(directory)
        release = root / "os-release"
        release.write_text("ID=debian\n")
        status = root / "status"
        with status.open("w") as stream:
            for number in range(package_count):
                stream.write(f"Package: package{number:06d}\nStatus: install ok installed\n"
                             f"Architecture: amd64\nVersion: 1:{number}.0-1\n\n")
        advisories = [Advisory(f"CVE-2026-{number:06d}", f"pkg:deb/debian/package{number:06d}",
                               (f"1:{number}.0-1",), "Synthetic benchmark", "synthetic-normalized-claim",
                               datetime(2027, 1, 1, tzinfo=timezone.utc), None)
                      for number in range(advisory_count)]
        start_cpu = time.process_time()
        start_wall = time.perf_counter()
        tracemalloc.start()
        packages = collect_inventory("synthetic-asset", os_release=release, dpkg_status=status)
        findings = match_findings(packages, advisories)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return {"packages": package_count, "advisories": advisory_count,
                "software_matches": sum(row["software_match"] == "matched" for row in findings),
                "wall_ms": round((time.perf_counter() - start_wall) * 1000, 2),
                "cpu_ms": round((time.process_time() - start_cpu) * 1000, 2),
                "python_peak_mib": round(peak / 1024 / 1024, 2),
                "input_disk_mib": round(status.stat().st_size / 1024 / 1024, 2)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {"scope": "single process, synthetic dpkg status and in-memory normalized unsigned claim records, no network or signature parsing",
              "environment": {"python": sys.version.split()[0], "platform": platform.platform()},
              "runs": [measure(1000, 100), measure(10000, 1000)]}
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
