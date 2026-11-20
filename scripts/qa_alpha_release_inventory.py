"""Source-level 100,000-row CLI inventory diagnostic on the local host.

This is not an installed Linux or hard-cgroup acceptance run. It uses a
disposable synthetic dpkg file and checks every emitted package identity.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import platform
import resource
import sys
import tempfile
import time
from pathlib import Path

from aegis import cli
from aegis.local_observer import collect_snapshot


def main() -> int:
    rows = 100_000
    with tempfile.TemporaryDirectory(prefix="aegis-alpha-qa-") as directory:
        root = Path(directory)
        release = root / "os-release"
        status = root / "status"
        output = root / "inventory.json"
        release.write_text("ID=debian\n", encoding="utf-8")
        with status.open("w", encoding="utf-8") as stream:
            for number in range(rows):
                stream.write(
                    f"Package: package{number:06d}\n"
                    "Status: install ok installed\n"
                    "Architecture: amd64\n"
                    f"Version: 1:{number}.0-1\n\n"
                )
        cli.collect_snapshot = lambda asset_id: collect_snapshot(
            asset_id, os_release=release, dpkg_status=status
        )
        wall_start = time.perf_counter()
        cpu_start = time.process_time()
        with output.open("w", encoding="utf-8") as stream, contextlib.redirect_stdout(stream):
            exit_code = cli.main(["inventory", "--json"])
        wall_ms = round((time.perf_counter() - wall_start) * 1000, 2)
        cpu_ms = round((time.process_time() - cpu_start) * 1000, 2)
        peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_rss_mib = round(peak_rss / (1024 if sys.platform.startswith("linux") else 1024 * 1024), 2)
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        data = json.loads(output.read_text(encoding="utf-8"))
        packages = data.get("packages", [])
        complete = (
            exit_code == 0
            and data.get("inventory_complete") is True
            and data.get("package_count") == rows
            and len(packages) == rows
            and all(
                item["purl"] == f"pkg:deb/debian/package{number:06d}"
                and item["version"] == f"1:{number}.0-1"
                for number, item in enumerate(packages)
            )
        )
        print(json.dumps({
            "scope": "source-level synthetic host diagnostic; no installed console or cgroup limit",
            "host": platform.platform(),
            "python": platform.python_version(),
            "rows": rows,
            "exit_code": exit_code,
            "reported_count": data.get("package_count"),
            "all_package_identities_correct": complete,
            "output_bytes": output.stat().st_size,
            "output_sha256": digest,
            "wall_ms": wall_ms,
            "cpu_ms": cpu_ms,
            "peak_rss_mib": peak_rss_mib,
        }, sort_keys=True))
        return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
