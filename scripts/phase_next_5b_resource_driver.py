"""Run inside an offline unprivileged Linux container with a writable dpkg tmpfs."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
from time import perf_counter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if os.geteuid() == 0 or not 1 <= args.rows <= 100_000 or not 1 <= args.repeats <= 5:
        raise ValueError("requires non-root and bounded rows/repeats")
    path = Path("/var/lib/dpkg/status")
    digest = sha256()
    with path.open("wb") as stream:
        for index in range(args.rows):
            stanza = (f"Package: fixture{index:06d}\nStatus: install ok installed\n"
                      f"Architecture: amd64\nVersion: 1.0-{index % 10}\n\n").encode()
            stream.write(stanza)
            digest.update(stanza)
    runs = []
    for _ in range(args.repeats):
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = perf_counter()
        proc = subprocess.run([sys.executable, "-m", "aegis.cli", "--state-dir", "/tmp/explicit-aegis",
                               "status", "--json"], capture_output=True, text=True, check=False)
        wall = perf_counter() - started
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        try:
            body = json.loads(proc.stdout)
        except json.JSONDecodeError:
            body = None
        runs.append({"exit_code": proc.returncode, "wall_ms": round(wall * 1000, 3),
                     "cpu_ms": round(((after.ru_utime + after.ru_stime) -
                                      (before.ru_utime + before.ru_stime)) * 1000, 3),
                     "peak_rss_kib_at_least": after.ru_maxrss,
                     "reported_count": body.get("package_count") if body else None,
                     "inventory_complete": body.get("inventory_complete") if body else None,
                     "stderr": proc.stderr[:1000]})
    print(json.dumps({"rows": args.rows, "input_sha256": digest.hexdigest(),
                      "input_bytes": path.stat().st_size, "uid": os.geteuid(),
                      "runs": runs}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
