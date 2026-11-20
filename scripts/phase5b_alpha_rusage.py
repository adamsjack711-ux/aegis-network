"""Measure installed CLI inventory cost in disposable Linux containers.

The caller provides a direct console-script path and a writable tmpfs mounted
at /var/lib/dpkg. Each trial starts a fresh CLI process. No network is used.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import resource
import subprocess
import time

STATUS = Path("/var/lib/dpkg/status")


def write_status(count: int) -> int:
    with STATUS.open("w", encoding="utf-8") as stream:
        for number in range(count):
            stream.write(f"Package: package{number:06d}\nStatus: install ok installed\n"
                         f"Architecture: amd64\nVersion: 1:{number}.0-1\n\n")
    return STATUS.stat().st_size


def trial(console: Path, packages: int, repetition: int) -> dict:
    environment = os.environ | {"PYTHONDONTWRITEBYTECODE": "1",
                                "XDG_STATE_HOME": "/tmp/aegis-resource-state"}
    start = time.perf_counter_ns()
    with subprocess.Popen([str(console), "inventory", "--json"], env=environment,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as child:
        pid, status, usage = os.wait4(child.pid, 0)
        stderr = child.stderr.read().decode("utf-8", errors="replace")
        exit_code = os.waitstatus_to_exitcode(status)
        child.returncode = exit_code
    wall_ms = (time.perf_counter_ns() - start) / 1_000_000
    return {"packages": packages, "repetition": repetition, "pid": pid,
            "exit": exit_code, "wall_ms": round(wall_ms, 3),
            "cpu_ms": round((usage.ru_utime + usage.ru_stime) * 1000, 3),
            "peak_rss_mib": round(usage.ru_maxrss / 1024, 3),
            "stderr": stderr[:4096], "state_created": Path("/tmp/aegis-resource-state").exists()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console", type=Path, required=True)
    parser.add_argument("--distro", choices=("debian", "ubuntu"), required=True)
    args = parser.parse_args()
    actual = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if line.startswith("ID="):
            actual["id"] = line[3:].strip().strip('"')
    if actual.get("id") != args.distro:
        raise SystemExit("real container distribution differs from requested row")
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    inputs = {}
    for count in (100, 10_000, 100_000):
        inputs[str(count)] = write_status(count)
        for repetition in range(1, 4):
            rows.append(trial(args.console, count, repetition))
    print(json.dumps({"at_utc": datetime.now(timezone.utc).isoformat(),
                      "distro": args.distro, "python": os.sys.version.split()[0],
                      "planned": 9, "attempted": len(rows), "completed": sum(row["exit"] is not None for row in rows),
                      "input_bytes": inputs, "trials": rows}, sort_keys=True))
    if any(row["exit"] != 0 or row["state_created"] for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
