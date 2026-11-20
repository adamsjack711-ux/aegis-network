"""Offline source-CLI resource trial in a disposable Linux container.

The caller mounts /var/lib/dpkg as tmpfs and caps the container memory. Each
trial launches a fresh CLI process. This is owner evidence, not validation.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time


STATUS = Path("/var/lib/dpkg/status")
EVENTS = Path("/sys/fs/cgroup/memory.events")


def events() -> dict[str, int]:
    return {key: int(value) for key, value in
            (line.split() for line in EVENTS.read_text().splitlines())} if EVENTS.exists() else {}


def trial(repetition: int, delay: float = 0.0, closed: bool = False) -> dict:
    env = os.environ | {"PYTHONDONTWRITEBYTECODE": "1", "XDG_STATE_HOME": "/tmp/implicit-state"}
    before = events()
    start = time.perf_counter_ns()
    child = subprocess.Popen([sys.executable, "-m", "aegis.cli", "inventory", "--json"],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output_bytes = 0
    if closed:
        child.stdout.close()
    else:
        while chunk := child.stdout.read(65536):
            output_bytes += len(chunk)
            if delay:
                time.sleep(delay)
    pid, status, usage = os.wait4(child.pid, 0)
    stderr = child.stderr.read().decode("utf-8", errors="replace")
    child.returncode = os.waitstatus_to_exitcode(status)
    after = events()
    return {"repetition": repetition, "pid": pid, "exit": child.returncode,
            "wall_ms": round((time.perf_counter_ns() - start) / 1_000_000, 3),
            "cpu_ms": round((usage.ru_utime + usage.ru_stime) * 1000, 3),
            "peak_rss_mib": round(usage.ru_maxrss / 1024, 3),
            "output_bytes": output_bytes, "stderr": stderr[:4096],
            "state_created": Path("/tmp/implicit-state").exists(),
            "cgroup_memory_events_delta": {key: after.get(key, 0) - before.get(key, 0)
                                           for key in after.keys() | before.keys()},
            "closed_consumer": closed, "reader_delay_ms_per_64k": delay * 1000}


def percentile(values: list[float], fraction: float) -> float:
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    index = (len(values) - 1) * fraction
    lower = int(index)
    return round(values[lower] + (values[min(lower + 1, len(values) - 1)] - values[lower]) *
                 (index - lower), 3)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=int, default=100_000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--reader-delay-ms", type=float, default=0.0)
    parser.add_argument("--closed", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.packages <= 100_000 or not 1 <= args.repetitions <= 3 or not 0 <= args.reader_delay_ms <= 10:
        parser.error("trial arguments outside bounded local fixture")
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    with STATUS.open("w", encoding="utf-8") as stream:
        for number in range(args.packages):
            stream.write(f"Package: package{number:06d}\nStatus: install ok installed\n"
                         f"Architecture: amd64\nVersion: 1:{number}.0-1\n\n")
    rows = [trial(i, args.reader_delay_ms / 1000, args.closed)
            for i in range(1, args.repetitions + 1)]
    walls = [row["wall_ms"] for row in rows]
    report = {"at_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version.split()[0],
              "packages": args.packages, "input_bytes": STATUS.stat().st_size,
              "planned": args.repetitions, "attempted": len(rows),
              "completed": sum(row["exit"] is not None for row in rows),
              "p50_wall_ms": percentile(walls, .5), "p95_wall_ms": percentile(walls, .95),
              "p99_wall_ms": percentile(walls, .99), "max_wall_ms": max(walls), "trials": rows}
    print(json.dumps(report, sort_keys=True))
    expected = 2 if args.closed else 0
    if any(row["exit"] != expected or row["state_created"] or
           row["cgroup_memory_events_delta"].get("oom_kill", 0) for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
