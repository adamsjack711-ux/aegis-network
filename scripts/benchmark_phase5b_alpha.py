"""Measure installed Linux CLI processes with wait4 resource accounting."""

import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time


ENTRY = "/tmp/alpha/bin/aegis"
PYTHON = "/tmp/alpha/bin/python"
COUNT = 10
commands = {
    "startup_help": [PYTHON, ENTRY, "--help"],
    "inventory": [PYTHON, ENTRY, "inventory", "--json"],
    "doctor": [PYTHON, ENTRY, "doctor", "--json"],
}
samples = {}
for name, command in commands.items():
    rows = []
    for _ in range(COUNT):
        start = time.perf_counter_ns()
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _, status, usage = os.wait4(process.pid, 0)
        wall_ms = (time.perf_counter_ns() - start) / 1_000_000
        stderr = process.stderr.read().decode()
        assert os.waitstatus_to_exitcode(status) == 0, stderr
        rows.append({
            "wall_ms": round(wall_ms, 3),
            "cpu_ms": round((usage.ru_utime + usage.ru_stime) * 1000, 3),
            "peak_rss_mib": round(usage.ru_maxrss / 1024, 3),
        })
    samples[name] = {
        "runs": COUNT,
        "median_wall_ms": round(statistics.median(row["wall_ms"] for row in rows), 3),
        "median_cpu_ms": round(statistics.median(row["cpu_ms"] for row in rows), 3),
        "max_peak_rss_mib": max(row["peak_rss_mib"] for row in rows),
        "min_wall_ms": min(row["wall_ms"] for row in rows),
        "max_wall_ms": max(row["wall_ms"] for row in rows),
    }

wheel = next(Path("/wheels").glob("aegis_network-*.whl"))
site = Path("/tmp/alpha/lib/python3.12/site-packages")
installed_bytes = sum(path.stat().st_size for path in (site / "aegis").rglob("*") if path.is_file())
print(json.dumps({
    "schema_version": "phase5b-alpha-benchmark-v1", "distribution": sys.argv[1],
    "python": sys.version.split()[0], "architecture": os.uname().machine,
    "inventory_packages": int(sys.argv[2]), "wheel_bytes": wheel.stat().st_size,
    "installed_package_bytes": installed_bytes, "samples": samples,
}, sort_keys=True))
