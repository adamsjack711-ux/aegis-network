"""Run fresh, restricted Linux CLI resource trials and retain raw evidence."""

import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time

from workload import generate, verify

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "benchmarks/alpha-cli-privacy"
IMAGE = "aegis-alpha-cli-privacy:local"


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def metric(stderr: str, label: str) -> str | None:
    match = re.search(r"^\s*" + re.escape(label) + r":\s*(.+)$", stderr, re.M)
    return match.group(1) if match else None


def run(rows: int, memory_mib: int, trial: int) -> dict:
    inputs = EVIDENCE / "inputs"
    raw = EVIDENCE / "raw"
    inputs.mkdir(parents=True, exist_ok=True)
    raw.mkdir(parents=True, exist_ok=True)
    status = inputs / f"status-{rows}"
    generate(status, rows)
    stem = f"inventory-{rows}-{memory_mib}m-{trial}"
    output = raw / f"{stem}.json"
    command = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--user", "1000:1000", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--memory", f"{memory_mib}m",
        "--cpus", "1", "-v", f"{ROOT}:/src:ro",
        "-v", f"{status}:/var/lib/dpkg/status:ro", IMAGE,
        "sh", "-c", "printf 'CGROUP_BEFORE\\n' >&2; cat /sys/fs/cgroup/memory.events >&2; "
        "/usr/bin/time -v python -m aegis.cli inventory --json; "
        "code=$?; printf 'CGROUP_AFTER\\n' >&2; cat /sys/fs/cgroup/memory.events >&2; exit $code",
    ]
    start = time.perf_counter()
    with output.open("wb") as stream:
        try:
            process = subprocess.run(command, stdout=stream, stderr=subprocess.PIPE, timeout=30)
            exit_code = process.returncode
            stderr = process.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            exit_code = None
            stderr = f"TIMEOUT {exc}\n"
    (raw / f"{stem}.stderr").write_text(stderr)
    (raw / f"{stem}.exit").write_text(f"{exit_code}\n")
    result = {
        "rows": rows, "memory_limit_mib": memory_mib, "trial": trial,
        "exit_code": exit_code, "controller_wall_s": round(time.perf_counter() - start, 3),
        "cpu_user_s": metric(stderr, "User time (seconds)"),
        "cpu_system_s": metric(stderr, "System time (seconds)"),
        "elapsed": metric(stderr, "Elapsed (wall clock) time (h:mm:ss or m:ss)"),
        "peak_rss_kib": metric(stderr, "Maximum resident set size (kbytes)"),
        "input_sha256": hashlib.sha256(status.read_bytes()).hexdigest(),
        "stderr_file": f"raw/{stem}.stderr",
    }
    if exit_code == 0:
        result["verification"] = verify(output, rows)
    else:
        result["verification"] = None
    if output.exists():
        with output.open("rb") as source, gzip.open(str(output) + ".gz", "wb", compresslevel=6) as dest:
            while block := source.read(1024 * 1024):
                dest.write(block)
        output.unlink()
    return result


def main() -> None:
    results = []
    for rows, memory in [(100, 512), (10_000, 512), (100_000, 512), (100_000, 256)]:
        for trial in range(1, 4):
            result = run(rows, memory, trial)
            results.append(result)
            print(json.dumps(result), flush=True)
    groups = {}
    for rows, memory in [(100, 512), (10_000, 512), (100_000, 512), (100_000, 256)]:
        selected = [r for r in results if (r["rows"], r["memory_limit_mib"]) == (rows, memory)]
        elapsed = []
        for row in selected:
            value = row["elapsed"]
            if value:
                parts = value.split(":")
                elapsed.append(sum(float(item) * 60 ** index for index, item in enumerate(reversed(parts))))
        groups[f"{rows}-{memory}m"] = {
            "attempted": len(selected), "completed": sum(r["exit_code"] == 0 for r in selected),
            "failed": sum(r["exit_code"] not in (0, None) for r in selected),
            "censored": sum(r["exit_code"] is None for r in selected),
            "wall_s_p50": percentile(elapsed, 0.5), "wall_s_p95": percentile(elapsed, 0.95),
            "wall_s_max": max(elapsed) if elapsed else None,
            "peak_rss_kib_max": max((int(r["peak_rss_kib"]) for r in selected if r["peak_rss_kib"]), default=None),
        }
    (EVIDENCE / "resource-results.json").write_text(json.dumps({"runs": results, "groups": groups}, indent=2) + "\n")


if __name__ == "__main__":
    main()
