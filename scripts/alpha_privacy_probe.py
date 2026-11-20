"""Bounded source-CLI privacy/resource diagnostic in a disposable Linux container.

This is not an installed-console release test. Run only with an offline cached
image, read-only root, no network/capabilities, and disposable tmpfs mounts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time


STATUS = Path("/var/lib/dpkg/status")
OUTPUT = Path("/tmp/alpha-privacy-output.json")
ERROR = Path("/tmp/alpha-privacy-error.txt")
EVENTS = Path("/sys/fs/cgroup/memory.events")
WATCH = (Path("/tmp"), Path("/var/lib/dpkg"), Path("/dev/shm"))


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def tree(root: Path) -> dict[str, tuple[int, int, int, str | None]]:
    result = {}
    for path in root.rglob("*"):
        if path in {OUTPUT, ERROR}:
            continue
        info = path.lstat()
        result[str(path)] = (info.st_mode, info.st_size, info.st_mtime_ns,
                             digest(path) if stat.S_ISREG(info.st_mode) else None)
    return result


def events() -> dict[str, int]:
    if not EVENTS.is_file():
        return {}
    return {name: int(value) for name, value in
            (line.split() for line in EVENTS.read_text().splitlines())}


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    return round(ordered[lower] +
                 (ordered[min(lower + 1, len(ordered) - 1)] - ordered[lower]) *
                 (position - lower), 3)


def make_status(rows: int) -> None:
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    with STATUS.open("w", encoding="utf-8") as stream:
        for number in range(rows):
            stream.write(f"Package: package{number:06d}\n"
                         "Status: install ok installed\nArchitecture: amd64\n"
                         f"Version: 1:{number}.0-1\n\n")


def verify_output(rows: int) -> tuple[bool, str | None]:
    if OUTPUT.stat().st_size > 64 * 1024 * 1024:
        return False, "JSON exceeds 64 MiB"
    try:
        with OUTPUT.open(encoding="utf-8") as stream:
            body = json.load(stream)
    except (OSError, ValueError) as exc:
        return False, f"invalid JSON: {type(exc).__name__}"
    if (body.get("schema_version"), body.get("package_count"),
        body.get("inventory_complete"), body.get("asset_id"),
        body.get("identity_scope")) != ("inventory-v2", rows, True, None, "none"):
        return False, "inventory envelope changed"
    packages = body.get("packages")
    if not isinstance(packages, list) or len(packages) != rows:
        return False, "package count changed"
    for index, package in enumerate(packages):
        name = f"package{index:06d}"
        if (package.get("name"), package.get("version"),
            package.get("architecture"), package.get("purl")) != (
                name, f"1:{index}.0-1", "amd64", f"pkg:deb/debian/{name}"):
            return False, f"package identity changed at row {index}"
    return True, None


def one_trial(rows: int, repetition: int, input_sha256: str) -> dict:
    OUTPUT.write_bytes(b"")
    ERROR.write_bytes(b"")
    before = {str(root): tree(root) for root in WATCH}
    before_events = events()
    environment = os.environ | {"PYTHONDONTWRITEBYTECODE": "1",
                                "XDG_STATE_HOME": "/tmp/alpha-implicit-state",
                                "HOME": "/tmp/alpha-home"}
    started = time.perf_counter_ns()
    with OUTPUT.open("wb") as stdout, ERROR.open("wb") as stderr:
        process = subprocess.Popen([sys.executable, "-m", "aegis.cli", "inventory", "--json"],
                                   stdout=stdout, stderr=stderr, env=environment)
        deadline = started + 10_000_000_000
        timed_out = False
        while True:
            completed_pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if completed_pid == process.pid:
                break
            if time.perf_counter_ns() >= deadline:
                timed_out = True
                process.send_signal(signal.SIGKILL)
                _, status, usage = os.wait4(process.pid, 0)
                break
            time.sleep(0.005)
    wall_ms = (time.perf_counter_ns() - started) / 1_000_000
    exit_code = os.waitstatus_to_exitcode(status)
    process.returncode = exit_code
    after_events = events()
    after = {str(root): tree(root) for root in WATCH}
    exact, output_error = verify_output(rows) if exit_code == 0 else (False, "CLI exited nonzero")
    cpu_ms = (usage.ru_utime + usage.ru_stime) * 1000
    rss_mib = usage.ru_maxrss / 1024
    oom_kills = after_events.get("oom_kill", 0) - before_events.get("oom_kill", 0)
    result = {"repetition": repetition, "exit_code": exit_code,
              "timed_out": timed_out, "wall_ms": round(wall_ms, 3),
              "cpu_ms": round(cpu_ms, 3), "peak_rss_mib": round(rss_mib, 3),
              "json_bytes": OUTPUT.stat().st_size, "json_sha256": digest(OUTPUT),
              "input_unchanged": digest(STATUS) == input_sha256,
              "writable_trees_unchanged": before == after,
              "implicit_state_absent": not Path(environment["XDG_STATE_HOME"]).exists(),
              "stderr_bytes": ERROR.stat().st_size,
              "stderr_excerpt": ERROR.read_text(errors="replace")[:512],
              "cgroup_oom_kill_delta": oom_kills,
              "all_rows_exact": exact, "output_error": output_error}
    result["pass"] = (exit_code == 0 and not timed_out and wall_ms <= 5000 and
                      cpu_ms <= 5000 and rss_mib <= 256 and oom_kills == 0 and
                      result["stderr_bytes"] == 0 and result["input_unchanged"] and
                      result["writable_trees_unchanged"] and result["implicit_state_absent"] and exact)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, choices=(100, 10_000, 100_000), required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run as an unprivileged disposable container user")
    make_status(args.rows)
    input_sha256 = digest(STATUS)
    trials = [one_trial(args.rows, repetition, input_sha256)
              for repetition in range(1, 4)]
    OUTPUT.unlink(missing_ok=True)
    ERROR.unlink(missing_ok=True)
    walls = [item["wall_ms"] for item in trials]
    report = {"scope": "cached-Kali-source-only-diagnostic", "rows": args.rows,
              "python": sys.version.split()[0], "uid": os.geteuid(),
              "input_sha256": input_sha256, "planned": 3, "attempted": 3,
              "passed": sum(item["pass"] for item in trials),
              "failed": sum(not item["pass"] for item in trials),
              "p50_wall_ms": percentile(walls, .5),
              "p95_wall_ms": percentile(walls, .95),
              "p99_wall_ms": percentile(walls, .99),
              "max_wall_ms": max(walls), "trials": trials}
    print(json.dumps(report, sort_keys=True))
    if report["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
