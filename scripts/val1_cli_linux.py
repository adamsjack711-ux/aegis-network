"""Offline, non-root installed-console resource and no-write probe in disposable Linux.

Run inside a networkless, read-only-root container with tmpfs /tmp and /var/lib/dpkg.
The caller records the exact image ID, source pin, wheel hash and Docker command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root: Path) -> dict[str, tuple[int, str]]:
    return {str(path.relative_to(root)): (path.stat().st_mode & 0o7777, digest(path))
            for path in root.rglob("*") if path.is_file()}


def memory_events() -> dict[str, int]:
    path = Path("/sys/fs/cgroup/memory.events")
    return {name: int(value) for name, value in (line.split() for line in path.read_text().splitlines())} if path.exists() else {}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--rows", type=int, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.rows not in {100, 10_000, 100_000} or not 1 <= args.repetitions <= 3:
        parser.error("bounded fixture only")
    if os.geteuid() == 0 or not Path("/var/lib/dpkg/status").parent.is_dir():
        parser.error("requires non-root and a disposable dpkg tmpfs")
    venv = Path("/tmp/val1-venv")
    subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)], check=True)
    python, pip, console = (venv / "bin" / name for name in ("python", "pip", "aegis"))
    install = subprocess.run([str(python), "-m", "pip", "install", "--no-index", "--no-deps",
                              "--no-compile", "--force-reinstall", str(args.wheel)],
                             capture_output=True, text=True, timeout=30)
    if install.returncode or not console.is_file():
        raise SystemExit(json.dumps({"install_exit": install.returncode, "stdout": install.stdout,
                                     "stderr": install.stderr, "console_exists": console.is_file()}))
    status = Path("/var/lib/dpkg/status")
    with status.open("w") as stream:
        for n in range(args.rows):
            stream.write(f"Package: package{n:06d}\nStatus: install ok installed\n"
                         f"Architecture: amd64\nVersion: 1:{n}.0-1\n\n")
    home, xdg = Path("/tmp/val1-home"), Path("/tmp/val1-xdg")
    home.mkdir(); xdg.mkdir()
    env = {"PATH": str(venv / "bin") + ":/usr/bin:/bin", "HOME": str(home),
           "XDG_STATE_HOME": str(xdg), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    before = {"tmp": snapshot(Path("/tmp")), "dpkg": snapshot(status.parent)}
    trials = []
    for repetition in range(1, args.repetitions + 1):
        usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        events_before = memory_events()
        start = time.perf_counter_ns()
        child = subprocess.Popen([str(console), "inventory", "--json"], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output_hash = hashlib.sha256()
        output_bytes = 0
        package_count = 0
        tail = b""
        marker = b'"purl": '
        while chunk := child.stdout.read(65536):
            output_hash.update(chunk)
            output_bytes += len(chunk)
            segment = tail + chunk
            package_count += segment.count(marker)
            tail = segment[-(len(marker) - 1):]
        err = child.stderr.read()
        child.wait(timeout=20)
        usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        events_after = memory_events()
        # Streaming keeps the validator process outside the child's memory
        # envelope. A separate cgroup/RSS observer remains mandatory.
        trials.append({"repetition": repetition, "exit": child.returncode,
                       "wall_ms": round((time.perf_counter_ns() - start) / 1e6, 3),
                       "output_bytes": output_bytes, "output_sha256": output_hash.hexdigest(),
                       "package_count": package_count, "stderr": err.decode(errors="replace")[:1024],
                       "cpu_ms": round(((usage_after.ru_utime + usage_after.ru_stime) -
                                        (usage_before.ru_utime + usage_before.ru_stime)) * 1000, 3),
                       "max_child_rss_upper_bound_mib": round(usage_after.ru_maxrss / 1024, 3),
                       "memory_events_delta": {key: events_after.get(key, 0) - events_before.get(key, 0)
                                               for key in events_after.keys() | events_before.keys()},
                       "filesystem_after": {"tmp": snapshot(Path("/tmp")), "dpkg": snapshot(status.parent)}})
    uninstall = subprocess.run([str(python), "-m", "pip", "uninstall", "-y", "aegis-network"],
                               capture_output=True, text=True, timeout=30)
    report = {"wheel_sha256": digest(args.wheel), "python": sys.version.split()[0],
              "uid": os.geteuid(), "rows": args.rows, "status_bytes": status.stat().st_size,
              "planned": args.repetitions, "attempted": len(trials), "before": before, "trials": trials,
              "uninstall_exit": uninstall.returncode, "console_removed": not console.exists(),
              "limits": "max_child_rss is an upper bound across setup and trials; attempted syscalls require a tracer"}
    print(json.dumps(report, sort_keys=True))
    if any(t["exit"] != 0 or t["package_count"] != args.rows or t["filesystem_after"] != before
           or t["memory_events_delta"].get("oom_kill", 0) for t in trials) or uninstall.returncode or console.exists():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
