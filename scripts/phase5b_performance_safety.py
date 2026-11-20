"""Frozen offline Linux CLI resource and output-integrity probe.

Run as a non-root user with a read-only root, disabled network, and disposable
/tmp and /var/lib/dpkg tmpfs mounts. The harness writes the input and captures
stdout; its own files are excluded from the CLI filesystem comparison.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from time import perf_counter_ns


STATUS = Path("/var/lib/dpkg/status")
TMP = Path("/tmp")
EVENTS = Path("/sys/fs/cgroup/memory.events")


def file_digest(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def memory_events() -> dict[str, int]:
    if not EVENTS.exists():
        return {}
    return {key: int(value) for key, value in
            (line.split() for line in EVENTS.read_text().splitlines())}


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    low = int(index)
    return round(ordered[low] + (ordered[min(low + 1, len(ordered) - 1)] - ordered[low]) * (index - low), 3)


def tree(root: Path, excluded: set[Path]) -> dict[str, tuple[int, int, str | None]]:
    result = {}
    for path in root.rglob("*"):
        if path in excluded:
            continue
        info = path.lstat()
        digest = file_digest(path) if stat.S_ISREG(info.st_mode) else None
        result[str(path.relative_to(root))] = (info.st_mode, info.st_size, digest)
    return result


def verify_inventory(path: Path, rows: int) -> dict[str, object]:
    with path.open(encoding="utf-8") as stream:
        body = json.load(stream)
    packages = body.get("packages", [])
    errors = []
    if (body.get("schema_version"), body.get("package_count"), body.get("inventory_complete")) != (
        "inventory-v2", rows, True
    ):
        errors.append("inventory envelope or count mismatch")
    if body.get("asset_id") is not None or body.get("identity_scope") != "none":
        errors.append("unexpected persistent identity")
    if len(packages) != rows:
        errors.append("output row count mismatch")
    for index, package in enumerate(packages):
        expected_name = f"package{index:06d}"
        if (package.get("name"), package.get("version"), package.get("architecture"),
            package.get("purl")) != (expected_name, f"1:{index}.0-1", "amd64",
                                     f"pkg:deb/debian/{expected_name}"):
            errors.append(f"output row {index} mismatch")
            break
    return {"output_rows": len(packages), "all_rows_exact": not errors, "errors": errors}


def child(argv: list[str], output: Path, environment: dict[str, str]) -> dict[str, object]:
    with output.open("wb") as stream:
        start = perf_counter_ns()
        process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.PIPE, env=environment)
        pid, status, usage = os.wait4(process.pid, 0)
        elapsed = (perf_counter_ns() - start) / 1_000_000
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        process.returncode = os.waitstatus_to_exitcode(status)
    return {"pid": pid, "exit_code": process.returncode, "wall_ms": round(elapsed, 3),
            "cpu_ms": round((usage.ru_utime + usage.ru_stime) * 1000, 3),
            "peak_rss_mib": round(usage.ru_maxrss / 1024, 3), "stderr": stderr[:4096],
            "output_bytes": output.stat().st_size,
            "output_sha256": file_digest(output)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--verify-output", type=Path)
    args = parser.parse_args()
    if args.verify_output is not None:
        print(json.dumps(verify_inventory(args.verify_output, args.rows), sort_keys=True))
        return
    if os.geteuid() == 0 or args.rows not in (100, 10_000, 100_000) or args.repetitions != 3:
        parser.error("requires non-root and three runs at a frozen row count")
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    with STATUS.open("w", encoding="utf-8") as stream:
        for index in range(args.rows):
            stream.write(f"Package: package{index:06d}\nStatus: install ok installed\n"
                         f"Architecture: amd64\nVersion: 1:{index}.0-1\n\n")
    input_digest = file_digest(STATUS)
    environment = os.environ | {"PYTHONDONTWRITEBYTECODE": "1", "XDG_STATE_HOME": "/tmp/implicit-aegis"}
    argv = [sys.executable, "-m", "aegis.cli", "inventory", "--json"]
    output = TMP / "aegis-harness-output.json"
    runs = []
    for repetition in range(1, 4):
        output.touch()
        excluded = {output}
        before = {str(root): tree(root, excluded) for root in (TMP, STATUS.parent)}
        before_events = memory_events()
        result = child(argv, output, environment)
        after_events = memory_events()
        after = {str(root): tree(root, excluded) for root in (TMP, STATUS.parent)}
        result.update(repetition=repetition,
                      cgroup_memory_events_delta={key: after_events.get(key, 0) - before_events.get(key, 0)
                                                  for key in before_events.keys() | after_events.keys()},
                      input_unchanged=file_digest(STATUS) == input_digest,
                      writable_trees_unchanged=before == after,
                      implicit_state_absent=not Path(environment["XDG_STATE_HOME"]).exists())
        if result["exit_code"] == 0:
            verification = subprocess.run([sys.executable, __file__, "--rows", str(args.rows),
                                           "--verify-output", str(output)],
                                          text=True, capture_output=True, check=True)
            result.update(json.loads(verification.stdout))
        runs.append(result)
        output.unlink()
    startup = []
    for repetition in range(3):
        startup_output = TMP / "aegis-harness-startup.txt"
        run = child([sys.executable, "-m", "aegis.cli", "--help"], startup_output, environment)
        startup.append({"repetition": repetition + 1, "exit_code": run["exit_code"],
                        "wall_ms": run["wall_ms"], "cpu_ms": run["cpu_ms"],
                        "peak_rss_mib": run["peak_rss_mib"]})
        startup_output.unlink()
    walls = [item["wall_ms"] for item in runs]
    result = {"at_utc": datetime.now(timezone.utc).isoformat(), "platform": sys.platform,
              "python": sys.version.split()[0], "uid": os.geteuid(), "rows": args.rows,
              "input_bytes": STATUS.stat().st_size, "input_sha256": input_digest,
              "attempted": 3, "completed": sum(item["exit_code"] == 0 for item in runs),
              "p50_wall_ms": percentile(walls, .5), "p95_wall_ms": percentile(walls, .95),
              "p99_wall_ms": percentile(walls, .99), "max_wall_ms": max(walls),
              "startup_help_p50_ms": percentile([item["wall_ms"] for item in startup], .5),
              "startup_help_p95_ms": percentile([item["wall_ms"] for item in startup], .95),
              "startup": startup, "runs": runs}
    print(json.dumps(result, sort_keys=True))
    if any(item["exit_code"] != 0 or not item.get("all_rows_exact") or
           not item["input_unchanged"] or not item["writable_trees_unchanged"] or
           not item["implicit_state_absent"] for item in runs):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
