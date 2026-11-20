"""Run frozen installed-console resource children inside one disposable cell.

This file is mounted read-only. It never imports the Aegis source checkout.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import threading
import time


ROOT = Path("/results")
STATUS = Path("/var/lib/dpkg/status")
FEED = Path("/tmp/resource-negative-feed.json")
CONSOLE = Path("/tmp/venv/bin/aegis")
EVENTS = Path("/sys/fs/cgroup/memory.events")
SIZES = (100, 10_000, 100_000)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def events() -> dict[str, int]:
    if not EVENTS.exists():
        raise RuntimeError("cgroup memory.events unavailable")
    return {part[0]: int(part[1]) for line in EVENTS.read_text().splitlines()
            if len(part := line.split()) == 2}


def snapshot() -> dict[str, tuple[int, int, str | None]]:
    """Observe writable trees except the fixed installed venv and named output sink."""
    result = {}
    for root in (Path("/tmp"), Path("/var/lib/dpkg"), Path("/dev/shm")):
        for path in root.rglob("*"):
            if root == Path("/tmp") and (path == Path("/tmp/venv") or
                                          Path("/tmp/venv") in path.parents):
                continue
            metadata = path.lstat()
            result[str(path)] = (metadata.st_mode, metadata.st_size,
                                 digest(path) if stat.S_ISREG(metadata.st_mode) else None)
    return result


def fixture(rows: int | str) -> str:
    if isinstance(rows, int):
        with gzip.open(f"/fixtures/status-{rows}.gz", "rb") as source, STATUS.open("wb") as dest:
            while data := source.read(1 << 20):
                dest.write(data)
        FEED.unlink(missing_ok=True)
    elif rows == "duplicate-inventory":
        STATUS.write_text("Package: duplicate\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n"
                          "Package: duplicate\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2\n\n")
        FEED.unlink(missing_ok=True)
    elif rows in {"malformed-feed", "oversized-feed"}:
        with gzip.open("/fixtures/status-100.gz", "rb") as source, STATUS.open("wb") as dest:
            dest.write(source.read())
        FEED.write_bytes(b"{" if rows == "malformed-feed" else b"x" * (8 * 1024 * 1024 + 1))
    else:
        raise ValueError(rows)
    return digest(STATUS)


def verify_inventory(path: Path, rows: int, distro: str) -> tuple[bool, str | None]:
    if path.stat().st_size > 64 * 1024 * 1024:
        return False, "JSON exceeds 64 MiB"
    try:
        with path.open(encoding="utf-8") as stream:
            body = json.load(stream)
    except (OSError, UnicodeError, ValueError) as exc:
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
                package.get("architecture"), package.get("purl"),
                package.get("source")) != (
                name, f"1:{index}.0-1", "amd64", f"pkg:deb/{distro}/{name}", "dpkg-status"):
            return False, f"package identity changed at row {index}"
    return True, None


def wait_child(process: subprocess.Popen, deadline: float) -> tuple[int, resource.struct_rusage, bool]:
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid == process.pid:
            code = os.waitstatus_to_exitcode(status)
            process.returncode = code
            return code, usage, False
        if time.monotonic() >= deadline:
            process.send_signal(signal.SIGKILL)
            _, status, usage = os.wait4(process.pid, 0)
            code = os.waitstatus_to_exitcode(status)
            process.returncode = code
            return code, usage, True
        time.sleep(.005)


def run_one(label: str, rows: int | str, distro: str, mode: str) -> dict:
    input_sha = fixture(rows)
    feed_sha = digest(FEED) if FEED.exists() else None
    before, before_events = snapshot(), events()
    output = ROOT / f"{label}.stdout"
    error = ROOT / f"{label}.stderr"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.update(PYTHONDONTWRITEBYTECODE="1", HOME="/tmp", XDG_STATE_HOME="/tmp/implicit-state")
    started = time.monotonic()
    reader = None
    argv = [str(CONSOLE), "inventory", "--json"] if rows not in {
        "malformed-feed", "oversized-feed"} else [str(CONSOLE), "status", "--json", "--feed", str(FEED)]
    if mode == "slow" or mode == "closed":
        with error.open("wb") as err:
            process = subprocess.Popen(argv,
                                       stdout=subprocess.PIPE, stderr=err, env=env)
            assert process.stdout is not None
            if mode == "closed":
                # Preserve the exact bytes the consumer saw before closing.
                # A zero-length output file would misleadingly imply no read.
                with output.open("wb") as out:
                    out.write(process.stdout.read(4096))
                process.stdout.close()
            else:
                def consume() -> None:
                    with output.open("wb") as out:
                        while chunk := process.stdout.read(65536):
                            out.write(chunk)
                            time.sleep(.001)
                    process.stdout.close()
                reader = threading.Thread(target=consume, daemon=True)
                reader.start()
            code, usage, timed_out = wait_child(process, started + 10)
            if reader:
                reader.join(timeout=2)
    else:
        with output.open("wb") as out, error.open("wb") as err:
            process = subprocess.Popen(argv,
                                       stdout=out, stderr=err, env=env)
            code, usage, timed_out = wait_child(process, started + 10)
    wall = time.monotonic() - started
    after_events = events()
    after = snapshot()
    exact, reason = (verify_inventory(output, rows, distro) if isinstance(rows, int) and
                     code == 0 and output.exists() else (False, "not a successful inventory"))
    stdout_size = output.stat().st_size if output.exists() else 0
    stdout_sha = digest(output) if output.exists() else None
    stderr_text = error.read_text(errors="replace")
    record = {"id": label, "mode": mode, "rows": rows, "exit_code": code,
              "timed_out": timed_out, "wall_seconds": round(wall, 6),
              "cpu_seconds": round(usage.ru_utime + usage.ru_stime, 6),
              "peak_rss_mib": round(usage.ru_maxrss / 1024, 3),
              "stdout_bytes": stdout_size, "stdout_sha256": stdout_sha,
              "stderr_bytes": error.stat().st_size, "stderr_excerpt": stderr_text[:512],
              "input_sha256": input_sha, "input_unchanged": digest(STATUS) == input_sha,
              "feed_sha256": feed_sha,
              "feed_unchanged": feed_sha is None or digest(FEED) == feed_sha,
              "writable_trees_unchanged": before == after,
              "implicit_state_absent": not Path("/tmp/implicit-state").exists(),
              "cgroup_oom_kill_delta": after_events.get("oom_kill", 0) - before_events.get("oom_kill", 0),
              "all_rows_exact": exact, "identity_error": reason}
    if mode == "closed":
        record["closed_consumer_bytes_read"] = stdout_size
        record["closed_consumer_sha256"] = stdout_sha
    if isinstance(rows, int):
        record["pass"] = (code == 0 and not timed_out and exact and
                          record["peak_rss_mib"] <= 256 and stdout_size <= 64 * 1024 * 1024 and
                          record["cgroup_oom_kill_delta"] == 0 and record["input_unchanged"] and
                          record["writable_trees_unchanged"] and record["implicit_state_absent"] and
                          not stderr_text and (mode == "slow" or wall <= 5) and
                          record["cpu_seconds"] <= 5)
    else:
        try:
            body = json.loads(output.read_text())
            conservative = (body.get("inventory_complete") is False and body.get("package_count") == 0
                            if rows == "duplicate-inventory" else
                            body.get("schema_version") == "observation-error-v2" and
                            body.get("status") == body.get("independent_status") == "unknown")
        except (OSError, ValueError):
            conservative = False
        record["conservative_failure"] = conservative
        record["pass"] = (code == 2 and conservative and wall <= 2 and
                          record["peak_rss_mib"] <= 128 and stdout_size <= 1 << 20 and
                          "Traceback" not in stderr_text and record["cgroup_oom_kill_delta"] == 0 and
                          record["input_unchanged"] and record["feed_unchanged"] and
                          record["writable_trees_unchanged"] and
                          record["implicit_state_absent"])
    if mode == "closed":
        record["pass"] = (not timed_out and wall <= 10 and record["peak_rss_mib"] <= 256 and
                          record["cgroup_oom_kill_delta"] == 0 and record["input_unchanged"] and
                          record["writable_trees_unchanged"] and record["implicit_state_absent"] and
                          len(stderr_text) <= 4096 and "Traceback" not in stderr_text)
    if output.exists():
        with output.open("rb") as source, gzip.open(str(output) + ".gz", "wb", compresslevel=1) as dest:
            while block := source.read(1 << 20):
                dest.write(block)
        output.unlink()
    (ROOT / f"{label}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def main() -> int:
    distro = sys.argv[1]
    budget = int(sys.argv[2])
    selected = sys.argv[3] if len(sys.argv) > 3 else "all"
    assert os.getuid() == 65534 and distro in {"debian", "ubuntu"} and budget in {256, 512}
    assert selected in {"all", "closed-only"}
    assert CONSOLE.is_file() and CONSOLE.is_file() and Path("/tmp/venv/pyvenv.cfg").is_file()
    cgroup = {name: Path("/sys/fs/cgroup", name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    assert cgroup["memory.max"] == str(budget * 1024 * 1024), cgroup
    cpu_quota, cpu_period = map(int, cgroup["cpu.max"].split())
    assert cpu_quota <= cpu_period, cgroup
    assert cgroup["memory.swap.max"] == "0", cgroup
    assert int(cgroup["pids.max"]) <= 64, cgroup
    plans = ([(kind, kind, "failure") for kind in ("malformed-feed", "oversized-feed", "duplicate-inventory")] +
             [(f"inventory-{rows}-{i}", rows, "normal") for rows in SIZES for i in range(1, 4)] +
             [("slow-reader", 100_000, "slow"), ("closed-stdout", 100_000, "closed")]) if budget == 512 else [
             (f"hard-256-{i}", 100_000, "hard") for i in range(1, 4)]
    if selected == "closed-only":
        assert budget == 512
        plans = [("closed-stdout", 100_000, "closed")]
    results = []
    for label, rows, mode in plans:
        try:
            results.append(run_one(label, rows, distro, mode))
        except BaseException as exc:
            results.append({"id": label, "rows": rows, "mode": mode, "pass": False,
                            "harness_error": f"{type(exc).__name__}: {exc}"})
    report = {"distro": distro, "memory_limit_mib": budget, "cgroup_readback": cgroup,
              "bytecode_suppressed_for_resource_measurement": True,
              "planned": len(plans),
              "attempted": len(results), "passed": sum(bool(r["pass"]) for r in results),
              "failed": sum(not r["pass"] for r in results), "children": results}
    (ROOT / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("planned", "attempted", "passed", "failed")}))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
