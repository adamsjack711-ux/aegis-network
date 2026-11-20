"""Three bounded malformed-input source CLI trials in a disposable Linux lab."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time


STATUS = Path("/var/lib/dpkg/status")
ROOT = Path("/tmp/aegis-5b-r-negatives")


def tree(root: Path) -> dict[str, tuple]:
    result = {}
    for path in root.rglob("*"):
        meta = path.lstat()
        content = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(meta.st_mode) else None
        result[str(path.relative_to(root))] = (meta.st_mode, meta.st_size, meta.st_mtime_ns, content)
    return result


def run(name: str, arguments: list[str]) -> dict:
    before = {"tmp": tree(Path("/tmp")), "dpkg": tree(STATUS.parent)}
    env = os.environ | {"PYTHONDONTWRITEBYTECODE": "1", "XDG_STATE_HOME": str(ROOT / "implicit-state")}
    started = time.perf_counter_ns()
    child = subprocess.Popen([sys.executable, "-m", "aegis.cli", *arguments], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = child.stdout.read()
    pid, status, usage = os.wait4(child.pid, 0)
    child.returncode = os.waitstatus_to_exitcode(status)
    stderr = child.stderr.read()
    wall_ms = (time.perf_counter_ns() - started) / 1_000_000
    after = {"tmp": tree(Path("/tmp")), "dpkg": tree(STATUS.parent)}
    body = json.loads(stdout)
    return {"name": name, "pid": pid, "exit": child.returncode, "wall_ms": round(wall_ms, 3),
            "cpu_ms": round((usage.ru_utime + usage.ru_stime) * 1000, 3),
            "peak_rss_mib": round(usage.ru_maxrss / 1024, 3),
            "stdout_bytes": len(stdout), "stderr": stderr.decode(errors="replace")[:4096],
            "status": body.get("status"), "independent_status": body.get("independent_status"),
            "schema_version": body.get("schema_version"),
            "changed": {key: sorted(path for path in before[key].keys() | after[key].keys()
                                   if before[key].get(path) != after[key].get(path))
                        for key in before},
            "implicit_state_created": (ROOT / "implicit-state").exists()}


def main() -> None:
    ROOT.mkdir(mode=0o700, exist_ok=True)
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    valid = "Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:8.0-1\n\n"
    STATUS.write_text(valid)
    malformed = ROOT / "malformed.json"
    malformed.write_text("{broken")
    oversized = ROOT / "oversized.json"
    oversized.write_bytes(b" " * (8 * 1024 * 1024 + 1))
    results = [run("malformed_feed", ["findings", "--feed", str(malformed), "--json"]),
               run("oversized_feed", ["findings", "--feed", str(oversized), "--json"])]
    STATUS.write_text(valid * 2)
    results.append(run("duplicate_inventory", ["inventory", "--json"]))
    print(json.dumps({"at_utc": datetime.now(timezone.utc).isoformat(),
                      "planned": 3, "attempted": len(results), "cases": results}, sort_keys=True))
    if any(row["exit"] != 2 or row["stderr"] or row["changed"]["tmp"] or
           row["changed"]["dpkg"] or row["implicit_state_created"] or
           row["wall_ms"] > 2000 or row["peak_rss_mib"] > 128 or
           row["stdout_bytes"] > 4096 for row in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
