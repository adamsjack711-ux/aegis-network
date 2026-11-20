"""Compare baseline and candidate CLI stdout bytes in an offline Linux fixture."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter_ns


def run(source, payload):
    env = os.environ | {"PYTHONPATH": source, "PYTHONDONTWRITEBYTECODE": "1",
                        "XDG_STATE_HOME": "/tmp/implicit-state"}
    started = perf_counter_ns()
    child = subprocess.run([sys.executable, "-c",
                            "import json,sys; from aegis.cli import _emit; "
                            "_emit(json.load(sys.stdin), True, 'inventory')"],
                           env=env, input=payload, capture_output=True, timeout=20)
    return {"source": source, "exit": child.returncode,
            "wall_ms": (perf_counter_ns() - started) / 1_000_000,
            "stdout_bytes": len(child.stdout),
            "stdout_sha256": hashlib.sha256(child.stdout).hexdigest(),
            "stderr": child.stderr.decode(errors="replace")[:1000],
            "state_created": Path("/tmp/implicit-state").exists()}


def main():
    fixture = {"schema_version": "inventory-v2", "captured_at": "2026-11-19T00:00:00Z",
               "independent_status": "unknown", "packages": [
                   {"purl": f"pkg:deb/debian/package{i:06d}", "version": f"1:{i}.0-1"}
                   for i in range(100_000)]}
    payload = json.dumps(fixture, sort_keys=True).encode()
    baseline, candidate = run("/work/baseline", payload), run("/work/candidate", payload)
    result = {"planned": 2, "attempted": 2, "input_bytes": len(payload),
              "python": sys.version.split()[0], "baseline": baseline, "candidate": candidate,
              "byte_equivalent": baseline["stdout_sha256"] == candidate["stdout_sha256"] and
                                 baseline["stdout_bytes"] == candidate["stdout_bytes"]}
    print(json.dumps(result, sort_keys=True))
    if any(x["exit"] != 0 or x["state_created"] for x in (baseline, candidate)) or not result["byte_equivalent"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
