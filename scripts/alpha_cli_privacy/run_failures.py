"""Measure three conservative inventory failure paths under the frozen cap."""

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "benchmarks/alpha-cli-privacy"


def main() -> None:
    inputs = EVIDENCE / "inputs"
    raw = EVIDENCE / "raw"
    oversized = inputs / "status-oversized-line"
    oversized.write_bytes(b"Package: " + b"a" * 16_385 + b"\n")
    cases = {
        "truncated": ROOT / "fixtures/phase-next-cli/dpkg-truncated",
        "duplicate": ROOT / "fixtures/phase-next-cli/dpkg-duplicate",
        "oversized-line": oversized,
    }
    results = []
    for name, status in cases.items():
        command = [
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--user", "1000:1000", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", "512m", "--cpus", "1",
            "-v", f"{ROOT}:/src:ro", "-v", f"{status}:/var/lib/dpkg/status:ro",
            "aegis-alpha-cli-privacy:local", "/usr/bin/time", "-v",
            "python", "-m", "aegis.cli", "inventory", "--json",
        ]
        result = subprocess.run(command, capture_output=True, timeout=20)
        body = json.loads(result.stdout)
        (raw / f"failure-{name}.stdout").write_bytes(result.stdout)
        (raw / f"failure-{name}.stderr").write_bytes(result.stderr)
        (raw / f"failure-{name}.exit").write_text(f"{result.returncode}\n")
        row = {"case": name, "exit_code": result.returncode,
               "inventory_complete": body.get("inventory_complete"),
               "package_count": body.get("package_count"),
               "reason": body.get("inventory_reason"),
               "stdout_bytes": len(result.stdout)}
        results.append(row)
        print(json.dumps(row), flush=True)
    (EVIDENCE / "failure-results.json").write_text(json.dumps({"attempted": 3, "runs": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
