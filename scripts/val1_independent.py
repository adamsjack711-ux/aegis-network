"""VAL-1 offline evidence verification and Diagnostic Runner challenge.

This is a validator-owned, stdlib-only harness. It does not modify candidate source.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_bytes())
    rows = []
    for entry in manifest["files"]:
        file_path = ROOT / entry["path"]
        data = file_path.read_bytes()
        rows.append({"path": entry["path"], "match": len(data) == entry["bytes"] and sha(data) == entry["sha256"]})
    return {"source_commit": manifest["source_commit"], "planned": len(rows),
            "matched": sum(row["match"] for row in rows), "mismatches": [row for row in rows if not row["match"]]}


def request(family: str, objects: dict[str, bytes]) -> bytes:
    return json.dumps({"family": family, "objects": {
        role: base64.b64encode(value).decode("ascii") for role, value in objects.items()
    }}, separators=(",", ":")).encode("ascii")


def runner_probe(worker: Path) -> dict:
    worker = worker.resolve(strict=True)
    worker_bytes = worker.read_bytes()
    family = "feature-gate"
    base = {"subject": b"feature-gate:marker-on",
            "configuration": b"feature-gate:observer-ready",
            "dependencies": b"feature-gate:no-dependencies-v1",
            "recipe": b"feature-gate:marker-model-v1"}
    tests = [
        ("positive_registered", request(family, base), 0, "reproduced"),
        ("negative_registered", request(family, base | {"subject": b"feature-gate:marker-off"}), 0, "not-reproduced"),
        ("unknown_family", request("arbitrary-command", base), 2, None),
        ("unknown_operation", request(family, base | {"recipe": b"feature-gate:run-command"}), 2, None),
        ("command_text", request(family, base | {"subject": b"$(touch val1-command-injection)"}), 2, None),
        ("extra_role", request(family, base | {"command": b"touch val1-command-injection"}), 2, None),
        ("malformed_json", b'{"family":', 2, None),
        ("oversized", b"X" * 2049, 2, None),
    ]
    portability = ROOT / "src/aegis/evidence/_portability_worker.py"
    portable_base = {"subject": b"v1:default:original",
                     "configuration": b"enabled:runtime-a:policy-v1",
                     "dependencies": b"lock-v1", "recipe": b"recipe-v1"}
    portable_tests = [
        ("portability_registered", "harness-v1", request("portability-marker", portable_base), 0, "reproduced"),
        ("portability_unknown_harness", "run-command", request("portability-marker", portable_base), 2, None),
        ("portability_command_text", "harness-v1", request("portability-marker", portable_base |
         {"subject": b"$(touch val1-command-injection)"}), 2, None),
    ]
    rows = []
    with tempfile.TemporaryDirectory(prefix="aegis-val1-runner-") as directory:
        scratch = Path(directory)
        for name, payload, expected_exit, expected_outcome in tests:
            started = time.perf_counter_ns()
            child = subprocess.run([sys.executable, "-I", "-S", str(worker)], input=payload,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=scratch,
                                   env={}, timeout=5, check=False)
            files = sorted(p.name for p in scratch.iterdir())
            output = None
            if child.returncode == 0:
                try:
                    output = json.loads(child.stdout)
                except ValueError:
                    pass
            passed = child.returncode == expected_exit and not files and not child.stderr
            if expected_outcome is not None:
                passed = passed and isinstance(output, dict) and output.get("outcome") == expected_outcome
            else:
                passed = passed and not child.stdout
            rows.append({"case": name, "status": "pass" if passed else "fail",
                         "expected_exit": expected_exit, "actual_exit": child.returncode,
                         "expected_outcome": expected_outcome, "actual_output": output,
                         "stdout_sha256": sha(child.stdout), "stderr": child.stderr.decode(errors="replace")[:1024],
                         "scratch_files": files, "wall_ms": round((time.perf_counter_ns() - started) / 1e6, 3)})
        for name, harness, payload, expected_exit, expected_outcome in portable_tests:
            started = time.perf_counter_ns()
            child = subprocess.run([sys.executable, "-I", "-S", str(portability), str(worker), harness],
                                   input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=scratch, env={}, timeout=5, check=False)
            files = sorted(p.name for p in scratch.iterdir())
            output = json.loads(child.stdout) if child.returncode == 0 else None
            passed = child.returncode == expected_exit and not files and not child.stderr
            passed = passed and ((output or {}).get("outcome") == expected_outcome if expected_outcome
                                 else not child.stdout)
            rows.append({"case": name, "status": "pass" if passed else "fail",
                         "expected_exit": expected_exit, "actual_exit": child.returncode,
                         "expected_outcome": expected_outcome, "actual_output": output,
                         "stdout_sha256": sha(child.stdout), "stderr": child.stderr.decode(errors="replace")[:1024],
                         "scratch_files": files, "wall_ms": round((time.perf_counter_ns() - started) / 1e6, 3)})
    return {"worker": str(worker), "worker_sha256": sha(worker_bytes), "python": sys.version.split()[0],
            "portability_worker_sha256": sha(portability.read_bytes()),
            "host_uid": os.getuid() if hasattr(os, "getuid") else None,
            "scope": "direct fixed worker, same OS identity; no syscall tracer or privilege separation",
            "planned": len(rows), "attempted": len(rows), "passed": sum(row["status"] == "pass" for row in rows),
            "failed": sum(row["status"] == "fail" for row in rows), "cases": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify-manifest", "runner-probe"))
    parser.add_argument("--worker", type=Path, default=ROOT / "src/aegis/evidence/_worker.py")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = (verify_manifest(ROOT / "benchmarks/phase-next-independent-validation/original-evidence-manifest.json")
              if args.operation == "verify-manifest" else runner_probe(args.worker))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: result[key] for key in ("planned", "matched", "mismatches") if key in result}
                     | {key: result[key] for key in ("attempted", "passed", "failed") if key in result},
                     sort_keys=True))
    if result.get("mismatches") or result.get("failed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
