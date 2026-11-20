"""Run 17 frozen resource children per reviewed installed Linux cell.

No pull, feed, model, or package network is permitted. Source is never mounted.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
INPUTS = ROOT.parent / "alpha-fc4a-inputs"
SOURCE_PIN = "fc4a17bc6f9f0c289a645c4fb7006c999ba90e99"
REVIEW_PIN = "ad830ada4bb13e45b9f192bc54c165281e8d9b50"
WHEEL_SHA = "28943894bfe543338a353a538fac3a26e9fd552df730e4cb83921953503727e5"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def preflight() -> tuple[list[dict], dict]:
    binding = json.loads((ROOT / "supply-prep/install-review.json").read_text())
    assert binding["source_commit"] == SOURCE_PIN and binding["review_commit"] == REVIEW_PIN
    assert sha(INPUTS / "wheels/manifest.json") == binding["manifest_sha256"]
    assert sha(INPUTS / "wheels/provenance.json") == binding["provenance_sha256"]
    provenance = json.loads((INPUTS / "wheels/provenance.json").read_text())
    assert provenance["review_commit"] == REVIEW_PIN
    assert subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e",
                           REVIEW_PIN + "^{commit}"], check=False).returncode == 0
    for number in (1, 2):
        assert sha(INPUTS / f"build-{number}/aegis_network-0.1.0-py3-none-any.whl") == WHEEL_SHA
    cells = json.loads((ROOT / "supply-prep/checks.json").read_text())
    assert [c["cell"] for c in cells] == ["debian-13-py312", "debian-13-py313",
                                           "ubuntu-2404-py312", "ubuntu-2404-py313"]
    for cell in cells:
        assert cell["image"].startswith("sha256:")
        probe = subprocess.run(["docker", "--context", "colima", "image", "inspect",
                                cell["image"], "--format", "{{.Id}}"],
                               text=True, capture_output=True, check=False)
        assert probe.returncode == 0 and probe.stdout.strip() == cell["image"], (cell["cell"], probe.stderr)
    return cells, binding


def verify_install_report(path: Path) -> list[str]:
    report = json.loads(path.read_text())
    manifest = json.loads((INPUTS / "wheels/manifest.json").read_text())
    expected = {row["file"]: row["sha256"] for row in manifest["wheels"]}
    expected["aegis_network-0.1.0-py3-none-any.whl"] = WHEEL_SHA
    installed = []
    for item in report["install"]:
        source = item["download_info"]
        url = urlparse(source["url"])
        name = Path(unquote(url.path)).name
        assert url.scheme == "file" and name in expected
        assert source["archive_info"]["hashes"]["sha256"] == expected[name]
        installed.append(name)
    assert "aegis_network-0.1.0-py3-none-any.whl" in installed
    return installed


def run_cell(cell: dict, memory: int, *, suffix: str = "", mode: str = "all") -> dict:
    label, image = cell["cell"], cell["image"]
    distro = "debian" if label.startswith("debian") else "ubuntu"
    assert mode in {"all", "closed-only"}
    directory = HERE / "results" / label / (f"{memory}m" + suffix)
    if directory.exists() and any(directory.iterdir()):
        raise RuntimeError(f"refusing to overwrite retained evidence: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o777)  # Disposable output sink written by container UID 65534.
    script = """set -eu
export PIP_NO_INDEX=1 PIP_CONFIG_FILE=/dev/null PYTHONDONTWRITEBYTECODE=1
python3 -m venv /tmp/venv
/tmp/venv/bin/pip --isolated install --no-index --no-cache-dir --find-links /inputs/wheels --report /results/install.json /inputs/build-1/aegis_network-0.1.0-py3-none-any.whl > /results/pip.stdout 2> /results/pip.stderr
test -x /tmp/venv/bin/aegis
/tmp/venv/bin/pip check > /results/pip-check.txt
python3 -B /runner/worker.py "$AEGIS_DISTRO" "$AEGIS_BUDGET" "$AEGIS_MODE"
"""
    command = ["docker", "--context", "colima", "run", "--rm", "--pull=never",
               "--network=none", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--user=65534:65534",
               "--cpus=1", f"--memory={memory}m", f"--memory-swap={memory}m",
               "--pids-limit=64", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
               "--tmpfs", "/tmp/venv:rw,exec,nosuid,nodev,uid=65534,gid=65534,mode=0700,size=256m",
               "--tmpfs", "/var/lib/dpkg:rw,noexec,nosuid,nodev,size=32m,uid=65534,gid=65534,mode=0700",
               "--mount", f"type=bind,src={INPUTS},dst=/inputs,readonly",
               "--mount", f"type=bind,src={ROOT / 'benchmarks/alpha-cli-privacy/inputs'},dst=/fixtures,readonly",
               "--mount", f"type=bind,src={HERE / 'worker.py'},dst=/runner/worker.py,readonly",
               "--mount", f"type=bind,src={directory},dst=/results",
               "-e", f"AEGIS_DISTRO={distro}", "-e", f"AEGIS_BUDGET={memory}",
               "-e", f"AEGIS_MODE={mode}",
               "--entrypoint", "sh", image, "-ec", script]
    try:
        run = subprocess.run(command, text=True, capture_output=True, timeout=360, check=False)
        (directory / "docker.stdout").write_text(run.stdout)
        (directory / "docker.stderr").write_text(run.stderr)
        result = {"cell": label, "image_id": image, "memory_limit_mib": memory,
                  "docker_exit": run.returncode, "docker_command": command[:-1],
                  "summary": json.loads((directory / "summary.json").read_text()) if
                  (directory / "summary.json").exists() else None}
        result["installed_archives"] = (verify_install_report(directory / "install.json")
                                         if (directory / "install.json").exists() else [])
    except (subprocess.TimeoutExpired, OSError, ValueError, KeyError, AssertionError) as exc:
        result = {"cell": label, "image_id": image, "memory_limit_mib": memory,
                  "error": f"{type(exc).__name__}: {exc}"}
    (directory / "run.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    cells, binding = preflight()  # No installation or Docker run precedes this check.
    report = {"source_commit": SOURCE_PIN, "review_commit": REVIEW_PIN, "binding": binding,
              "wheel_sha256": WHEEL_SHA, "planned": 68, "cells": []}
    for cell in cells:
        for memory in (512, 256):
            result = run_cell(cell, memory)
            report["cells"].append(result)
            summary = result.get("summary") or {}
            print(f"{cell['cell']} {memory} MiB: {summary.get('passed', 0)}/{summary.get('planned', 0)}; "
                  f"Docker exit {result.get('docker_exit', 'error')}", flush=True)
    report["attempted"] = sum((row.get("summary") or {}).get("attempted", 0) for row in report["cells"])
    report["passed"] = sum((row.get("summary") or {}).get("passed", 0) for row in report["cells"])
    report["failed"] = report["attempted"] - report["passed"]
    report["unattempted"] = 68 - report["attempted"]
    (HERE / "results/overall.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("planned", "attempted", "passed", "failed", "unattempted")}))
    return 0 if report["passed"] == 68 else 1


if __name__ == "__main__":
    raise SystemExit(main())
