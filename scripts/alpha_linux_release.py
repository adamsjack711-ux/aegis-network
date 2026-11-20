"""Fail-closed, local-only Linux release rehearsal for an exact Aegis commit.

Inputs are original wheel archives supplied and reviewed out of band. This
script never downloads packages or pulls images. Missing inputs are skips,
not successful release tests.
"""

from __future__ import annotations

import argparse
from email.parser import BytesParser
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlparse
import zipfile

import phase5b1_build_offline as builder


ROOT = Path(__file__).resolve().parents[1]
CELLS = (
    ("debian-13-py312", "aegis_phase4_baseline-coordinator:latest", "debian", "13", "3.12"),
    ("debian-13-py313", "python:3.13-slim", "debian", "13", "3.13"),
    ("ubuntu-2404-py312", "mcr.microsoft.com/playwright/python:v1.50.0-noble", "ubuntu", "24.04", "3.12"),
    ("ubuntu-2404-py313", "", "ubuntu", "24.04", "3.13"),
)


def wheel_identity(path: Path) -> tuple[str, str, list[str]]:
    with zipfile.ZipFile(path) as archive:
        metadata_files = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        wheel_files = [name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")]
        if len(metadata_files) != 1 or len(wheel_files) != 1:
            raise builder.OfflineBuildError(f"invalid wheel metadata: {path.name}")
        metadata = BytesParser().parsebytes(archive.read(metadata_files[0]))
        wheel = BytesParser().parsebytes(archive.read(wheel_files[0]))
        name, version, tags = metadata.get("Name"), metadata.get("Version"), wheel.get_all("Tag", [])
        if not name or not version or not tags:
            raise builder.OfflineBuildError(f"incomplete wheel identity: {path.name}")
        return name, version, tags


def validate_provenance(wheelhouse: Path) -> dict:
    """Verify original archives, metadata, and an explicit reviewer record."""
    legacy = builder.validate_wheelhouse(wheelhouse)
    path = wheelhouse / "provenance.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise builder.OfflineBuildError("reviewed provenance record is missing or oversized")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise builder.OfflineBuildError("invalid provenance record") from exc
    if not isinstance(record, dict) or record.get("schema") != "aegis-release-provenance-v1":
        raise builder.OfflineBuildError("unsupported provenance schema")
    reviewer = record.get("review_commit")
    if not isinstance(reviewer, str) or not re.fullmatch(r"[0-9a-f]{40}", reviewer):
        raise builder.OfflineBuildError("exact reviewer commit is required")
    review_object = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{reviewer}^{{commit}}"],
                                   capture_output=True, check=False)
    if review_object.returncode:
        raise builder.OfflineBuildError("review commit is not present locally")
    entries = record.get("wheels")
    if not isinstance(entries, list) or len(entries) != len(legacy["wheels"]):
        raise builder.OfflineBuildError("provenance wheel count differs from manifest")
    listed = {item["file"]: item for item in legacy["wheels"]}
    seen: set[str] = set()
    for item in entries:
        required = {"file", "sha256", "distribution", "version", "tags", "source", "license", "role"}
        if not isinstance(item, dict) or set(item) != required:
            raise builder.OfflineBuildError("incomplete provenance entry")
        filename = item["file"]
        if not all(isinstance(item[key], str) and item[key] for key in
                   ("file", "sha256", "distribution", "version", "source", "license", "role")) or \
                not isinstance(item["tags"], list) or \
                not all(isinstance(tag, str) for tag in item["tags"]):
            raise builder.OfflineBuildError("invalid provenance field or tags")
        if filename in seen or filename not in listed or item["sha256"] != listed[filename]["sha256"]:
            raise builder.OfflineBuildError("provenance archive digest mismatch or duplicate")
        if item["source"] != listed[filename]["source"] or item["license"] != listed[filename]["license"]:
            raise builder.OfflineBuildError("provenance source or license differs from manifest")
        if item["role"] not in {"build", "runtime", "both"}:
            raise builder.OfflineBuildError("invalid wheel role")
        name, version, tags = wheel_identity(wheelhouse / filename)
        if (item["distribution"].lower().replace("_", "-") != name.lower().replace("_", "-")
                or item["version"] != version or sorted(item["tags"]) != sorted(tags)):
            raise builder.OfflineBuildError("provenance identity differs from wheel metadata")
        seen.add(filename)
    if seen != set(listed) or not any(item["file"] == builder.BACKEND_WHEEL and
                                      item["role"] in {"build", "both"} for item in entries):
        raise builder.OfflineBuildError("build backend provenance is incomplete")
    return {"manifest_sha256": legacy["manifest_sha256"],
            "provenance_sha256": builder.digest(path), "review_commit": reviewer,
            "wheels": entries}


def command(argv: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, **kwargs)


def verify_pip_report(pip_report: dict, provenance: dict, aegis_wheel: Path) -> list[dict]:
    expected = {item["file"]: item["sha256"] for item in provenance["wheels"]}
    expected[aegis_wheel.name] = builder.digest(aegis_wheel)
    installed = []
    if not isinstance(pip_report, dict) or not isinstance(pip_report.get("install"), list):
        raise builder.OfflineBuildError("pip install report is incomplete")
    for item in pip_report["install"]:
        source = item.get("download_info", {})
        url = urlparse(source.get("url", ""))
        name = Path(unquote(url.path)).name
        hashes = source.get("archive_info", {}).get("hashes", {})
        if url.scheme != "file" or name not in expected or hashes.get("sha256") != expected[name]:
            raise builder.OfflineBuildError("pip installed an unpinned or wrong-hash archive")
        installed.append({"file": name, "sha256": expected[name],
                          "distribution": item.get("metadata", {}).get("name"),
                          "version": item.get("metadata", {}).get("version")})
    if aegis_wheel.name not in {item["file"] for item in installed}:
        raise builder.OfflineBuildError("Aegis wheel absent from pip install report")
    return installed


def run_cell(cell: tuple[str, str, str, str, str], wheelhouse: Path,
             dist: Path, provenance: dict) -> dict:
    label, image, distro, release, python = cell
    result: dict = {"cell": label, "image": image or None, "status": "skipped"}
    if not image:
        result["reason"] = "no reviewed cached image assigned"
        return result
    probe = command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    if probe.returncode:
        result["reason"] = "image absent from local cache or Docker unavailable"
        return result
    result["image_id"] = probe.stdout.strip()
    # The container receives only immutable wheel inputs and a disposable tmpfs.
    # Neither pip nor Docker may use a package index or image registry.
    script = r'''
set -eu
test "$(id -u)" != 0
. /etc/os-release
test "$ID" = "$AEGIS_DISTRO"
test "$VERSION_ID" = "$AEGIS_RELEASE"
python3 -c 'import sys,os; assert sys.version.startswith(os.environ["AEGIS_PYTHON"]+".")'
python3 -m venv /tmp/venv
export PYTHONDONTWRITEBYTECODE=1 PIP_NO_INDEX=1 PIP_CONFIG_FILE=/dev/null
/tmp/venv/bin/python -m pip install --no-index --no-cache-dir --find-links /wheels --report /tmp/install.json /dist/aegis_network-0.1.0-py3-none-any.whl >/dev/null
test -x /tmp/venv/bin/aegis
/tmp/venv/bin/aegis --help >/dev/null
before="$(find /tmp -type f -print | sort)"
if status="$(/tmp/venv/bin/aegis status --json)"; then exit 1; else test "$?" -eq 2; fi
printf '%s' "$status" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["independent_status"] == "unknown" and d["network"] == "offline" and d["mode"] == "observation-only"'
inventory="$(/tmp/venv/bin/aegis inventory --json)"
printf '%s' "$inventory" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["schema_version"] == "inventory-v2" and d["inventory_complete"] is True'
if missing="$(/tmp/venv/bin/aegis findings --json)"; then exit 1; else test "$?" -eq 2; fi
printf '%s' "$missing" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["independent_status"] == "unknown" and "--feed is required" in d["error"]'
after="$(find /tmp -type f -print | sort)"
test "$before" = "$after"
/tmp/venv/bin/python -m pip uninstall -y aegis-network >/dev/null
test ! -e /tmp/venv/bin/aegis
/tmp/venv/bin/python -c 'import importlib.util; assert importlib.util.find_spec("aegis") is None'
cat /tmp/install.json
'''
    argv = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
            "--tmpfs", "/tmp/venv:rw,exec,nosuid,nodev,uid=65534,gid=65534,mode=0700,size=256m",
            "--mount", f"type=bind,src={wheelhouse},dst=/wheels,readonly",
            "--mount", f"type=bind,src={dist},dst=/dist,readonly",
            "-e", f"AEGIS_DISTRO={distro}", "-e", f"AEGIS_RELEASE={release}",
            "-e", f"AEGIS_PYTHON={python}", image, "sh", "-ec", script]
    try:
        trial = command(argv, timeout=180)
    except subprocess.TimeoutExpired:
        result.update(status="failed", reason="offline install or CLI trial exceeded 180 seconds")
        return result
    result["status"] = "passed" if trial.returncode == 0 else "failed"
    result["exit_code"] = trial.returncode
    result["stderr"] = trial.stderr[-4000:]
    if trial.returncode == 0:
        try:
            pip_report = json.loads(trial.stdout)
            result["installed_archives"] = verify_pip_report(
                pip_report, provenance, dist / "aegis_network-0.1.0-py3-none-any.whl")
        except (json.JSONDecodeError, builder.OfflineBuildError) as exc:
            result["status"] = "failed"
            result["reason"] = str(exc)
    else:
        result["stdout"] = trial.stdout[-2000:]
    return result


def release(pin: str, wheelhouse: Path, output: Path, images: dict[str, str] | None = None) -> dict:
    report: dict = {"source_commit": pin, "status": "incomplete", "builds": [], "cells": []}
    if not re.fullmatch(r"[0-9a-f]{40}", pin):
        raise builder.OfflineBuildError("exact 40-character source commit required")
    output = output.expanduser().absolute()
    if output.resolve() != output:
        raise builder.OfflineBuildError("output path must be canonical")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise builder.OfflineBuildError("output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    try:
        wheelhouse = wheelhouse.expanduser().absolute()
        if wheelhouse.resolve() != wheelhouse:
            raise builder.OfflineBuildError("wheelhouse path must be canonical")
        provenance = validate_provenance(wheelhouse)
        report["wheelhouse"] = provenance
        with tempfile.TemporaryDirectory(prefix="aegis-release-input-") as temporary:
            frozen = Path(temporary) / "wheels"
            shutil.copytree(wheelhouse, frozen, symlinks=False)
            if validate_provenance(frozen)["manifest_sha256"] != provenance["manifest_sha256"] or \
                    validate_provenance(frozen)["provenance_sha256"] != provenance["provenance_sha256"]:
                raise builder.OfflineBuildError("wheelhouse changed during snapshot")
            for label in ("a", "b"):
                built = builder.build(pin, frozen, output / f"build-{label}", sys.executable)
                report["builds"].append({"label": label, "wheel": built["wheel"]["sha256"],
                                         "sdist": built["sdist"]["sha256"],
                                         "requires_dist": built["wheel"]["requires_dist"],
                                         "members": built["wheel"]["members"]})
            if report["builds"][0]["wheel"] != report["builds"][1]["wheel"] or \
                    report["builds"][0]["sdist"] != report["builds"][1]["sdist"]:
                raise builder.OfflineBuildError("two exact-source builds differ byte-for-byte")
            report["status"] = "build-reproducible"
            for cell in CELLS:
                if images and cell[0] in images:
                    cell = (cell[0], images[cell[0]], *cell[2:])
                report["cells"].append(run_cell(cell, frozen, output / "build-a", provenance))
            if validate_provenance(frozen)["manifest_sha256"] != provenance["manifest_sha256"] or \
                    validate_provenance(frozen)["provenance_sha256"] != provenance["provenance_sha256"]:
                raise builder.OfflineBuildError("wheelhouse changed during release rehearsal")
            if all(cell["status"] == "passed" for cell in report["cells"]):
                report["status"] = "matrix-passed"
    except (builder.OfflineBuildError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile,
            subprocess.TimeoutExpired) as exc:
        report["reason"] = str(exc)[:512]
    (output / "release-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_commit")
    parser.add_argument("wheelhouse", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--image", action="append", default=[], metavar="CELL=LOCAL_IMAGE",
                        help="override a cached image; never pulls")
    args = parser.parse_args()
    images = {}
    for setting in args.image:
        label, separator, image = setting.partition("=")
        if not separator or label not in {cell[0] for cell in CELLS} or not image:
            parser.error("--image requires a known CELL and nonempty local image")
        images[label] = image
    report = release(args.source_commit, args.wheelhouse, args.output, images)
    print(json.dumps({"status": report["status"], "reason": report.get("reason"),
                      "report": str(args.output / "release-report.json")}, sort_keys=True))
    return 0 if report["status"] == "matrix-passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
