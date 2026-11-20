"""Build exact-source Aegis wheel/sdist from a reviewed local wheelhouse.

This script never resolves an index. It refuses an absent, unmanifested or
hash-mismatched backend wheelhouse before creating a build environment.
"""

from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


EPOCH = "1735689600"
BACKEND_WHEEL = "hatchling-1.33.0-py3-none-any.whl"
ROOT = Path(__file__).resolve().parents[1]


class OfflineBuildError(ValueError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def validate_wheelhouse(root: Path) -> dict:
    if not root.is_dir() or root.is_symlink():
        raise OfflineBuildError("reviewed wheelhouse directory is missing or aliased")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise OfflineBuildError("reviewed wheelhouse manifest is missing")
    if manifest_path.stat().st_size > 1024 * 1024:
        raise OfflineBuildError("wheelhouse manifest exceeds input limit")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OfflineBuildError("invalid wheelhouse manifest") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != "aegis-offline-wheelhouse-v1":
        raise OfflineBuildError("unsupported wheelhouse manifest")
    entries = manifest.get("wheels")
    if not isinstance(entries, list) or not entries:
        raise OfflineBuildError("wheelhouse manifest has no wheels")
    listed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"file", "sha256", "source", "license"}:
            raise OfflineBuildError("invalid wheelhouse entry")
        filename = entry["file"]
        if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\.whl", filename):
            raise OfflineBuildError("unsafe wheel filename")
        if filename in listed or not all(isinstance(entry[key], str) and entry[key]
                                         for key in ("sha256", "source", "license")):
            raise OfflineBuildError("duplicate or incomplete wheel provenance")
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise OfflineBuildError("invalid wheel digest")
        wheel = root / filename
        try:
            if not stat.S_ISREG(wheel.lstat().st_mode) or digest(wheel) != entry["sha256"]:
                raise OfflineBuildError("wheel archive missing or digest mismatch")
        except OSError as exc:
            raise OfflineBuildError("wheel archive missing or unreadable") from exc
        listed.add(filename)
    if BACKEND_WHEEL not in listed:
        raise OfflineBuildError("reviewed Hatchling 1.33.0 archive is missing")
    if {path.name for path in root.glob("*.whl")} != listed:
        raise OfflineBuildError("wheelhouse contains unmanifested wheel archives")
    return {"manifest_sha256": digest(manifest_path), "wheels": entries}


def exact_source(pin: str, target: Path) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", pin):
        raise OfflineBuildError("source pin must be an exact full commit hash")
    verified = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", f"{pin}^{{commit}}"],
                              capture_output=True, text=True, check=True).stdout.strip()
    if verified != pin:
        raise OfflineBuildError("source pin does not resolve exactly")
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", pin,
                              "pyproject.toml", "src/aegis"], capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        stream.extractall(target, filter="data")


def inspect_wheel(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        members = {}
        for suffix in ("METADATA", "WHEEL", "RECORD", "entry_points.txt"):
            matching = [name for name in names if name.endswith(f".dist-info/{suffix}")]
            if len(matching) != 1:
                raise OfflineBuildError(f"wheel {suffix} is missing or ambiguous")
            members[suffix] = archive.read(matching[0]).decode("utf-8")
    metadata = Parser().parsestr(members["METADATA"])
    requirements = metadata.get_all("Requires-Dist", [])
    if metadata.get("Name") != "aegis-network" or metadata.get("Version") != "0.1.0" or \
            metadata.get("Requires-Python") != ">=3.12":
        raise OfflineBuildError("unexpected wheel identity or Python requirement")
    expected = ("cryptography", "pydantic", "fastapi", "httpx", "nats-py", "psycopg", "uvicorn")
    if any(not any(re.match(rf"^{re.escape(name)}(?:\[|[ <>=!~])", item, re.IGNORECASE)
                   for item in requirements) for name in expected):
        raise OfflineBuildError("default lab or direct parser requirement missing")
    if "aegis = aegis.cli:main" not in members["entry_points.txt"]:
        raise OfflineBuildError("unexpected console entry point")
    return {"members": names, "requires_python": metadata.get("Requires-Python"),
            "requires_dist": requirements, "wheel_metadata": members["WHEEL"]}


def build(pin: str, wheelhouse: Path, output: Path, python: str) -> dict:
    requested_wheelhouse = wheelhouse.expanduser().absolute()
    if requested_wheelhouse.resolve() != requested_wheelhouse:
        raise OfflineBuildError("reviewed wheelhouse path must be canonical")
    wheelhouse = requested_wheelhouse
    output = output.expanduser().resolve()
    approved = validate_wheelhouse(wheelhouse)
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise OfflineBuildError("output directory must be empty")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aegis-5b1-", dir=output.parent) as scratch_name:
        scratch = Path(scratch_name)
        source = scratch / "source"
        source.mkdir()
        exact_source(pin, source)
        environment = os.environ | {"SOURCE_DATE_EPOCH": EPOCH, "PIP_NO_INDEX": "1",
                                    "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_CONFIG_FILE": os.devnull,
                                    "PYTHONDONTWRITEBYTECODE": "1"}
        venv = scratch / "venv"
        subprocess.run([python, "-m", "venv", str(venv)], check=True, env=environment,
                       capture_output=True, text=True)
        interpreter = venv / "bin" / "python"
        subprocess.run([str(interpreter), "-m", "pip", "install", "--no-index",
                        "--no-cache-dir", "--find-links", str(wheelhouse), "hatchling==1.33.0"],
                       check=True, env=environment, capture_output=True, text=True)
        output.mkdir(exist_ok=True)
        script = ("from hatchling.build import build_wheel, build_sdist; "
                  f"build_wheel({str(output)!r}); build_sdist({str(output)!r})")
        subprocess.run([str(interpreter), "-c", script], cwd=source, env=environment,
                       check=True, capture_output=True, text=True)
    wheels = list(output.glob("aegis_network-*.whl"))
    sdists = list(output.glob("aegis_network-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise OfflineBuildError("build did not produce one wheel and one source distribution")
    inspected = inspect_wheel(wheels[0])
    report = {"source_commit": pin, "source_date_epoch": EPOCH,
              "wheelhouse": approved, "python": python,
              "wheel": {"file": wheels[0].name, "sha256": digest(wheels[0]), "bytes": wheels[0].stat().st_size,
                        **inspected},
              "sdist": {"file": sdists[0].name, "sha256": digest(sdists[0]),
                        "bytes": sdists[0].stat().st_size}}
    (output / "build-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_commit")
    parser.add_argument("wheelhouse", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    try:
        report = build(args.source_commit, args.wheelhouse, args.output, args.python)
    except (OfflineBuildError, OSError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "skipped-or-failed", "reason": str(exc)[:512]}, sort_keys=True))
        return 2
    print(json.dumps({"status": "built-offline", "wheel_sha256": report["wheel"]["sha256"],
                      "sdist_sha256": report["sdist"]["sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
