"""Offline packaging contract checks; no wheel or network is fetched."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tomllib
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "phase5b1_build_offline.py"
SPEC = importlib.util.spec_from_file_location("phase5b1_build_offline", SCRIPT)
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def test_metadata_adds_console_and_direct_parser_dependency_without_default_split():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "scripts" not in project["project"]
    wheel = project["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["shared-scripts"] == {"src/aegis/launcher/aegis": "aegis"}
    launcher = ROOT / "src/aegis/launcher/aegis"
    assert launcher.read_text().splitlines()[-1] == 'exec "${0%/*}/python" -B -P -m aegis.cli "$@"'
    assert project["project"]["requires-python"] == ">=3.12"
    assert project["project"]["dependencies"] == [
        "cryptography>=44,<47", "pydantic>=2.10,<3", "fastapi>=0.115,<1",
        "httpx>=0.27,<1", "nats-py>=2.9,<3", "psycopg[binary]>=3.2,<4",
        "uvicorn>=0.30,<1",
    ]
    assert project["build-system"] == {"requires": ["hatchling"],
                                       "build-backend": "hatchling.build"}
    assert "lab" not in project["project"].get("optional-dependencies", {})


def write_manifest(path, wheels):
    path.mkdir()
    (path / "manifest.json").write_text(json.dumps({
        "schema": "aegis-offline-wheelhouse-v1", "wheels": wheels,
    }))


def entry(filename, content=b"synthetic non-wheel test bytes"):
    return {"file": filename, "sha256": hashlib.sha256(content).hexdigest(),
            "source": "synthetic local fixture", "license": "test-only"}


def test_missing_reviewed_wheelhouse_fails_before_output(tmp_path):
    output = tmp_path / "dist"
    with pytest.raises(builder.OfflineBuildError, match="missing"):
        builder.build("a" * 40, tmp_path / "absent", output, sys.executable)
    assert not output.exists()
    result = subprocess.run([sys.executable, str(SCRIPT), "a" * 40,
                             str(tmp_path / "absent"), str(output)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2 and result.stderr == ""
    assert json.loads(result.stdout)["status"] == "skipped-or-failed"
    assert not output.exists()


def test_manifest_requires_exact_hatchling_archive_and_hash(tmp_path):
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    with pytest.raises(builder.OfflineBuildError, match="manifest is missing"):
        builder.validate_wheelhouse(wheelhouse)
    (wheelhouse / "manifest.json").write_text('{"schema":"aegis-offline-wheelhouse-v1","wheels":[]}')
    with pytest.raises(builder.OfflineBuildError, match="no wheels"):
        builder.validate_wheelhouse(wheelhouse)
    wheelhouse.joinpath(builder.BACKEND_WHEEL).write_bytes(b"fixture")
    (wheelhouse / "manifest.json").write_text(json.dumps({"schema": "aegis-offline-wheelhouse-v1",
        "wheels": [entry(builder.BACKEND_WHEEL)]}))
    with pytest.raises(builder.OfflineBuildError, match="digest mismatch"):
        builder.validate_wheelhouse(wheelhouse)


def test_manifest_rejects_unlisted_duplicate_and_unsafe_archives(tmp_path):
    wheelhouse = tmp_path / "wheels"
    content = b"synthetic non-wheel test bytes"
    e = entry(builder.BACKEND_WHEEL, content)
    write_manifest(wheelhouse, [e])
    wheelhouse.joinpath(builder.BACKEND_WHEEL).write_bytes(content)
    assert builder.validate_wheelhouse(wheelhouse)["wheels"] == [e]
    wheelhouse.joinpath("extra-1.0-py3-none-any.whl").write_bytes(content)
    with pytest.raises(builder.OfflineBuildError, match="unmanifested"):
        builder.validate_wheelhouse(wheelhouse)
    wheelhouse.joinpath("extra-1.0-py3-none-any.whl").unlink()
    (wheelhouse / "manifest.json").write_text(json.dumps({"schema": "aegis-offline-wheelhouse-v1",
                                                 "wheels": [e, e]}))
    with pytest.raises(builder.OfflineBuildError, match="duplicate"):
        builder.validate_wheelhouse(wheelhouse)
    unsafe = entry("../escape.whl", content)
    (wheelhouse / "manifest.json").write_text(json.dumps({"schema": "aegis-offline-wheelhouse-v1",
                                                 "wheels": [unsafe]}))
    with pytest.raises(builder.OfflineBuildError, match="unsafe"):
        builder.validate_wheelhouse(wheelhouse)


def test_aliased_and_oversized_manifest_fails_closed(tmp_path):
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    (wheelhouse / "manifest.json").write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(builder.OfflineBuildError, match="input limit"):
        builder.validate_wheelhouse(wheelhouse)
    alias = tmp_path / "alias"
    alias.symlink_to(wheelhouse, target_is_directory=True)
    with pytest.raises(builder.OfflineBuildError, match="canonical"):
        builder.build("a" * 40, alias, tmp_path / "dist", sys.executable)


def test_wheel_inspection_requires_exact_console_and_default_dependencies(tmp_path):
    wheel = tmp_path / "fixture.whl"
    prefix = "aegis_network-0.1.0.dist-info/"
    metadata = ("Name: aegis-network\nVersion: 0.1.0\nRequires-Python: >=3.12\n" +
                "".join(f"Requires-Dist: {name}>=1\n" for name in
                        ("cryptography", "pydantic", "fastapi", "httpx", "nats-py",
                         "psycopg[binary]", "uvicorn")) + "\n")
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(prefix + "METADATA", metadata)
        archive.writestr(prefix + "WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n")
        archive.writestr(prefix + "RECORD", "fixture\n")
        archive.writestr(prefix + "entry_points.txt", "[console_scripts]\naegis = aegis.cli:main\n")
    inspected = builder.inspect_wheel(wheel)
    assert inspected["requires_python"] == ">=3.12"
    assert len(inspected["requires_dist"]) == 7
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(prefix + "METADATA", metadata.replace("Requires-Dist: pydantic>=1\n", ""))
        archive.writestr(prefix + "WHEEL", "Wheel-Version: 1.0\n")
        archive.writestr(prefix + "RECORD", "fixture\n")
        archive.writestr(prefix + "entry_points.txt", "[console_scripts]\naegis = aegis.cli:main\n")
    with pytest.raises(builder.OfflineBuildError, match="parser requirement"):
        builder.inspect_wheel(wheel)
