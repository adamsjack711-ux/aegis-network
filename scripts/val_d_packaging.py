"""Build an exact Git archive twice offline and inspect the wheel entry point."""

import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile


def run(argv, **kwargs):
    process = subprocess.run(argv, capture_output=True, text=True, check=False, **kwargs)
    return {"argv": argv, "exit_code": process.returncode,
            "stdout": process.stdout, "stderr": process.stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-pin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.candidate_root.resolve()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if head != args.source_pin or len(head) != 40:
        raise ValueError("candidate HEAD differs from exact source pin")
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip()
    archive = subprocess.check_output(["git", "archive", args.source_pin,
                                       "pyproject.toml", "src/aegis"], cwd=root)
    scratch = Path(tempfile.mkdtemp(prefix="val-d-cli-package-", dir="/private/tmp"))
    source = scratch / "source"
    source.mkdir()
    with tarfile.open(fileobj=BytesIO(archive)) as stream:
        stream.extractall(source, filter="data")
    env = os.environ | {"SOURCE_DATE_EPOCH": "1795143126", "UV_NO_NETWORK": "1"}
    builds = []
    wheels = []
    for label in ("a", "b"):
        dest = scratch / label
        dest.mkdir()
        argv = ["uv", "build", "--offline", "--wheel", "--out-dir", str(dest), str(source)]
        result = run(argv, env=env)
        paths = sorted(dest.glob("*.whl"))
        result["wheel_paths"] = [str(path) for path in paths]
        builds.append(result)
        if result["exit_code"] == 0 and len(paths) == 1:
            wheels.append(paths[0])
    hashes = [sha256(path.read_bytes()).hexdigest() for path in wheels]
    wheel_info = None
    if len(wheels) == 2:
        with zipfile.ZipFile(wheels[0]) as z:
            names = z.namelist()
            entry = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
            metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
            wheel_info = {"bytes": wheels[0].stat().st_size,
                          "entry_points": z.read(entry[0]).decode() if len(entry) == 1 else None,
                          "metadata": z.read(metadata[0]).decode() if len(metadata) == 1 else None,
                          "module_count": sum(name.startswith("aegis/") and name.endswith(".py") for name in names),
                          "zip_members": len(names)}
    result = {"source_pin": args.source_pin, "candidate_checkout_dirty": bool(dirty),
              "source_archive_sha256": sha256(archive).hexdigest(),
              "source_tree": str(source), "scratch": str(scratch),
              "source_date_epoch": env["SOURCE_DATE_EPOCH"],
              "builds": builds, "wheel_sha256": hashes,
              "byte_reproducible": len(hashes) == 2 and hashes[0] == hashes[1],
              "wheel_info": wheel_info}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"build_exit_codes": [x["exit_code"] for x in builds],
                      "byte_reproducible": result["byte_reproducible"],
                      "wheel_sha256": hashes}))


if __name__ == "__main__":
    main()
