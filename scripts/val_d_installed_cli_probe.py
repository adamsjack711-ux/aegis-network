"""Run inside an offline, unprivileged, read-only Linux container."""

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import venv


WHEEL = Path("/wheel/aegis_network-0.1.0-py3-none-any.whl")
ROOT = Path("/tmp/val-d-venv")


def call(argv, env=None):
    proc = subprocess.run([str(x) for x in argv], capture_output=True, text=True,
                          check=False, env=env)
    return {"argv": [str(x) for x in argv], "exit_code": proc.returncode,
            "stdout": proc.stdout[:8000], "stderr": proc.stderr[:8000]}


def tree():
    result = {}
    for path in sorted(Path("/tmp").rglob("*")):
        rel = str(path.relative_to("/tmp"))
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            result[rel] = {"kind": "file", "sha256": sha256(path.read_bytes()).hexdigest(),
                           "mtime_ns": path.stat().st_mtime_ns}
        elif stat.S_ISLNK(mode):
            result[rel] = {"kind": "symlink", "target": os.readlink(path)}
        else:
            result[rel] = {"kind": "directory", "mode": stat.S_IMODE(mode)}
    return result


def main():
    assert os.geteuid() == 1000
    assert WHEEL.exists()
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(ROOT)
    python = ROOT / "bin/python"
    entry = ROOT / "bin/aegis"
    env = os.environ | {"PYTHONDONTWRITEBYTECODE": "1", "XDG_STATE_HOME": "/tmp/val-d-state",
                        "HOME": "/tmp/val-d-home", "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    Path(env["HOME"]).mkdir(exist_ok=True)
    install = call([python, "-m", "pip", "install", "--no-index", "--no-deps",
                    "--force-reinstall", WHEEL], env)
    origin = call([python, "-c", "import aegis,sys; print(aegis.__file__); print(sys.version)"], env)
    cases = {}
    commands = {
        "status_no_feed": ["status", "--json"],
        "findings_no_feed": ["findings", "--json"],
        "findings_missing_feed": ["findings", "--feed", "/tmp/missing.json", "--json"],
        "inventory": ["inventory", "--json"],
        "malformed_feed": ["findings", "--feed", "/fixture/malformed-feed.json", "--json"],
    }
    if install["exit_code"] == 0 and entry.exists():
        for name, argv in commands.items():
            before = tree()
            result = call([entry, *argv], env)
            after = tree()
            result["created"] = sorted(set(after) - set(before))
            result["removed"] = sorted(set(before) - set(after))
            result["modified"] = sorted(key for key in set(before) & set(after)
                                        if before[key] != after[key])
            cases[name] = result
        before = tree()
        explicit = call([entry, "--state-dir", "/tmp/val-d-chosen", "inventory", "--json"], env)
        after = tree()
        explicit["created"] = sorted(set(after) - set(before))
        identity = Path("/tmp/val-d-chosen/identity.json")
        explicit["identity_file_mode"] = (oct(stat.S_IMODE(identity.stat().st_mode))
                                          if identity.exists() else None)
        explicit["identity_dir_mode"] = (oct(stat.S_IMODE(identity.parent.stat().st_mode))
                                         if identity.parent.exists() else None)
    else:
        explicit = None
    uninstall = call([python, "-m", "pip", "uninstall", "-y", "aegis-network"], env)
    dist_info = sorted(str(path) for path in (ROOT / "lib").rglob("aegis_network-*.dist-info"))
    print(json.dumps({"uid": os.geteuid(), "python": sys.version, "os_release":
                      Path("/etc/os-release").read_text(), "wheel_sha256": sha256(WHEEL.read_bytes()).hexdigest(),
                      "install": install, "candidate_module_origin": origin,
                      "entry_point_present_after_install": bool(cases),
                      "cases": cases, "explicit_state": explicit, "uninstall": uninstall,
                      "entry_point_present_after_uninstall": entry.exists(),
                      "candidate_dist_info_after_uninstall": dist_info}, sort_keys=True))


if __name__ == "__main__":
    main()
