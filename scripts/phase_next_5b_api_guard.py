"""Catch Python-level network, process, and privilege calls in CLI observation."""

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-pin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    candidate = args.candidate_root.resolve()
    pin = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=candidate, text=True).strip()
    if pin != args.source_pin or subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=candidate, text=True).strip():
        raise ValueError("candidate is not the requested clean exact pin")
    sys.path.insert(0, str(candidate / "src"))
    from aegis.cli import main as cli_main

    calls = []
    originals = {"socket": socket.socket, "setuid": os.setuid, "setgid": os.setgid,
                 "system": os.system, "popen": subprocess.Popen}

    def deny(name):
        def blocked(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError("forbidden API called: " + name)
        return blocked

    with TemporaryDirectory(prefix="aegis-cli-api-guard-") as directory:
        state = Path(directory) / "explicit-state"
        socket.socket = deny("socket.socket")
        os.setuid = deny("os.setuid")
        os.setgid = deny("os.setgid")
        os.system = deny("os.system")
        subprocess.Popen = deny("subprocess.Popen")
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                exit_code = cli_main(["--state-dir", str(state), "inventory", "--json"])
        finally:
            socket.socket = originals["socket"]
            os.setuid = originals["setuid"]
            os.setgid = originals["setgid"]
            os.system = originals["system"]
            subprocess.Popen = originals["popen"]
        files = sorted(str(p.relative_to(Path(directory))) for p in Path(directory).rglob("*") if p.is_file())
    result = {"at_utc": datetime.now(timezone.utc).isoformat(), "source_pin": pin,
              "scope": "Python-level API guard, local host; not a syscall trace",
              "calls": calls, "exit_code": exit_code, "stdout": output.getvalue(), "files": files,
              "status": "pass" if not calls and files == ["explicit-state/identity.json"] else "fail"}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "calls": calls, "files": files}))


if __name__ == "__main__":
    main()
