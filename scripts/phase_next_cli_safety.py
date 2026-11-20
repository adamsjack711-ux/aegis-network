"""Audit an observation CLI with Linux strace and unprivileged fixtures."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic_ns


MALFORMED = {
    "valid_empty": b'{"packages":[]}',
    "truncated": b'{"packages":[',
    "invalid_utf8": b"\xff\xfe\x00",
    "hostile_string": b'{"packages":[{"name":"$(touch /tmp/aegis-cli-injection)","version":"1"}]}',
    "oversized": b'{"packages":[{"name":"' + b"A" * 1_000_000 + b'","version":"1"}]}',
}


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def command_from_template(template, input_path):
    args = shlex.split(template)
    if sum(part.count("{input}") for part in args) != 1:
        raise ValueError("command template must contain exactly one {input} placeholder")
    return [part.replace("{input}", str(input_path)) for part in args]


def assess_trace(raw, executable):
    lines = raw.splitlines()
    violations = []
    for line in lines:
        if re.search(r"\b(connect|sendto|sendmsg|socket)\(", line):
            violations.append("network syscall: " + line)
        if re.search(r"\b(setuid|setreuid|setresuid|setgid|setregid|setresgid|capset|setns|unshare|mount|ptrace)\(", line):
            violations.append("privilege or namespace syscall: " + line)
        if re.search(r"\b(open|openat|openat2|creat)\(.*\b(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b", line):
            violations.append("write-open syscall: " + line)
        if re.search(r"\b(rename|renameat|unlink|unlinkat|mkdir|mkdirat|rmdir|chmod|fchmod|chown|fchown|truncate|ftruncate|symlink|link)\(", line):
            violations.append("filesystem mutation syscall: " + line)
        if "execve(" in line and executable not in line and "strace" not in line:
            violations.append("unexpected executable: " + line)
        if "/mitigation/" in line or "/run/aegis" in line:
            violations.append("enforcement interface access: " + line)
    return violations


def run_case(template, name, payload, root, timeout):
    path = root / (name + ".json")
    path.write_bytes(payload)
    before = digest(path)
    argv = command_from_template(template, path)
    trace = root / (name + ".strace")
    before_files = {p.name for p in root.iterdir()}
    started = monotonic_ns()
    try:
        process = subprocess.run(["strace", "-f", "-qq", "-e", "trace=file,network,process,setuid,setgid,capset,setns,unshare,mount,ptrace",
                                  "-o", str(trace), *argv], capture_output=True, text=True, timeout=timeout,
                                 cwd=root, check=False)
        error = None
    except subprocess.TimeoutExpired as exc:
        process = None
        error = "timeout: " + str(exc)
    elapsed = (monotonic_ns() - started) / 1_000_000
    trace_text = trace.read_text(errors="replace") if trace.exists() else ""
    violations = assess_trace(trace_text, argv[0])
    if digest(path) != before:
        violations.append("input file modified")
    extra = sorted({p.name for p in root.iterdir()} - before_files - {trace.name})
    if extra:
        violations.append("unexpected output files: " + ", ".join(extra))
    return {"case": name, "status": "inconclusive" if error else "fail" if violations else "pass",
            "elapsed_ms": elapsed, "exit_code": process.returncode if process else None,
            "stdout": process.stdout if process else "", "stderr": process.stderr if process else "",
            "error": error, "violations": violations, "trace": trace_text,
            "input_sha256": before}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command-template", help="argv string with one {input} placeholder")
    parser.add_argument("--pin", default="unavailable")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"at_utc": datetime.now(timezone.utc).isoformat(), "pin": args.pin,
              "platform": platform.platform(), "topology": "one-host syscall fixture"}
    if not args.command_template:
        result.update(status="skipped", reason="no exact-pin CLI command supplied")
    elif platform.system() != "Linux" or not shutil.which("strace"):
        result.update(status="skipped", reason="unprivileged Linux with strace required")
    elif os.geteuid() == 0:
        result.update(status="skipped", reason="run as an ordinary unprivileged user")
    else:
        with TemporaryDirectory(prefix="aegis-cli-safety-") as directory:
            root = Path(directory)
            cases = [run_case(args.command_template, name, payload, root, args.timeout)
                     for name, payload in MALFORMED.items()]
        result.update(status="executed", cases=cases,
                      summary={key: sum(row["status"] == key for row in cases)
                               for key in ("pass", "fail", "inconclusive")})
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "summary": result.get("summary")}))


if __name__ == "__main__":
    main()
