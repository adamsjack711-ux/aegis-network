"""Trace CLI default, conservative failure, and explicit-state paths."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "benchmarks/alpha-cli-privacy"
TRACE = EVIDENCE / "traces"
INPUT = EVIDENCE / "inputs"
IMAGE = "aegis-alpha-cli-privacy:local"
FIX = "/src/fixtures/phase-next-cli"


def digest_tree(path: Path) -> list[dict]:
    result = []
    if not path.exists():
        return result
    for item in sorted(path.rglob("*")):
        stat = item.lstat()
        result.append({
            "path": str(item.relative_to(path)), "mode": oct(stat.st_mode & 0o777),
            "size": stat.st_size, "sha256": hashlib.sha256(item.read_bytes()).hexdigest()
            if item.is_file() and not item.is_symlink() else None,
        })
    return result


def run_case(name: str, argv: list[str], *, state: bool = False) -> dict:
    before = digest_tree(INPUT)
    command = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--user", "1000:1000", "--cap-drop", "ALL",
        "--security-opt", "seccomp=unconfined", "--security-opt", "no-new-privileges",
        "-v", f"{ROOT}:/src:ro",
        "-v", f"{ROOT / 'fixtures/phase-next-cli/dpkg-status'}:/var/lib/dpkg/status:ro",
        "-v", f"{TRACE}:/trace:rw",
    ]
    if state:
        command += ["-v", f"{EVIDENCE / 'state'}:/state:rw"]
    command += [IMAGE, "strace", "-ff", "-qq", "-e", "trace=file,network,process",
                "-o", f"/trace/{name}.trace", "python", "-m", "aegis.cli", *argv]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    (TRACE / f"{name}.stdout").write_text(stdout)
    (TRACE / f"{name}.stderr").write_text(stderr)
    (TRACE / f"{name}.exit").write_text(f"{result.returncode}\n")
    files = sorted(TRACE.glob(f"{name}.trace.*"))
    lines = [line for file in files for line in file.read_text(errors="replace").splitlines()]
    network = [line for line in lines if re.search(r"\b(socket|connect|sendto|sendmsg|sendmmsg)\(", line)]
    writes = [line for line in lines if (
        re.search(r"\b(open|openat|openat2|creat)\(.*\b(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b", line)
        or re.search(r"\b(mkdir|mkdirat|rename|renameat|unlink|unlinkat|rmdir|truncate|ftruncate|chmod|fchmod|chown|fchown|symlink|symlinkat|link|linkat)\(", line)
    )]
    execs = [line for line in lines if "execve(" in line]
    privilege = [line for line in lines if re.search(r"\b(setuid|setreuid|setresuid|setgid|setregid|setresgid|capset|setns|unshare|mount)\(", line)]
    parsed = None
    if stdout.lstrip().startswith("{"):
        try:
            parsed = json.loads(stdout)
        except ValueError:
            pass
    return {
        "case": name, "argv": argv, "exit_code": result.returncode,
        "trace_files": [str(file.relative_to(EVIDENCE)) for file in files],
        "trace_lines": len(lines), "network_attempts": network,
        "write_attempts": writes, "exec_attempts": execs,
        "privilege_attempts": privilege, "stderr": stderr,
        "input_tree_unchanged": digest_tree(INPUT) == before,
        "parsed_status": parsed.get("status") if parsed else None,
        "independent_status": parsed.get("independent_status") if parsed else None,
        "overall_assessment": parsed.get("overall_assessment") if parsed else None,
        "observation_count": parsed.get("observation_count") if parsed else None,
        "findings": parsed.get("findings") if parsed else None,
        "asset_id": parsed.get("asset_id") if parsed else None,
    }


def main() -> None:
    TRACE.mkdir(parents=True, exist_ok=True)
    os.chmod(TRACE, 0o777)
    INPUT.mkdir(parents=True, exist_ok=True)
    feed = json.loads((ROOT / "fixtures/phase-next-cli/signed-current.json").read_text())
    feed["events"][0]["finding"]["vulnerability_id"] = "AEGIS-TAMPERED"
    (INPUT / "tampered-signed-current.json").write_text(json.dumps(feed) + "\n")
    cases = [
        ("status-default", ["status", "--json"], False),
        ("inventory-default", ["inventory", "--json"], False),
        ("doctor-default", ["doctor", "--json"], False),
        ("findings-no-feed", ["findings", "--json"], False),
        ("explain-no-feed", ["explain", "absent", "--json"], False),
        ("findings-signed", ["findings", "--feed", f"{FIX}/signed-current.json", "--trust", f"{FIX}/trust.json", "--json"], False),
        ("status-signed", ["status", "--feed", f"{FIX}/signed-current.json", "--trust", f"{FIX}/trust.json", "--json"], False),
        ("findings-tampered", ["findings", "--feed", "/src/benchmarks/alpha-cli-privacy/inputs/tampered-signed-current.json", "--trust", f"{FIX}/trust.json", "--json"], False),
        ("findings-missing-trust", ["findings", "--feed", f"{FIX}/signed-current.json", "--json"], False),
        ("findings-malformed", ["findings", "--feed", f"{FIX}/malformed-feed.json", "--trust", f"{FIX}/trust.json", "--json"], False),
        ("findings-expired", ["findings", "--feed", f"{FIX}/signed-expired.json", "--trust", f"{FIX}/trust.json", "--json"], False),
        ("findings-withdrawn", ["findings", "--feed", f"{FIX}/signed-withdrawn.json", "--trust", f"{FIX}/trust.json", "--json"], False),
    ]
    state_dir = EVIDENCE / "state"
    if state_dir.exists() and any(state_dir.iterdir()):
        raise RuntimeError(f"remove disposable prior state before rerunning: {state_dir}")
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o777)
    (state_dir / "real").mkdir(exist_ok=True)
    for link in ("ancestor-link", "final-link"):
        path = state_dir / link
        if not path.exists() and not path.is_symlink():
            path.symlink_to(state_dir / "real", target_is_directory=True)
    cases += [
        ("state-first", ["--state-dir", "/state/chosen", "inventory", "--json"], True),
        ("state-repeat", ["--state-dir", "/state/chosen", "inventory", "--json"], True),
        ("state-ancestor-link", ["--state-dir", "/state/ancestor-link/chosen", "inventory", "--json"], True),
        ("state-final-link", ["--state-dir", "/state/final-link", "inventory", "--json"], True),
    ]
    results = []
    for name, argv, state in cases:
        row = run_case(name, argv, state=state)
        results.append(row)
        print(json.dumps({k: v for k, v in row.items() if k not in {"findings", "write_attempts", "exec_attempts"}}), flush=True)
    (EVIDENCE / "trace-results.json").write_text(json.dumps({"runs": results, "state_tree": digest_tree(state_dir)}, indent=2) + "\n")


if __name__ == "__main__":
    main()
