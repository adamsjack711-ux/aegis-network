"""Independent read-only appraisal of installed CLI syscall and tree evidence.

The analyzer never executes an installed CLI. Missing or malformed evidence is
inconclusive. Attempted effects count even when the kernel denies them.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import stat
from pathlib import Path


WRITE_OPEN = {"open", "openat", "openat2", "creat"}
WRITE_FLAGS = re.compile(r"\b(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b")
MUTATION = {
    "rename", "renameat", "renameat2", "unlink", "unlinkat", "mkdir",
    "mkdirat", "rmdir", "chmod", "fchmod", "fchmodat", "chown", "lchown",
    "fchown", "fchownat", "truncate", "ftruncate", "symlink",
    "symlinkat", "link", "linkat", "mknod", "mknodat", "utime",
    "utimes", "futimesat", "utimensat", "fallocate", "mount", "umount2",
}
NETWORK = {
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
}
PROCESS = {"clone", "clone3", "fork", "vfork", "execve", "execveat"}
PRIVILEGE = {
    "setuid", "seteuid", "setreuid", "setresuid", "setgid", "setegid",
    "setregid", "setresgid", "setgroups", "capset", "setns", "unshare",
    "ptrace", "chroot", "pivot_root", "prctl",
}
CALL = re.compile(r"(?:^|\s)([a-z][a-z0-9_]*)\(")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
ERRNO = re.compile(r"= -1 ([A-Z][A-Z0-9_]+)")
INITIAL_EXEC = ("/tmp/venv/bin/aegis", "/usr/bin/env", "/tmp/venv/bin/python")
MAX_DECOMPRESSED = 100_000_000
CASE_NAMES = {
    "doctor", "inventory", "status", "explain", "no-feed", "current",
    "future", "expired", "withdrawn", "revoked", "conflict", "missing",
    "malformed", "range", "grant", "signature", "duplicate",
    "create", "repeat", "ancestor", "final",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def event(line: str) -> dict | None:
    found = CALL.search(line)
    if not found:
        return None
    name = found.group(1)
    if name in WRITE_OPEN and WRITE_FLAGS.search(line):
        category = "write_open"
    elif name in MUTATION:
        category = "file_mutation"
    elif name in NETWORK:
        category = "network"
    elif name in PROCESS:
        category = "process"
    elif name in PRIVILEGE:
        category = "privilege"
    else:
        return None
    quoted = QUOTED.search(line)
    path = quoted.group(1) if quoted else None
    errno = ERRNO.search(line)
    return {"category": category, "syscall": name, "path": path,
            "errno": errno.group(1) if errno else None,
            "unfinished": "<unfinished ...>" in line,
            "line_sha256": sha(line.encode())}


def case_kind(stem: str) -> str:
    if any(word in stem for word in ("create", "repeat", "ancestor", "final")):
        return "explicit_state"
    return "default_or_error"


def read_trace(path: Path) -> tuple[list[dict], dict]:
    raw = path.read_bytes()
    if len(raw) > 50_000_000:
        raise ValueError("compressed trace exceeds 50 MB")
    with gzip.open(path, "rb") as handle:
        data = handle.read(MAX_DECOMPRESSED + 1)
    if len(data) > MAX_DECOMPRESSED:
        raise ValueError("decompressed trace exceeds 100 MB")
    text = data.decode("utf-8", errors="replace")
    if not text.strip() or not ("+++ exited with" in text or "+++ killed by" in text):
        raise ValueError("trace missing completion marker")
    records = [item for line in text.splitlines() if (item := event(line))]
    return records, {"sha256": sha(raw), "lines": len(text.splitlines()),
                     "bytes": len(raw), "decode_replacements": text.count("\ufffd")}


def read_tree(cell: Path, digest: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid tree digest")
    path = cell / f"tree-{digest}.json.gz"
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"full tree manifest missing: {digest}")
    if path.stat().st_size > 50_000_000:
        raise ValueError("compressed tree exceeds 50 MB")
    with gzip.open(path, "rb") as handle:
        data = handle.read(MAX_DECOMPRESSED + 1)
    if len(data) > MAX_DECOMPRESSED or sha(data) != digest:
        raise ValueError("full tree manifest size/digest mismatch")
    tree = json.loads(data)
    if not isinstance(tree, dict):
        raise ValueError("full tree manifest is not an object")
    return tree


def analyze_case(path: Path) -> dict:
    result = {"cell": path.parent.name, "case": path.stem, "status": "inconclusive",
              "reasons": [], "counts": {}, "denied_counts": {}, "samples": []}
    try:
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict):
            raise ValueError("case JSON is not an object")
        trace_path = path.with_suffix(".trace.gz")
        if not trace_path.is_file() or trace_path.is_symlink():
            raise ValueError("paired trace missing or symlink")
        records, trace = read_trace(trace_path)
        result["trace"] = trace
        change = payload.get("change")
        if not isinstance(change, dict) or not all(
            isinstance(pair, list) and len(pair) == 2 for pair in change.values()
        ):
            raise ValueError("mount change map missing or invalid")
        if not isinstance(payload.get("before_sha256"), str) or not isinstance(payload.get("after_sha256"), str):
            raise ValueError("mount snapshot hashes missing")
        before = read_tree(path.parent, payload["before_sha256"])
        after = read_tree(path.parent, payload["after_sha256"])
        reconstructed = {key: [before.get(key), after.get(key)]
                         for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
        if reconstructed != change:
            raise ValueError("mount change map differs from full manifests")
        result["mount_before_sha256"] = payload["before_sha256"]
        result["mount_after_sha256"] = payload["after_sha256"]
        result["manifest_entries"] = {"before": len(before), "after": len(after)}
        result["changed_paths"] = sorted(change)
        result["changed_count"] = len(change)
        result["kind"] = case_kind(path.stem)
        result["exit_code"] = payload.get("rc")
        result["counts"] = {kind: sum(x["category"] == kind for x in records)
                            for kind in ("write_open", "file_mutation", "network", "process", "privilege")}
        result["denied_counts"] = {kind: sum(x["category"] == kind and x["errno"] is not None for x in records)
                                   for kind in result["counts"]}
        for item in records[:20]:
            # Avoid copying arguments, env, grant contents, or full trace lines.
            result["samples"].append(item)
        extra_exec = [x for x in records if x["category"] == "process" and
                      (x["syscall"] not in {"execve", "execveat"} or
                       not x["path"] or not x["path"].startswith(INITIAL_EXEC))]
        write_attempts = [x for x in records if x["category"] in {"write_open", "file_mutation"}]
        cache_attempts = [x for x in write_attempts if "__pycache__" in (x["path"] or "")]
        result["runtime_cache_write_attempts"] = len(cache_attempts)
        result["runtime_cache_errno_counts"] = {
            errno: sum((x["errno"] or "none") == errno for x in cache_attempts)
            for errno in sorted({x["errno"] or "none" for x in cache_attempts})
        }
        result["other_write_attempts"] = len(write_attempts) - len(cache_attempts)
        network = [x for x in records if x["category"] == "network"]
        privilege = [x for x in records if x["category"] == "privilege"]
        if trace["decode_replacements"]:
            result["reasons"].append("trace decode replacements")
        if cache_attempts:
            result["status"] = "fail"
            result["reasons"].append("unrequested CPython bytecode-cache write attempts")
        elif result["kind"] == "explicit_state":
            allowed = {"/tmp", "/tmp/chosen", "/tmp/chosen/identity.json"} if path.stem.startswith("create-") else set()
            if "--state-dir" not in payload.get("argv", []):
                result["status"] = "fail"
                result["reasons"].append("explicit state lacks recorded opt-in argument")
            elif set(change) - allowed or network or privilege or extra_exec:
                result["status"] = "fail"
                result["reasons"].append("explicit state had unexpected tree/process/network/privilege effect")
            elif path.stem.startswith("create-"):
                directory = after.get("/tmp/chosen")
                identity = after.get("/tmp/chosen/identity.json")
                if (not directory or not identity or stat.S_IMODE(directory[0]) != 0o700
                        or stat.S_IMODE(identity[0]) != 0o600):
                    result["status"] = "fail"
                    result["reasons"].append("explicit state mode is not 0700/0600")
                else:
                    result["status"] = "review"
                    result["reasons"].append("authorized creation; inspect exact write attempts and persisted identity")
            elif change or payload["before_sha256"] != payload["after_sha256"]:
                result["status"] = "fail"
                result["reasons"].append("explicit repeat/error changed tree")
            else:
                result["status"] = "review"
                result["reasons"].append("verify scoped EEXIST attempts and symlink denial")
        elif result["changed_count"] or payload["before_sha256"] != payload["after_sha256"]:
            result["status"] = "fail"
            result["reasons"].append("default/error mounted tree changed")
        elif write_attempts or network or privilege or extra_exec:
            result["status"] = "fail"
            result["reasons"].append("attempted write/network/privilege/extra process effect")
        elif result["reasons"]:
            result["status"] = "inconclusive"
        else:
            result["status"] = "pass"
    except (OSError, ValueError, EOFError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
        result["reasons"].append(type(exc).__name__ + ": " + str(exc))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console-root", type=Path, default=Path("validation/console"))
    parser.add_argument("--output", type=Path, default=Path("validation/privacy/analysis.json"))
    args = parser.parse_args()
    cases = sorted(path for path in args.console_root.glob("*/*.json")
                   if path.stem.endswith(("-json", "-human"))
                   and path.stem.rsplit("-", 1)[0] in CASE_NAMES)
    rows = [analyze_case(path) for path in cases]
    report = {"schema": "aegis-installed-privacy-analysis-v1", "case_count": len(rows),
              "cases": rows, "counts": {status: sum(row["status"] == status for row in rows)
                                      for status in ("pass", "fail", "review", "inconclusive")}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
