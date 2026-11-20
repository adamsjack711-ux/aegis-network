"""Bounded observation of an enrolled disposable Linux snapshot, without subprocesses."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import select
import stat
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

MAX_SOURCE = 1024 * 1024
MAX_RESULT = 8192
MAX_ROWS = 4096
MAX_PORTS = 128
MAX_SECONDS = 3.0
_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z", re.ASCII)
_UNIT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}\.service\Z", re.ASCII)
_VERSION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9.+:~_-]{0,127}\Z", re.ASCII)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class InspectPackage:
    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME.fullmatch(self.name):
            raise ValueError("invalid package name")


@dataclass(frozen=True)
class CheckService:
    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _UNIT.fullmatch(self.name):
            raise ValueError("invalid service name")


@dataclass(frozen=True)
class CheckListeningPorts:
    protocol: Literal["tcp", "tcp6", "both"] = "both"

    def __post_init__(self) -> None:
        if self.protocol not in ("tcp", "tcp6", "both"):
            raise ValueError("invalid protocol")


Arguments = InspectPackage | CheckService | CheckListeningPorts


@dataclass(frozen=True)
class DiagnosticRequest:
    operation: Literal["inspect_package", "check_service", "check_listening_ports"]
    arguments: Arguments

    def __post_init__(self) -> None:
        types = {
            "inspect_package": InspectPackage,
            "check_service": CheckService,
            "check_listening_ports": CheckListeningPorts,
        }
        if self.operation not in types or type(self.arguments) is not types[self.operation]:
            raise ValueError("unsupported operation or malformed arguments")

    def digest(self) -> str:
        return _sha(_canonical({"operation": self.operation, "arguments": asdict(self.arguments)}))


@dataclass(frozen=True)
class DiagnosticResult:
    kind: Literal["DiagnosticResult.local-prototype-v0"]
    operation: str
    outcome: Literal["observed", "not-observed", "inconclusive", "rejected"]
    reason: str
    target_id: str
    request_sha256: str
    source_sha256: dict[str, str]
    implementation_sha256: str
    started_at: str
    finished_at: str
    elapsed_ms: float
    data: dict[str, object]
    independent_status: Literal["unknown"] = "unknown"

    def to_json(self) -> str:
        return _canonical(asdict(self)).decode("ascii")


@dataclass(eq=False)
class _Grant:
    secret: object = field(repr=False)
    request_sha256: str
    pid: int
    uid: int
    deadline: float
    used: bool = False


class _Incomplete(Exception):
    def __init__(self, reason: str):
        self.reason = reason


class LocalDiagnosticService:
    """One-process local library. The root must be an operator-owned fixture directory."""

    def __init__(self, fixture_root: Path):
        root = Path(fixture_root)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("fixture root must be an owned, non-writable-by-others directory")
        self._root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened = os.fstat(self._root_fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(self._root_fd)
            raise ValueError("fixture root changed")
        self._target_id = _sha(f"fixture:{opened.st_dev}:{opened.st_ino}".encode())
        self._secret = object()
        self._lock = threading.Lock()
        self._grants: set[_Grant] = set()
        self._code_sha = _sha(Path(__file__).read_bytes())

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1
        self._grants.clear()

    def __enter__(self) -> LocalDiagnosticService:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def authorize(self, request: DiagnosticRequest, *, tty_fd: int | None = None) -> _Grant:
        """Mint one run grant after an explicit yes on a local TTY. Never serialize it."""
        if type(request) is not DiagnosticRequest or os.getuid() != os.geteuid() or os.geteuid() == 0:
            raise PermissionError("unprivileged local operator required")
        if self._root_fd < 0:
            raise PermissionError("diagnostic service is closed")
        owned_fd = tty_fd is None
        fd = os.open("/dev/tty", os.O_RDWR | os.O_CLOEXEC) if owned_fd else tty_fd
        try:
            if not os.isatty(fd):
                raise PermissionError("local terminal required")
            prompt = f"AEGIS fixture diagnostic {request.operation} ({request.digest()[:12]})? Type yes: "
            os.write(fd, prompt.encode("ascii"))
            answer = bytearray()
            deadline = time.monotonic() + 30
            while len(answer) < 8:
                if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                    raise PermissionError("operator consent timed out")
                ch = os.read(fd, 1)
                if not ch or ch == b"\n":
                    break
                answer.extend(ch)
            if answer != b"yes":
                raise PermissionError("operator consent declined")
        finally:
            if owned_fd:
                os.close(fd)
        grant = _Grant(self._secret, request.digest(), os.getpid(), os.geteuid(), time.monotonic() + 30)
        with self._lock:
            now = time.monotonic()
            self._grants = {item for item in self._grants if not item.used and item.deadline >= now}
            if len(self._grants) >= 16:
                raise PermissionError("too many pending local grants")
            self._grants.add(grant)
        return grant

    def run(
        self, request: DiagnosticRequest, grant: _Grant | None,
        *, cancel: threading.Event | None = None, timeout: float = MAX_SECONDS,
    ) -> DiagnosticResult:
        start = time.monotonic()
        started_at = datetime.now(timezone.utc).isoformat()
        request_hash = request.digest() if type(request) is DiagnosticRequest else ""
        source_hashes: dict[str, str] = {}
        outcome: Literal["observed", "not-observed", "inconclusive", "rejected"] = "rejected"
        reason = "invalid-authorization"
        data: dict[str, object] = {}
        with self._lock:
            valid = (
                type(request) is DiagnosticRequest and type(grant) is _Grant
                and grant in self._grants and grant.secret is self._secret and not grant.used
                and grant.pid == os.getpid() and grant.uid == os.geteuid()
                and grant.request_sha256 == request_hash and start <= grant.deadline
                and self._root_fd >= 0
            )
            if type(grant) is _Grant and grant in self._grants:
                self._grants.remove(grant)
                grant.used = True
        if valid:
            try:
                if _sha(Path(__file__).read_bytes()) != self._code_sha:
                    raise _Incomplete("implementation-changed")
                if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                        or not 0 < timeout <= MAX_SECONDS):
                    raise _Incomplete("invalid-budget")
                deadline = start + timeout
                self._check(deadline, cancel)
                if request.operation == "inspect_package":
                    outcome, reason, data = self._package(request.arguments, deadline, cancel, source_hashes)
                elif request.operation == "check_service":
                    outcome, reason, data = self._service(request.arguments, deadline, cancel, source_hashes)
                else:
                    outcome, reason, data = self._ports(request.arguments, deadline, cancel, source_hashes)
                self._check(deadline, cancel)
                if len(_canonical(data)) > MAX_RESULT:
                    raise _Incomplete("output-limit")
            except _Incomplete as exc:
                outcome, reason, data = "inconclusive", exc.reason, {}
            except (OSError, ValueError, UnicodeError, TypeError, KeyError, json.JSONDecodeError):
                outcome, reason, data = "inconclusive", "invalid-or-unavailable-snapshot", {}
        finished_at = datetime.now(timezone.utc).isoformat()
        return DiagnosticResult(
            "DiagnosticResult.local-prototype-v0", request.operation if type(request) is DiagnosticRequest else "invalid",
            outcome, reason, self._target_id, request_hash, source_hashes, self._code_sha,
            started_at, finished_at, round((time.monotonic() - start) * 1000, 3), data,
        )

    @staticmethod
    def _check(deadline: float, cancel: threading.Event | None) -> None:
        if cancel is not None and cancel.is_set():
            raise _Incomplete("cancelled")
        if time.monotonic() >= deadline:
            raise _Incomplete("timeout")

    def _read(self, relative: str, deadline: float, cancel: threading.Event | None, hashes: dict[str, str]) -> bytes:
        current = os.dup(self._root_fd)
        try:
            parts = relative.split("/")
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
                directory = os.fstat(next_fd)
                if directory.st_uid != os.geteuid() or directory.st_mode & 0o022:
                    os.close(next_fd)
                    raise _Incomplete("invalid-source-directory")
                os.close(current)
                current = next_fd
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=current)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                        or before.st_mode & 0o022 or before.st_size > MAX_SOURCE or before.st_nlink != 1):
                    raise _Incomplete("invalid-source")
                chunks = bytearray()
                while True:
                    self._check(deadline, cancel)
                    part = os.read(fd, min(65536, MAX_SOURCE + 1 - len(chunks)))
                    if not part:
                        break
                    chunks.extend(part)
                    if len(chunks) > MAX_SOURCE:
                        raise _Incomplete("input-limit")
                after = os.fstat(fd)
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
                ):
                    raise _Incomplete("source-changed")
                result = bytes(chunks)
                hashes[relative] = _sha(result)
                return result
            finally:
                os.close(fd)
        finally:
            os.close(current)

    def _package(self, args: InspectPackage, deadline: float, cancel: threading.Event | None, hashes: dict[str, str]):
        raw = self._read("dpkg/status", deadline, cancel, hashes)
        if raw and not raw.endswith(b"\n\n"):
            raise _Incomplete("partial-snapshot")
        found = None
        count = 0
        for block in raw.decode("utf-8").split("\n\n"):
            self._check(deadline, cancel)
            if not block.strip():
                continue
            count += 1
            if count > MAX_ROWS:
                raise _Incomplete("row-limit")
            fields: dict[str, str] = {}
            for line in block.splitlines():
                if line.startswith(" "):
                    continue
                key, sep, value = line.partition(": ")
                if not sep or key in fields:
                    raise ValueError("invalid dpkg stanza")
                if key in ("Package", "Version", "Status"):
                    fields[key] = value
            if fields.get("Package") == args.name:
                if found is not None:
                    raise ValueError("duplicate package")
                version = fields.get("Version", "")
                if not _VERSION.fullmatch(version):
                    raise ValueError("invalid version")
                found = {"name": args.name, "version": version, "installed": fields.get("Status") == "install ok installed"}
        if found is None:
            return "not-observed", "package-absent-in-snapshot", {"name": args.name, "installed": False}
        return ("observed" if found["installed"] else "not-observed", "package-state-in-snapshot", found)

    def _service(self, args: CheckService, deadline: float, cancel: threading.Event | None, hashes: dict[str, str]):
        raw = self._read("systemd/units.json", deadline, cancel, hashes)
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result
        units = json.loads(raw, object_pairs_hook=pairs)
        if type(units) is not dict or len(units) > MAX_ROWS:
            raise ValueError("invalid service snapshot")
        for name, state in units.items():
            if not isinstance(name, str) or not _UNIT.fullmatch(name) or type(state) is not bool:
                raise ValueError("invalid service record")
        if args.name not in units:
            return "not-observed", "service-absent-in-snapshot", {"name": args.name, "active": False}
        active = units[args.name]
        return ("observed" if active else "not-observed", "service-state-in-snapshot", {"name": args.name, "active": active})

    def _ports(self, args: CheckListeningPorts, deadline: float, cancel: threading.Event | None, hashes: dict[str, str]):
        protocols = ("tcp", "tcp6") if args.protocol == "both" else (args.protocol,)
        ports: set[tuple[str, int]] = set()
        for protocol in protocols:
            raw = self._read(f"proc/net/{protocol}", deadline, cancel, hashes)
            if raw and not raw.endswith(b"\n"):
                raise _Incomplete("partial-snapshot")
            lines = raw.decode("ascii").splitlines()
            if not lines or len(lines) > MAX_ROWS + 1 or "local_address" not in lines[0]:
                raise ValueError("invalid proc header")
            for line in lines[1:]:
                self._check(deadline, cancel)
                cells = line.split()
                if len(cells) < 4 or cells[3] not in ("0A", "01", "06", "07", "08", "09", "0B"):
                    raise ValueError("invalid proc row")
                if cells[3] == "0A":
                    address, sep, port_hex = cells[1].rpartition(":")
                    if not sep or not address or len(port_hex) != 4:
                        raise ValueError("invalid proc address")
                    port = int(port_hex, 16)
                    if not 0 < port <= 65535:
                        raise ValueError("invalid port")
                    ports.add((protocol, port))
                    if len(ports) > MAX_PORTS:
                        raise _Incomplete("output-limit")
        records = [{"protocol": protocol, "port": port} for protocol, port in sorted(ports)]
        return ("observed" if records else "not-observed", "listening-ports-in-snapshot", {"ports": records})
