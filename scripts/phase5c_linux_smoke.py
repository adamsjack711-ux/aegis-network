"""Offline, stdlib-only Linux smoke and preliminary resource/privacy measurement."""

import hashlib
import json
import os
import platform
import pty
import resource
import tempfile
import threading
import time
import tracemalloc
from pathlib import Path

from aegis.diagnostic import (
    CheckListeningPorts, CheckService, DiagnosticRequest, InspectPackage, LocalDiagnosticService,
)


def grant(service, request):
    master, slave = pty.openpty()
    try:
        os.write(master, b"yes\n")
        return service.authorize(request, tty_fd=slave)
    finally:
        os.close(master)
        os.close(slave)


def tree_digest(root):
    hashed = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        hashed.update(str(path.relative_to(root)).encode())
        hashed.update(str((info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns)).encode())
        if path.is_file():
            hashed.update(path.read_bytes())
    return hashed.hexdigest()


def fixture(root):
    for name in ("dpkg", "systemd", "proc/net"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "dpkg/status").write_text(
        "Package: alpha\nVersion: 1.2-3\nStatus: install ok installed\n"
        "Description: FAKE_SECRET_CANARY\n\n", encoding="utf-8"
    )
    (root / "systemd/units.json").write_text('{"alpha.service":true}')
    header = "sl local_address rem_address st\n"
    (root / "proc/net/tcp").write_text(header + "0: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 0\n")
    (root / "proc/net/tcp6").write_text(header)


def main():
    assert platform.system() == "Linux" and os.geteuid() != 0
    with tempfile.TemporaryDirectory(prefix="aegis-5c-") as temporary:
        root = Path(temporary) / "snapshot"
        root.mkdir(mode=0o700)
        fixture(root)
        before = tree_digest(root)
        requests = [
            DiagnosticRequest("inspect_package", InspectPackage("alpha")),
            DiagnosticRequest("check_service", CheckService("alpha.service")),
            DiagnosticRequest("check_listening_ports", CheckListeningPorts()),
        ]
        elapsed = []
        outputs = []
        tracemalloc.start()
        cpu_before = resource.getrusage(resource.RUSAGE_SELF)
        with LocalDiagnosticService(root) as service:
            for _ in range(10):
                for request in requests:
                    start = time.perf_counter_ns()
                    result = service.run(request, grant(service, request))
                    elapsed.append((time.perf_counter_ns() - start) / 1e6)
                    output = result.to_json()
                    outputs.append(len(output.encode()))
                    assert result.outcome == "observed"
                    assert result.independent_status == "unknown"
                    assert "FAKE_SECRET_CANARY" not in output
                    assert "0100007F" not in output
                    assert len(output) < 8192
                    assert tree_digest(root) == before
            assert service.run(requests[0], None).outcome == "rejected"
            cancelled = threading.Event()
            cancelled.set()
            assert service.run(requests[0], grant(service, requests[0]), cancel=cancelled).reason == "cancelled"
            assert service.run(requests[0], grant(service, requests[0]), timeout=1e-12).reason == "timeout"
            try:
                InspectPackage("alpha; id")
            except ValueError:
                pass
            else:
                raise AssertionError("shell metacharacters accepted")
        cpu_after = resource.getrusage(resource.RUSAGE_SELF)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        with LocalDiagnosticService(root) as service:
            status = root / "dpkg/status"
            status.unlink()
            status.symlink_to(root / "systemd/units.json")
            assert service.run(requests[0], grant(service, requests[0])).outcome == "inconclusive"
            status.unlink()
            status.write_bytes(b"x" * (1024 * 1024 + 1))
            assert service.run(requests[0], grant(service, requests[0])).outcome == "inconclusive"
            unit = root / "systemd/units.json"
            unit.write_text('{"alpha.service":true,"alpha.service":false}')
            assert service.run(requests[1], grant(service, requests[1])).outcome == "inconclusive"
            header = (root / "proc/net/tcp").read_text().splitlines()[0] + "\n"
            rows = "".join(f"{i}: 0100007F:{i+1:04X} 00000000:0000 0A 0 0 0 0 0 0\n" for i in range(129))
            (root / "proc/net/tcp").write_text(header + rows)
            assert service.run(requests[2], grant(service, requests[2])).reason == "output-limit"
        elapsed.sort()
        print(json.dumps({
            "image_fixture": "offline non-root Linux",
            "kernel": platform.release(), "python": platform.python_version(),
            "uid": os.geteuid(), "trial_count": len(elapsed),
            "request_to_result_ms": {"p50": elapsed[14], "p95": elapsed[28], "max": elapsed[-1]},
            "cpu_user_ms": round((cpu_after.ru_utime - cpu_before.ru_utime) * 1000, 3),
            "cpu_system_ms": round((cpu_after.ru_stime - cpu_before.ru_stime) * 1000, 3),
            "python_peak_allocated_bytes": peak,
            "process_peak_rss_kib": cpu_after.ru_maxrss,
            "max_result_bytes": max(outputs), "host_fixture_write_count": 0,
            "secret_canary_exposed": False, "network_access": "disabled by container",
            "adversarial_checks": ["no-grant", "malformed-argument", "cancel", "timeout", "symlink", "oversize-source", "duplicate-key", "output-flood"],
        }, sort_keys=True))


if __name__ == "__main__":
    main()
