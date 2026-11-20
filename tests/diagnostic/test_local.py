"""Disposable non-root Linux snapshot checks; also runnable on a developer host."""

import json
import os
import pty
import stat
import threading
from pathlib import Path

import pytest

from aegis.diagnostic import (
    CheckListeningPorts, CheckService, DiagnosticRequest, InspectPackage, LocalDiagnosticService,
)


@pytest.fixture
def fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "snapshot"
    for directory in ("dpkg", "systemd", "proc/net"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "dpkg/status").write_text(
        "Package: alpha\nVersion: 1.2-3\nStatus: install ok installed\n"
        "Description: FAKE_SECRET_CANARY\n\nPackage: beta\nVersion: 2\n"
        "Status: deinstall ok config-files\n\n", encoding="utf-8"
    )
    (root / "systemd/units.json").write_text('{"alpha.service":true,"beta.service":false}')
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    (root / "proc/net/tcp").write_text(header + "   0: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 0\n")
    (root / "proc/net/tcp6").write_text(header)
    return root


def consent(service, request):
    master, slave = pty.openpty()
    try:
        os.write(master, b"yes\n")
        return service.authorize(request, tty_fd=slave)
    finally:
        os.close(master)
        os.close(slave)


def tree_state(root):
    return {
        str(path.relative_to(root)): (stat.S_IMODE(path.lstat().st_mode), path.lstat().st_size,
                                      path.lstat().st_mtime_ns, path.read_bytes() if path.is_file() else None)
        for path in root.rglob("*")
    }


@pytest.mark.parametrize("operation,args,expected", [
    ("inspect_package", InspectPackage("alpha"), "observed"),
    ("inspect_package", InspectPackage("missing"), "not-observed"),
    ("check_service", CheckService("alpha.service"), "observed"),
    ("check_service", CheckService("beta.service"), "not-observed"),
    ("check_listening_ports", CheckListeningPorts(), "observed"),
])
def test_operations_are_local_bounded_and_read_only(fixture_root, operation, args, expected):
    before = tree_state(fixture_root)
    request = DiagnosticRequest(operation, args)
    with LocalDiagnosticService(fixture_root) as service:
        result = service.run(request, consent(service, request))
    assert result.outcome == expected
    assert result.independent_status == "unknown"
    assert result.kind == "DiagnosticResult.local-prototype-v0"
    assert result.source_sha256 and result.started_at and result.finished_at
    assert "FAKE_SECRET_CANARY" not in result.to_json()
    assert "0100007F" not in result.to_json()
    assert len(result.to_json().encode()) < 8192
    assert tree_state(fixture_root) == before


def test_validation_rejects_commands_and_unknown_operations():
    with pytest.raises(ValueError):
        InspectPackage("alpha; id")
    with pytest.raises(ValueError):
        InspectPackage("--help")
    with pytest.raises(ValueError):
        InspectPackage("a" * 129)
    with pytest.raises(ValueError):
        CheckService("../alpha.service")
    with pytest.raises(ValueError):
        CheckListeningPorts("udp")
    with pytest.raises(ValueError):
        DiagnosticRequest("execute", InspectPackage("alpha"))
    with pytest.raises(ValueError):
        DiagnosticRequest("inspect_package", CheckService("alpha.service"))
    with pytest.raises(TypeError):
        InspectPackage(name="alpha", command="id")


def test_consent_is_required_bound_and_one_use(fixture_root):
    package = DiagnosticRequest("inspect_package", InspectPackage("alpha"))
    service_request = DiagnosticRequest("check_service", CheckService("alpha.service"))
    with LocalDiagnosticService(fixture_root) as service:
        assert service.run(package, None).outcome == "rejected"
        grant = consent(service, package)
        assert service.run(service_request, grant).outcome == "rejected"
        assert service.run(package, grant).outcome == "rejected"
        grant = consent(service, package)
        assert service.run(package, grant).outcome == "observed"
        assert service.run(package, grant).outcome == "rejected"
        master, slave = os.pipe()
        try:
            with pytest.raises(PermissionError):
                service.authorize(package, tty_fd=slave)
        finally:
            os.close(master)
            os.close(slave)


def test_denied_consent(fixture_root):
    request = DiagnosticRequest("inspect_package", InspectPackage("alpha"))
    with LocalDiagnosticService(fixture_root) as service:
        master, slave = pty.openpty()
        try:
            os.write(master, b"no\n")
            with pytest.raises(PermissionError):
                service.authorize(request, tty_fd=slave)
        finally:
            os.close(master)
            os.close(slave)


def test_source_restrictions_and_malformed_snapshot(fixture_root, tmp_path):
    request = DiagnosticRequest("inspect_package", InspectPackage("alpha"))
    with LocalDiagnosticService(fixture_root) as service:
        status = fixture_root / "dpkg/status"
        status.unlink()
        status.symlink_to(tmp_path / "outside")
        assert service.run(request, consent(service, request)).outcome == "inconclusive"
        status.unlink()
        status.write_bytes(b"x" * (1024 * 1024 + 1))
        assert service.run(request, consent(service, request)).outcome == "inconclusive"
        status.write_text("Package: alpha\nPackage: alpha\nVersion: 1\n")
        assert service.run(request, consent(service, request)).outcome == "inconclusive"
        status.write_text("Package: alpha\nVersion: 1\nStatus: install ok installed\n")
        assert service.run(request, consent(service, request)).reason == "partial-snapshot"
        status.chmod(0o666)
        assert service.run(request, consent(service, request)).reason == "invalid-source"


def test_grant_is_bound_to_service_instance(fixture_root):
    request = DiagnosticRequest("inspect_package", InspectPackage("alpha"))
    with LocalDiagnosticService(fixture_root) as first, LocalDiagnosticService(fixture_root) as second:
        grant = consent(first, request)
        assert second.run(request, grant).outcome == "rejected"
        assert first.run(request, grant).outcome == "observed"


def test_duplicate_service_key_and_port_flood(fixture_root):
    unit = fixture_root / "systemd/units.json"
    unit.write_text('{"alpha.service":true,"alpha.service":false}')
    service_request = DiagnosticRequest("check_service", CheckService("alpha.service"))
    ports_request = DiagnosticRequest("check_listening_ports", CheckListeningPorts("tcp"))
    with LocalDiagnosticService(fixture_root) as service:
        assert service.run(service_request, consent(service, service_request)).outcome == "inconclusive"
        header = (fixture_root / "proc/net/tcp").read_text().splitlines()[0] + "\n"
        rows = "".join(f"{i}: 0100007F:{i+1:04X} 00000000:0000 0A 0 0 0 0 0 0\n" for i in range(129))
        (fixture_root / "proc/net/tcp").write_text(header + rows)
        result = service.run(ports_request, consent(service, ports_request))
        assert result.outcome == "inconclusive" and result.reason == "output-limit"
        assert result.data == {}


def test_timeout_and_cancellation(fixture_root):
    request = DiagnosticRequest("inspect_package", InspectPackage("alpha"))
    with LocalDiagnosticService(fixture_root) as service:
        cancelled = threading.Event()
        cancelled.set()
        result = service.run(request, consent(service, request), cancel=cancelled)
        assert (result.outcome, result.reason) == ("inconclusive", "cancelled")
        result = service.run(request, consent(service, request), timeout=1e-12)
        assert (result.outcome, result.reason) == ("inconclusive", "timeout")
        for malformed in (float("nan"), True, "3"):
            result = service.run(request, consent(service, request), timeout=malformed)
            assert (result.outcome, result.reason) == ("inconclusive", "invalid-budget")


def test_no_network_or_process_primitives_in_runner():
    source = Path(__file__).parents[2] / "src/aegis/diagnostic/local.py"
    import ast
    tree = ast.parse(source.read_text())
    imports = {alias.name.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in
               (node.names if isinstance(node, ast.Import) else [ast.alias(name=node.module or "")])}
    assert not imports.intersection({"subprocess", "socket", "urllib", "requests", "httpx"})


def test_result_cannot_be_used_as_signed_or_native_evidence(fixture_root):
    from pydantic import ValidationError
    from aegis.artifact import SignedFinding
    from aegis.evidence.records import Attestation, Manifest

    request = DiagnosticRequest("inspect_package", InspectPackage("alpha"))
    with LocalDiagnosticService(fixture_root) as service:
        data = json.loads(service.run(request, consent(service, request)).to_json())
    for authority_model in (SignedFinding, Attestation, Manifest):
        with pytest.raises(ValidationError):
            authority_model.model_validate(data)
