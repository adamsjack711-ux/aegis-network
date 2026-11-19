"""Pin and launch the built-in fixture verifier in a fresh process."""

import base64
import json
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ._portability_worker import FAMILY, HARNESSES
from ._worker import MAX_REQUEST
from .records import Manifest, Observation, decode, digest

WORKER = Path(__file__).with_name("_worker.py")
WORKER_SHA256 = digest(WORKER.read_bytes())
CHECK_SHA256 = digest(b"AEGIS-CHECK\x00" + bytes.fromhex(WORKER_SHA256))
ORACLE_SHA256 = digest(b"AEGIS-ORACLE\x00" + bytes.fromhex(WORKER_SHA256))
ENVIRONMENT_SHA256 = digest(json.dumps([
    "isolated-stdlib-process-v1", WORKER_SHA256, sys.implementation.name,
    platform.python_version(), platform.system(), platform.release(), platform.machine(),
], separators=(",", ":")).encode("ascii"))


@dataclass(frozen=True)
class WorkerProfile:
    environment_sha256: str
    check_sha256: str
    oracle_sha256: str

    @classmethod
    def from_manifest(cls, manifest: Manifest):
        return cls(manifest.environment_sha256, manifest.check_sha256, manifest.oracle_sha256)


LOCAL_PROFILE = WorkerProfile(ENVIRONMENT_SHA256, CHECK_SHA256, ORACLE_SHA256)

PORTABILITY_WORKER = WORKER.with_name("_portability_worker.py")
PORTABILITY_WORKER_SHA256 = digest(PORTABILITY_WORKER.read_bytes())
PORTABILITY_ENVIRONMENT = digest(
    b"AEGIS-PORTABILITY-ENVIRONMENT\x00" + bytes.fromhex(ENVIRONMENT_SHA256)
    + bytes.fromhex(PORTABILITY_WORKER_SHA256)
)
PORTABILITY_ORACLE = digest(b"AEGIS-PORTABILITY-ORACLE\x00" + bytes.fromhex(PORTABILITY_WORKER_SHA256))
PORTABILITY_PROFILES = {
    harness: WorkerProfile(
        PORTABILITY_ENVIRONMENT,
        digest(b"AEGIS-PORTABILITY-CHECK\x00" + bytes.fromhex(PORTABILITY_WORKER_SHA256) + harness.encode("ascii")),
        PORTABILITY_ORACLE,
    )
    for harness in HARNESSES
}


class WorkerFailure(Exception):
    """A process failed to provide a usable observation."""


def run(manifest: Manifest, objects: Mapping[str, bytes], timeout: float) -> Observation:
    profile = WorkerProfile.from_manifest(manifest)
    harness = None
    if manifest.family == FAMILY:
        harness = next((name for name, pin in PORTABILITY_PROFILES.items() if pin == profile), None)
        if harness is None:
            raise WorkerFailure("worker cannot reproduce the pinned portability environment")
    elif profile != LOCAL_PROFILE:
        raise WorkerFailure("worker cannot reproduce the pinned environment")
    request = json.dumps({
        "family": manifest.family,
        "objects": {role: base64.b64encode(data).decode("ascii") for role, data in objects.items()},
    }).encode("ascii")
    if len(request) > MAX_REQUEST:
        raise WorkerFailure("invalid worker request size")
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-evidence-") as directory:
            # Launch the exact inspected bytes from the disposable directory.
            worker_bytes = WORKER.read_bytes()
            if digest(worker_bytes) != WORKER_SHA256:
                raise WorkerFailure("worker implementation pin changed")
            executable = Path(directory) / "worker.py"
            executable.write_bytes(worker_bytes)
            command = [os.path.abspath(sys.executable), "-I", "-S"]
            if harness is None:
                command.append(str(executable))
            else:
                extended = PORTABILITY_WORKER.read_bytes()
                if digest(extended) != PORTABILITY_WORKER_SHA256:
                    raise WorkerFailure("portability worker implementation pin changed")
                entry = Path(directory) / "portability_worker.py"
                entry.write_bytes(extended)
                command.extend((str(entry), str(executable), harness))
            completed = subprocess.run(
                command,
                input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                cwd=directory, env={}, close_fds=True, timeout=timeout, check=True,
            )
        return decode(Observation, completed.stdout)
    except subprocess.TimeoutExpired as exc:
        raise WorkerFailure("worker timed out") from exc
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        raise WorkerFailure("worker failed") from exc
