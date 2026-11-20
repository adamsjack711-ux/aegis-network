"""Print a read-only, standard-library manifest for an offline Linux image."""

import hashlib
import importlib.metadata
import json
import os
import platform
import sys
from pathlib import Path

PACKAGES = (
    "aegis-network", "cryptography", "cffi", "pycparser", "pydantic",
    "pydantic-core", "annotated-types", "typing-extensions", "typing-inspection", "pip",
)


def package(name: str) -> dict:
    try:
        dist = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return {"name": name, "installed": False}
    record = dist.read_text("RECORD")
    return {
        "name": name,
        "installed": True,
        "version": dist.version,
        "location": str(dist.locate_file("")),
        "record_sha256": hashlib.sha256(record.encode()).hexdigest() if record else None,
    }


print(json.dumps({
    "os_release": Path("/etc/os-release").read_text(),
    "kernel": platform.release(),
    "architecture": platform.machine(),
    "python": sys.version,
    "uid": os.getuid(),
    "packages": [package(name) for name in PACKAGES],
}, sort_keys=True, indent=2))
