"""Check that the frozen resource oracle detects missing and altered output."""

import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "phase5b_performance_safety.py"
SPEC = importlib.util.spec_from_file_location("phase5b_performance_safety", SCRIPT)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def test_output_oracle_checks_every_row_and_default_identity(tmp_path):
    path = tmp_path / "inventory.json"
    packages = [{"name": f"package{index:06d}", "version": f"1:{index}.0-1",
                 "architecture": "amd64", "purl": f"pkg:deb/debian/package{index:06d}"}
                for index in range(3)]
    body = {"schema_version": "inventory-v2", "package_count": 3,
            "inventory_complete": True, "asset_id": None, "identity_scope": "none",
            "packages": packages}

    def check():
        path.write_text(json.dumps(body))
        return probe.verify_inventory(path, 3)

    assert check()["all_rows_exact"]
    body["packages"] = packages[:2]
    assert not check()["all_rows_exact"]
    body["packages"] = packages[:]
    body["packages"][1] = packages[0]
    assert not check()["all_rows_exact"]
    body["packages"] = packages
    body["identity_scope"] = "explicit-local"
    assert not check()["all_rows_exact"]
