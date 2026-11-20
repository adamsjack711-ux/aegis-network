"""The resource probe must reject an omitted or altered inventory row."""

import importlib.util
import json
from pathlib import Path


def _probe():
    path = Path(__file__).resolve().parents[2] / "scripts" / "alpha_privacy_probe.py"
    spec = importlib.util.spec_from_file_location("alpha_privacy_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exact_row_oracle_rejects_missing_reordered_and_changed_rows(tmp_path, monkeypatch):
    probe = _probe()
    output = tmp_path / "inventory.json"
    monkeypatch.setattr(probe, "OUTPUT", output)
    rows = [{"name": f"package{index:06d}", "version": f"1:{index}.0-1",
             "architecture": "amd64", "purl": f"pkg:deb/debian/package{index:06d}"}
            for index in range(2)]
    envelope = {"schema_version": "inventory-v2", "package_count": 2,
                "inventory_complete": True, "asset_id": None,
                "identity_scope": "none", "packages": rows}
    output.write_text(json.dumps(envelope))
    assert probe.verify_output(2) == (True, None)
    envelope["packages"] = rows[:1]
    output.write_text(json.dumps(envelope))
    assert probe.verify_output(2)[0] is False
    envelope["packages"] = rows[::-1]
    output.write_text(json.dumps(envelope))
    assert probe.verify_output(2)[0] is False
    envelope["packages"] = rows
    envelope["packages"][1] = rows[1] | {"purl": "pkg:deb/debian/wrong"}
    output.write_text(json.dumps(envelope))
    assert probe.verify_output(2)[0] is False
