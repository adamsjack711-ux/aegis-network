"""Recheck retained compressed child output and frozen resource denominators."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def raw_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with gzip.open(path, "rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def verify() -> dict:
    overall = json.loads((HERE / "results/overall.json").read_text())
    assert (overall["planned"], overall["attempted"], overall["passed"], overall["failed"],
            overall["unattempted"]) == (68, 68, 68, 0, 0)
    counted = []
    for cell in overall["cells"]:
        label, budget = cell["cell"], cell["memory_limit_mib"]
        summary = cell["summary"]
        expected = 14 if budget == 512 else 3
        assert (summary["planned"], summary["attempted"], summary["passed"],
                summary["failed"]) == (expected, expected, expected, 0)
        limits = summary["cgroup_readback"]
        assert limits["memory.max"] == str(budget * 1024 * 1024)
        assert limits["memory.swap.max"] == "0"
        cpu_quota, cpu_period = map(int, limits["cpu.max"].split())
        assert cpu_quota <= cpu_period
        assert summary["bytecode_suppressed_for_resource_measurement"] is True
        directory = HERE / "results" / label / f"{budget}m"
        distro = "debian" if label.startswith("debian") else "ubuntu"
        for child in summary["children"]:
            assert child["pass"] and child["cgroup_oom_kill_delta"] == 0
            assert child["input_unchanged"] and child["writable_trees_unchanged"]
            assert child["implicit_state_absent"] and not child["timed_out"]
            if child["mode"] == "closed":
                correction = json.loads((HERE / "results" / label / "512m-closed-correction" /
                                         "summary.json").read_text())
                replacement = correction["children"]
                assert len(replacement) == 1 and replacement[0]["pass"]
                assert child["exit_code"] == replacement[0]["exit_code"] == 2
                assert child["stderr_bytes"] <= 4096 and replacement[0]["stderr_bytes"] <= 4096
                assert replacement[0]["closed_consumer_bytes_read"] == 4096
                assert raw_sha(HERE / "results" / label / "512m-closed-correction" /
                               "closed-stdout.stdout.gz") == replacement[0]["closed_consumer_sha256"]
                counted.append({"cell": label, "id": child["id"], "rows_exact": None,
                                "closed_bytes_measured_separately": 4096})
                continue
            output = directory / f"{child['id']}.stdout.gz"
            assert raw_sha(output) == child["stdout_sha256"]
            with gzip.open(output, "rt", encoding="utf-8") as stream:
                body = json.load(stream)
            rows = child["rows"]
            if isinstance(rows, int):
                assert child["exit_code"] == 0 and child["cpu_seconds"] <= 5
                assert child["peak_rss_mib"] <= 256 and child["stdout_bytes"] <= 64 * 1024 * 1024
                assert child["wall_seconds"] <= (10 if child["mode"] == "slow" else 5)
                assert body["schema_version"] == "inventory-v2"
                assert body["package_count"] == rows and body["inventory_complete"] is True
                packages = body["packages"]
                assert len(packages) == rows
                for index, item in enumerate(packages):
                    name = f"package{index:06d}"
                    assert (item["name"], item["version"], item["architecture"],
                            item["purl"], item["source"]) == (
                            name, f"1:{index}.0-1", "amd64", f"pkg:deb/{distro}/{name}", "dpkg-status")
            else:
                assert child["exit_code"] == 2 and child["wall_seconds"] <= 2
                assert child["peak_rss_mib"] <= 128 and child["stdout_bytes"] <= 4096
                assert child["stderr_bytes"] <= 4096 and child["feed_unchanged"]
                if rows == "duplicate-inventory":
                    assert body["schema_version"] == "inventory-v2"
                    assert body["inventory_complete"] is False and body["package_count"] == 0
                else:
                    assert body["schema_version"] == "observation-error-v2"
                    assert body["status"] == body["independent_status"] == "unknown"
            counted.append({"cell": label, "id": child["id"],
                            "rows_exact": rows if isinstance(rows, int) else None,
                            "stdout_sha256": child["stdout_sha256"]})
    assert len(counted) == 68
    result = {"planned": 68, "verified": len(counted), "failed": 0,
              "identity_checked_rows": sum(item["rows_exact"] or 0 for item in counted),
              "closed_corrections": 4, "cases": counted}
    (HERE / "results/verification.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    result = verify()
    print({key: result[key] for key in ("planned", "verified", "failed", "identity_checked_rows")})
