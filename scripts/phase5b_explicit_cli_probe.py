"""Verify the explicit state opt-in through two fresh Linux CLI processes."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys


status = Path("/var/lib/dpkg/status")
status.write_text("Package: fixture\nStatus: install ok installed\n"
                  "Architecture: amd64\nVersion: 1.0\n\n")
state = Path("/tmp/aegis-explicit-choice")
results = []
for _ in range(2):
    child = subprocess.run([sys.executable, "-m", "aegis.cli", "--state-dir", str(state),
                            "inventory", "--json"], text=True, capture_output=True,
                           env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"}, check=False)
    body = json.loads(child.stdout)
    results.append({"exit_code": child.returncode, "asset_id": body.get("asset_id"),
                    "identity_scope": body.get("identity_scope"),
                    "package_count": body.get("package_count"), "stderr": child.stderr})
result = {"uid": os.geteuid(), "runs": results,
          "files": sorted(str(path.relative_to(state)) for path in state.rglob("*")),
          "dir_mode": oct(stat.S_IMODE(state.stat().st_mode)),
          "file_mode": oct(stat.S_IMODE((state / "identity.json").stat().st_mode))}
result["pass"] = (result["uid"] != 0 and result["files"] == ["identity.json"] and
                  result["dir_mode"] == "0o700" and result["file_mode"] == "0o600" and
                  all(run["exit_code"] == 0 and run["package_count"] == 1 and
                      run["identity_scope"] == "explicit-local" and not run["stderr"] for run in results) and
                  results[0]["asset_id"] == results[1]["asset_id"])
print(json.dumps(result, sort_keys=True))
if not result["pass"]:
    raise SystemExit(1)
