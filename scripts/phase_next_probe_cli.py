"""Read-only observer of CLI side effects in a disposable container."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

commands = {
    "status_no_feed": ["status", "--json"],
    "inventory": ["inventory", "--json"],
    "inventory_explicit_state": ["--state-dir", "{scratch}/chosen", "inventory", "--json"],
    "findings_no_feed": ["findings", "--json"],
    "findings_missing_trust": ["findings", "--feed", "/tmp/missing.json", "--json"],
}
results = {}
for name, arguments in commands.items():
    with TemporaryDirectory(prefix="aegis-cli-observer-") as scratch:
        state = Path(scratch) / "state"
        env = os.environ | {"XDG_STATE_HOME": str(state), "PYTHONDONTWRITEBYTECODE": "1"}
        before = sorted(str(path.relative_to(scratch)) for path in Path(scratch).rglob("*"))
        arguments = [item.replace("{scratch}", scratch) for item in arguments]
        result = subprocess.run([sys.executable, "-m", "aegis.cli", *arguments],
                                env=env, capture_output=True, text=True, check=False)
        after = sorted(str(path.relative_to(scratch)) for path in Path(scratch).rglob("*"))
        results[name] = {"exit": result.returncode, "before": before, "after": after,
                         "created": sorted(set(after) - set(before)),
                         "json_status": (json.loads(result.stdout).get("status")
                                         if result.stdout.startswith("{") else None),
                         "stderr": result.stderr.strip()}
print(json.dumps(results, sort_keys=True, indent=2))
