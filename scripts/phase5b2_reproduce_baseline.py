"""Re-run the retained explicit-state path-race tests against the frozen baseline.

This script writes only to the requested raw-results path and a disposable
temporary Python package. It does not download dependencies or use a network.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


BASELINE = "ec939e14a5acd438ff0d5fa562ed61a70b68f3c9"
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "benchmarks/phase5b2/failed-first-state-races.txt"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="aegis-5b2-baseline-") as scratch:
        package = Path(scratch) / "aegis"
        package.mkdir()
        (package / "__init__.py").write_text("")
        source = subprocess.run(
            ["git", "show", f"{BASELINE}:src/aegis/local_observer.py"],
            cwd=ROOT, capture_output=True, check=True,
        ).stdout
        (package / "local_observer.py").write_bytes(source)
        command = [sys.executable, "-m", "pytest", "-q",
                   "tests/cli_safety_phase5b2/test_state_races.py"]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                env=os.environ | {"PYTHONPATH": scratch,
                                                  "PYTHONDONTWRITEBYTECODE": "1"}, check=False)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        f"baseline={BASELINE}\npython={sys.version}\n"
        f"argv={command!r}\nexit={result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    print(f"{OUTPUT}: {result.returncode}")
    return 0 if result.returncode == 1 and "2 failed" in result.stdout else 1


if __name__ == "__main__":
    raise SystemExit(main())
