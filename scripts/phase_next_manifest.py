"""Write SHA-256 inventory for retained predecessor and new validation artifacts."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "docs/phase-next-acceptance-frozen.md",
    "docs/phase-next-validation.md",
    "docs/phase-next-findings.md",
    "fixtures/phase-next-ai-holdout-v1.json",
    "fixtures/phase-next-ai-claim-map-v1.json",
    "scripts/phase_next_native_trial.py",
    "scripts/phase_next_native_oracle.py",
    "scripts/phase_next_ai_eval.py",
    "scripts/phase_next_5a_adapter.py",
    "scripts/phase_next_5a_security.py",
    "scripts/phase_next_cli_safety.py",
    "scripts/phase_next_contract_audit.py",
    "scripts/phase_next_5b_fixtures.py",
    "scripts/phase_next_5b_oracle.py",
    "scripts/phase_next_5b_resource_driver.py",
    "scripts/phase_next_5b_api_guard.py",
    "scripts/phase_next_manifest.py",
    "benchmarks/phase4e-adversarial/observer-order-native.json",
    "benchmarks/phase4e-adversarial/observer-order-native-repeat.json",
    "benchmarks/phase4e-adversarial/observer-order-b.json",
    "benchmarks/phase4e-adversarial/observer-order-b-repeat.json",
    "benchmarks/phase4e/integrated-final-348.xml",
    "benchmarks/phase4e-withdrawal/baseline-sigkill.json",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    files = list(FILES)
    files.extend(str(path.relative_to(ROOT)) for path in sorted(
        (ROOT / "fixtures/phase-next-cli").glob("*")) if path.is_file())
    files.extend(str(path.relative_to(ROOT)) for path in sorted(
        (ROOT / "benchmarks/phase-next-validation").glob("*"))
                 if path.is_file() and path.resolve() != args.output.resolve())
    rows = []
    for name in files:
        raw = (ROOT / name).read_bytes()
        rows.append({"path": name, "bytes": len(raw), "sha256": sha256(raw).hexdigest()})
    args.output.write_text(json.dumps({"at_utc": datetime.now(timezone.utc).isoformat(),
                                       "hash": "SHA-256", "files": rows}, indent=2) + "\n")


if __name__ == "__main__":
    main()
