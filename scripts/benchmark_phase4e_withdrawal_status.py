"""Compare the historical checkpoint profile and direct withdrawal freshness on local sockets."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
from tempfile import TemporaryDirectory

from aegis.journal.protocol import JournalBlocked
from aegis.phase4e.protocol import Leaf, Wire
from scripts.benchmark_phase4e_trust import challenge_status, duration
from scripts.phase4e_lab import Lab


def observe(lab, finding, bundle):
    try:
        return lab.status(finding, bundle).body.outcome
    except JournalBlocked:
        return "held"


def trial(path, size, repeats, profile):
    with Lab(path, profile=profile) as lab:
        finding, bundle = lab.seed()
        for index in range(size - 4):
            unrelated = lab.evidence.bundle(f"withdrawal status benchmark {index}")
            lab.append(lab.receive(Wire.from_bytes("evidence", unrelated.manifest), ("research", "lab-v1")))
        cut = lab.seal_latest()
        assert cut.head.size == size

        warm, publication = [], []
        for _ in range(repeats):
            full, publish, status = challenge_status(lab, finding, bundle)
            assert status.body.outcome == "reproduced"
            warm.append(full)
            publication.append(publish)

        lab.stop("w0")
        outage = [duration(observe, lab, finding, bundle) for _ in range(repeats)]
        expected_outage = "reproduced" if profile == "checkpoint-v1" else "held"
        assert all(outcome == expected_outage for _, outcome in outage)
        lab.start("w0")
        assert observe(lab, finding, bundle) == "reproduced"

        leaf = lab.admissions["review", "lab-v1"]["w0"].call("/admit", Leaf, lab.evidence_withdrawal(bundle))
        assert len(leaf.receipt.votes) == 1
        elapsed, withdrawn = duration(lab.status, finding, bundle)
        assert withdrawn.body.head == status.body.head
        expected_reason = "quorum" if profile == "checkpoint-v1" else "revoked"
        assert withdrawn.body.reason == expected_reason
        return {
            "profile": profile, "records": size,
            "healthy_positive": [len(warm), repeats],
            "healthy_appraisal_ms": warm, "publisher_response_ms": publication,
            "one_witness_offline_positive": [sum(outcome == "reproduced" for _, outcome in outage), repeats],
            "one_witness_offline_ms": [elapsed for elapsed, _ in outage],
            "single_receipt_refresh_ms": elapsed,
            "single_receipt_outcome": withdrawn.body.outcome, "single_receipt_reason": withdrawn.body.reason,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[4, 128])
    parser.add_argument("--repeats", type=int, default=12)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if any(not 4 <= size <= 248 for size in args.sizes) or args.repeats < 1:
        parser.error("require 4–248 ordinary records and at least one repeat")
    profiles = ("checkpoint-v1", "withdrawal-v2")
    rows = []
    for index, size in enumerate(args.sizes):
        for profile in profiles if index % 2 == 0 else reversed(profiles):
            with TemporaryDirectory(prefix="p4e-wb-", dir="/tmp") as path:
                rows.append(trial(Path(path), size, args.repeats, profile))
    files = sorted(Path("src/aegis/phase4e").glob("*.py"))
    files.extend(Path("scripts").glob("*phase4e*trust.py"))
    files.extend([Path("scripts/phase4e_lab.py"), Path("scripts/benchmark_phase4e_withdrawal_status.py")])
    args.output.write_text(json.dumps({
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "python": platform.python_version(),
        "source_sha256": {str(file): sha256(file.read_bytes()).hexdigest() for file in files},
        "trials": rows,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
