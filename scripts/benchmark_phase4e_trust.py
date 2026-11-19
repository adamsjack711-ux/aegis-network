"""Measure the authenticated local-service path with disposable credentials and fixtures."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import resource
import subprocess
from tempfile import TemporaryDirectory
import time
from datetime import datetime, timezone

from aegis.journal.protocol import JournalBlocked
from aegis.journal.witness import verify_extension
from aegis.phase4e.history import reconcile
from aegis.phase4e.protocol import Wire
from scripts.phase4e_lab import Lab


def duration(call, *args):
    start = time.perf_counter_ns()
    value = call(*args)
    return (time.perf_counter_ns() - start) / 1_000_000, value


def blocked(call, *args):
    try:
        call(*args)
    except JournalBlocked:
        return
    raise AssertionError("status should have blocked")


def rss(pids):
    return sum(int(size) for size in subprocess.check_output(
        ["ps", "-o", "rss=", "-p", ",".join(map(str, pids))], text=True,
    ).split())


def challenge_status(lab, finding, bundle):
    durations = []
    endpoint = lab.gate.fetch_status

    def measure(request):
        latency, result = duration(endpoint, request)
        durations.append(latency)
        return result

    lab.gate.fetch_status = measure
    try:
        elapsed, status = duration(lab.status, finding, bundle)
        return elapsed, durations[0], status
    finally:
        lab.gate.fetch_status = endpoint


def trial(path, size, repeats):
    lab = Lab(path)
    usage_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_start = time.process_time()
    with lab:
        topology = rss([process.pid for process in lab.processes.values()])
        finding, bundle = lab.seed()
        for index in range(size - 4):
            padding = lab.evidence.bundle(f"phase4e unrelated record {index}")
            lab.append(lab.receive(Wire.from_bytes("evidence", padding.manifest), ("research", "lab-v1")))
        cut = lab.seal_latest()
        assert cut.head.size == size
        warm, retrieval, checkpoint, reconciliation, freshness = [], [], [], [], []
        for _ in range(repeats):
            elapsed, retrieved, status = challenge_status(lab, finding, bundle)
            assert status.body.outcome == "reproduced"
            freshness.append((status.deadline - time.monotonic()) * 1000)
            warm.append(elapsed)
            retrieval.append(retrieved)
            elapsed, _ = duration(lab.policy.journal.check_cut, cut)
            checkpoint.append(elapsed)
            elapsed, _ = duration(reconcile, lab.reader.archives, lab.policy, cut.head)
            reconciliation.append(elapsed)
        loaded = rss([process.pid for process in lab.processes.values()])
        assert lab.status(finding, bundle).body.outcome == "reproduced"
        lab.stop("w3")
        one_lost = [duration(lab.status, finding, bundle)[0] for _ in range(repeats)]
        assert lab.status(finding, bundle).body.outcome == "reproduced"
        lab.stop("w2")
        two_lost = [duration(blocked, lab.status, finding, bundle)[0] for _ in range(repeats)]
        lab.start("w2")
        lab.start("w3")
        initial = time.perf_counter_ns()
        leaf = lab.receive(lab.evidence_withdrawal(bundle), ("review", "lab-v1"))
        receipted = time.perf_counter_ns()
        blocked(lab.status, finding, bundle)
        denied = time.perf_counter_ns()
        lab.append(leaf)
        new_cut = lab.seal(lab.propose(leaf.receipt.admission.epoch))
        converged_ms, revoked = duration(lab.status, finding, bundle)
        assert revoked.body.reason == "revoked"
        confirmed = time.perf_counter_ns()
        extension = []  # Isolate RFC 9162 verification from archive fetch and construction.
        history = reconcile(lab.reader.archives, lab.policy, new_cut.head)
        proof = tuple(node.hex() for node in history.tree.consistency(cut.head.size, new_cut.head.size))
        for _ in range(repeats):
            elapsed, _ = duration(verify_extension, cut.head, new_cut.head, proof)
            extension.append(elapsed)
        mirrored = rss([process.pid for process in lab.processes.values()])
        lab.stop("arc")
        mirror_replay_ms, history = duration(reconcile, lab.reader.archives, lab.policy, new_cut.head)
        assert len(history.events) == size + 1
        storage = {file.name: file.stat().st_size for file in sorted(path.glob("*.db"))}
    usage_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "records_before_revocation": size,
        "duration_ms": {
            "warm_status_and_relying_appraisal": warm, "freshness_remaining_on_delivery": freshness, "publisher_status_retrieval": retrieval,
            "checkpoint_quorum_signatures": checkpoint, "merkle_consistency_verification": extension,
            "archive_reconciliation": reconciliation, "one_witness_offline_accepted": one_lost,
            "two_witnesses_offline_denied": two_lost,
            "withdrawal_intake": (receipted - initial) / 1_000_000,
            "receipt_to_observed_denial": (denied - receipted) / 1_000_000,
            "intake_to_included_revocation": (confirmed - initial) / 1_000_000,
            "included_revocation_appraisal": converged_ms, "mirror_replay_with_primary_offline": mirror_replay_ms,
        },
        "availability": {"four": [repeats, repeats], "three": [repeats, repeats], "two": [0, repeats]},
        "processes": len(lab.services), "service_rss_kib": {"initial": topology, "warm": loaded, "revoked": mirrored},
        "storage_bytes": storage,
        "cpu_s": {"client": time.process_time() - cpu_start,
                  "all_children_user": usage_end.ru_utime - usage_start.ru_utime,
                  "all_children_system": usage_end.ru_stime - usage_start.ru_stime},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[4, 32, 128])
    parser.add_argument("--repeats", type=int, default=12)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if any(not 4 <= size <= 248 for size in args.sizes) or args.repeats < 1:
        parser.error("require 4–248 ordinary records and at least one repeat")
    trials = []
    for size in args.sizes:
        with TemporaryDirectory(prefix="p4e-bench-", dir="/tmp") as directory:
            trials.append(trial(Path(directory), size, args.repeats))
    files = sorted(Path("src/aegis/phase4e").glob("*.py"))
    files.extend([Path(__file__), Path("scripts/phase4e_lab.py")])
    args.output.write_text(json.dumps({
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "python": platform.python_version(),
        "source_sha256": {str(file): sha256(file.read_bytes()).hexdigest() for file in files},
        "trials": trials,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
