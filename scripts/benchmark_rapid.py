"""Measure local Rapid dry-run decision latency; no coordinator or NATS is used."""

import argparse
import json
import platform
import resource
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence, Finding, Software, sign
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.storage import SqliteAudit


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction + 0.5)))]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decisions", type=int, default=1000)
    parser.add_argument("--inventory-size", type=int, default=1000)
    parser.add_argument("--scenario", choices=("allow", "inventory-deny", "policy-deny"),
                        default="allow")
    args = parser.parse_args()
    if args.decisions < 1 or args.inventory_size < 1:
        parser.error("decisions and inventory-size must be positive")

    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    inventory = [InventoryItem(f"pkg:generic/item-{i}", "1.0.0")
                 for i in range(args.inventory_size)]
    target = inventory[-1]
    finding_purl = target.purl if args.scenario != "inventory-deny" else "pkg:generic/absent"
    envelopes = [sign(Finding(
        schema_version="1.0", artifact_id=uuid4(), publisher_id="bench-publisher",
        sequence=i + 1, issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1), vulnerability_id="BENCH-LAB-1",
        software=Software(purl=finding_purl, affected_versions=[target.version]),
        evidence=[Evidence(uri="urn:benchmark:opaque", sha256="a" * 64,
                           method="lab-reproduction")],
        applicability="authorized-lab", mitigation_template="observe-only",
    ), key) for i in range(args.decisions)]

    with tempfile.TemporaryDirectory(prefix="aegis-rapid-bench-") as directory:
        audit = SqliteAudit(Path(directory) / "audit.db", agent_id="benchmark-agent")
        templates = frozenset() if args.scenario == "policy-deny" else frozenset({"observe-only"})
        agent = LocalAgent(LocalPolicy({"bench-publisher": key.public_key()},
                                       templates, True), inventory, audit)
        elapsed_ms = []
        cpu_before = time.process_time()
        wall_before = time.perf_counter()
        allowed = 0
        for envelope in envelopes:
            started = time.perf_counter_ns()
            decision = agent.evaluate(envelope, now)
            elapsed_ms.append((time.perf_counter_ns() - started) / 1_000_000)
            allowed += decision.outcome == "allow_dry_run"
        wall_seconds = time.perf_counter() - wall_before
        cpu_seconds = time.process_time() - cpu_before
        rows = audit.all_decisions()
        duplicate_before = time.perf_counter_ns()
        duplicate = agent.evaluate(envelopes[-1], now)
        duplicate_ms = (time.perf_counter_ns() - duplicate_before) / 1_000_000
        expected = "allow_dry_run" if args.scenario == "allow" else "deny"
        assert duplicate.outcome == expected and allowed == (args.decisions if expected == "allow_dry_run" else 0)
        assert len(audit.all_decisions()) == len(rows)
        audit.db.close()

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes; Linux reports KiB.
    rss_mib = rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024
    print(json.dumps({
        "scope": "local signature verification, exact inventory policy, SQLite commit",
        "python": platform.python_version(), "platform": platform.platform(),
        "processor": platform.processor(), "scenario": args.scenario,
        "decisions": args.decisions,
        "inventory_size": args.inventory_size, "allowed": allowed,
        "logical_rows": len(rows), "duplicate_logical_rows": len(rows) - args.decisions,
        "latency_ms": {"p50": percentile(elapsed_ms, 0.50),
                       "p95": percentile(elapsed_ms, 0.95),
                       "p99": percentile(elapsed_ms, 0.99),
                       "mean": statistics.mean(elapsed_ms),
                       "duplicate": duplicate_ms},
        "wall_seconds": wall_seconds, "cpu_seconds": cpu_seconds,
        "throughput_per_second": args.decisions / wall_seconds,
        "peak_rss_mib": rss_mib,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
