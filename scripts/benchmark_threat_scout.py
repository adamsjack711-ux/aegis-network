"""Offline Scout microbenchmark over the pinned synthetic corpus."""

import json
import platform
import resource
import statistics
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.scout import ThreatScout


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction + 0.999999))]


def main():
    corpus_path = Path(__file__).parents[1] / "tests/fixtures/scout-corpus-v1.json"
    corpus = json.loads(corpus_path.read_text())
    instant = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    sources = [snapshot(row["kind"], row["uri"],
                        json.dumps(row["body"], sort_keys=True, separators=(",", ":")).encode(),
                        retrieved_at=instant) for row in corpus["entries"]]
    rounds = 100
    fresh_ms, replay_ms = [], []
    cpu_start = time.process_time()
    tracemalloc.start()
    for _ in range(rounds):
        scout = ThreatScout()
        for source in sources:
            start = time.perf_counter_ns()
            scout.ingest(source)
            fresh_ms.append((time.perf_counter_ns() - start) / 1_000_000)
        for source in sources:
            start = time.perf_counter_ns()
            scout.ingest(source)
            replay_ms.append((time.perf_counter_ns() - start) / 1_000_000)
        scout.close()
    peak_bytes = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    cpu_seconds = time.process_time() - cpu_start
    with tempfile.TemporaryDirectory(prefix="aegis-scout-bench-") as directory:
        path = Path(directory) / "intake.sqlite"
        scout = ThreatScout(path)
        for source in sources:
            scout.ingest(source)
        count = len(scout.events())
        scout.close()
        recovered = ThreatScout(path)
        restart_count = len(recovered.events())
        recovered.close()
    result = {
        "corpus": corpus["version"], "rounds": rounds, "fresh_intakes": len(fresh_ms),
        "duplicate_replays": len(replay_ms), "durable_events_before_restart": count,
        "durable_events_after_restart": restart_count,
        "fresh_ms": {"median": statistics.median(fresh_ms), "p95": percentile(fresh_ms, .95),
                     "max": max(fresh_ms)},
        "replay_ms": {"median": statistics.median(replay_ms), "p95": percentile(replay_ms, .95),
                      "max": max(replay_ms)},
        "process_cpu_seconds": cpu_seconds, "tracemalloc_peak_bytes": peak_bytes,
        "process_peak_rss_raw": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "process_peak_rss_unit": "bytes" if platform.system() == "Darwin" else "KiB",
        "platform": platform.platform(), "python": platform.python_version(),
        "scope": "single process; includes JSON decode, normalization, validation and SQLite write; excludes interpreter startup",
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
