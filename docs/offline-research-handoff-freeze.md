# Offline research handoff acceptance freeze

Baseline fc4a17bc6f9f0c289a645c4fb7006c999ba90e99. Scout's committed SQLite events are the durable queue. A caller supplies one sequence, an independently chosen local Asset and an explicit vulnerability ID. Retrying the same tuple can yield at most one historical Investigator result. Current describes revision currency only. Every assessment remains unverified private research.

A withdrawal takes effect at successful COMMIT of Scout.ingest in the local database. The source modification time orders Scout revisions. An incomparable conflict blocks positive results even though Scout retains the preceding current_state pointer. A result becomes visible only at COMMIT of a conditional insert in the same database. The final write must test the latest authoritative state under SQLite writer serialization. Readers must join the result to that same state in one fresh statement. No previously returned copy or already-open read snapshot is a live subscription. A committed result stays in history when its revision loses currency.

| Forced order, using independent connections and explicit resume points | Frozen outcome |
|---|---|
| Queue revision A, process A, read | One current unverified result linked to advisory, sequence, raw digest, original source reference, selected ID and asset digest |
| Queue A, commit withdrawal W, pick up A | Hold, zero results |
| Queue A, finish Investigator preparation, pause before write, commit W, read, resume A, read | Zero visible before resume, final write inserts zero, zero after resume |
| Commit result for A, read, commit W, read | One current before W, one withdrawn historical result after W, unchanged payload |
| Redeliver A after W, close and reopen consumer, redeliver A again | No new result or resurrection, historical identity and status preserved |

All five schedules use offline fixtures and explicit call boundaries without sleeps. Review must check the final SQL write, the reader snapshot and absence of a second publication path. Malformed, missing, lossy or stale input must hold. Tests must include independent semantic attribution and revision/source digest checks. No network, real provider, publication, signing or protected writer participates.

## Read research history

Point `read_history` at the existing SQLite database initialized by `ThreatScout` and `OfflineHandoff`. Use the source kind and advisory ID recorded by Scout.

```python
from pathlib import Path

from aegis.intelligence.handoff import read_history

rows = read_history(Path("private/scout.sqlite"), source_kind="osv", advisory_id="OSV-2099-1")
for row in rows:
    print(row["sequence"], row["status"])
```

Each call opens a read-only connection and returns one fresh snapshot of committed results and revision status. Call again after a commit to refresh the report.

| Result | Meaning |
| --- | --- |
| `[]` | The database opened and contains no saved research for that source kind and advisory ID. |
| `sqlite3.OperationalError: unable to open database file: ...` | The message includes the resolved path. Check that the file exists, the reporting account can read it, and that account can traverse each parent directory. The exception retains SQLite’s original error code. |
| `sqlite3.OperationalError: Incomplete research history schema ...` | Use a database initialized by both `ThreatScout` and `OfflineHandoff`, or have the writer initialize it before reporting. |

## Report one asset

Set `ASSET_DIGEST` to the selected asset's SHA-256 from the research history. Run the reporter in the installed Python environment.

```sh
python -m aegis.intelligence.report private/scout.sqlite osv OSV-2099-1 CVE-2099-0001 "$ASSET_DIGEST"
```

Each invocation reads one committed snapshot. The JSON field `current` contains the selected asset's reportable research outcome and check status. A current result can have outcome `unknown`. A null `current` means this selection has no current research result. The `history` entries show the sequence, digest and status of each matching stored revision. Withdrawal and supersession therefore remain visible even when no current result is available. Current v1 records use null for `applicability_references` because that format predates structured references. Current v2 records include the stored references from the deterministic assessment. Database errors exit 1. A successful report exits 0, including an empty selection.
