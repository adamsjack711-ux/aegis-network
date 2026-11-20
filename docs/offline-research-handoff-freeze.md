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
