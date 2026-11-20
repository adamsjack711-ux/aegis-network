# Threat Scout v1: offline advisory intake

Branch `feat/phase5a-threat-scout` begins at `8292e531194216a578c32c912d066f98cdbce9ea`. The Scout is a private research intake boundary. It calls the existing deterministic `normalize` adapter and produces `scout-advisory-input-v1` records for a future Investigator. It does not publish to Mesh, sign a Finding, create Evidence, approve a mitigation, or call a protected writer. The existing `Finding 1.0`, `InventoryItem`, and T4/T5 authority paths are unchanged. The [schema authority map](phase5-schema-authority.md) controls any later integration.

## Supported source adapters

| Kind | Canonical official source shape | Extracted fields | Limits |
| --- | --- | --- | --- |
| `osv` | `https://api.osv.dev/v1/vulns/{id}` | OSV ID and aliases, ecosystem/package or purl, exact versions and range events, source publication/modification/withdrawal, summary | Version evaluation remains ecosystem-specific and may be unknown. |
| `nvd` | `https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId={CVE}` | CVE, CPE product and bounds, CVSS score/vector, timestamps, description | A CPE match does not resolve configuration context or a local package identity. |
| `kev` | CISA known exploited vulnerabilities JSON feed URI | One record per CVE, vendor/product label, date added/released, known exploitation | KEV does not establish affected versions. |
| `vendor-ghsa` | `https://api.github.com/repos/{owner}/{repo}/security-advisories/{GHSA}` | GHSA/CVE, ecosystem/package, vendor range and first patched version, severity label and timestamps | The repository URI is metadata, not publisher authentication. |

`FeedClient.fetch` remains disabled. The Scout accepts only caller-supplied `SourceSnapshot` bytes. `fixture` acquisition is labeled `synthetic-fixture`; caller-supplied `https` acquisition is labeled `unverified-archive`, never authenticated merely because the URI is official. Synthetic redistribution is `synthetic-test-only`; archive redistribution is `unknown`. Real source enrollment, provenance verification, license review, and live retrieval require a separate decision. No live request is made by this pipeline or benchmark.

## Intake and scheduling

`ThreatScout()` uses in-memory SQLite. `ThreatScout(Path("private/scout.sqlite"))` explicitly opts into durable SQLite; the caller chooses and protects that path. A transaction saves raw bytes by SHA-256, each supplied URI/acquisition/retrieval-time observation, normalized advisory revisions, current state, and any events together. Replaying the same digest and metadata creates no revision or event. A second retrieval of the same bytes records its time without a new advisory event. Different metadata for the same pinned revision is rejected; the caller must reconcile it instead of silently changing a prior record.

The key is `(source kind, source advisory ID)`. KEV is split into one advisory per CVE. Cross-source records sharing a CVE remain separate and retain their references; no source is silently made authoritative over another. Every distinct digest remains available even when an older correction arrives late. A newer source modification time and changed normalized material emits `changed` and advances current state. A changed revision with equal or missing/uncomparable modification time emits `conflict` and retains the prior current state. An older revision is retained without rolling back current state. A format-only raw-byte change is retained without an event. Event sequence is a monotonic SQLite ID; `events(after, limit)` supplies ordered cursor replay after restart. No scheduler runs in the background and no outbound event is published. An Investigator can poll this queue explicitly and retain its cursor.

An OSV or GitHub notice without an affected-product list still becomes an `unknown` product claim with explicit missing-product/version labels. An empty KEV catalog records its snapshot and acquisition observation and schedules no advisory event.

Each `AdvisoryInput` includes a version tag, stable source ID, normalized vulnerability IDs, source URI, acquisition/provenance, publication/modification/withdrawal fields, missing/conflicting metadata labels, priority indicator, and original normalized claims. Every claim carries a source kind, URI, retrieval time, SHA-256 and structured pointer. `source_bytes(digest)` returns the exact submitted bytes. The content digest proves only local byte identity, not authenticity or semantic truth.

Priority is deterministic: known exploitation plus operator-supplied exposure is `urgent`; known exploitation alone or exposed CVSS at least 9 is `high`; exposure or a CVSS score alone is `review`; otherwise `unscored`. A withdrawn source is always `unscored`. The indicator retains the supplied exposure Boolean, score and reason codes. It is triage metadata, never a vulnerability or affected-version verdict. Missing exposure stays unknown. Conflicting exposure values across aliases are labeled and treated as unknown.

The normalizer rejects duplicate JSON keys, malformed roots, inconsistent KEV counts and mismatched lookup IDs. Scout adds exact URI allowlisting, source digest and timezone checks, 8 MiB byte and 10,000 claim bounds, timestamp validation and transactional rollback. Advisory text is stored as untrusted data. No text becomes a command, model instruction, signed Finding or writer capability. Existing range-comparison limitations remain: prereleases, distro epochs/backports and NVD configuration context require a separate reviewed comparator or Investigator abstention.

## Offline corpus and evaluation

`tests/fixtures/scout-corpus-v1.json` contains eight author-labeled synthetic snapshots: initial OSV notice, newer correction, same-time conflict, late older revision, KEV exploitation, NVD configuration context, GitHub advisory with a shared CVE, and instruction-looking source text. Every entry pins canonical JSON SHA-256 and expected normalized advisory ID, vulnerability IDs, product identity, priority tier and event kind. The eight fixture entries pass all these asserted fields and scheduling outcomes; seven events are emitted because the late older version is retained without scheduling. These are visible development labels, not independent factual adjudication. Tests also exercise format-only changes, missing timestamps, unverified archives, malformed bodies, URI spoofing, metadata-replay conflict, withdrawn priority, atomic failure and durable restart. No live source, independent authenticity check or production exposure is represented.

Run:

```sh
PYTHONPATH=src ../../.venv/bin/python -m pytest -q tests/test_threat_scout.py tests/test_phase5a_intelligence.py tests/test_phase5a_source_claim.py tests/test_phase5a_claim_integrity.py
PYTHONPATH=src ../../.venv/bin/python scripts/benchmark_threat_scout.py
```

The benchmark uses 100 in-memory rounds over eight snapshots and 800 duplicate replays, then checks durable event count across one SQLite restart. It measures in-process wall latency, process CPU, Python allocation peak, and process RSS high-water mark. It excludes interpreter startup, network, model inference, production storage contention and Investigator processing. Raw measured values and platform are in [the benchmark result](../benchmarks/threat-scout-v1.json). The tests verify event ordering, normalized IDs/products, conflict retention, missing metadata and failure recovery; they do not establish real-world normalization accuracy. On this corpus, expected event classifications and checked source/product fields were exact in the regression tests, with the stated author-label limitation.
