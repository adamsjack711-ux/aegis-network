"""Check that incomplete normalized product/version placeholders are held."""
import json
import tempfile
from pathlib import Path
import runpy

shared = runpy.run_path(str(Path(__file__).with_name("independent-challenge.py")))
outcomes = []
for name, affected in [
    ("empty-identity", {"package": {}, "versions": ["1.2"]}),
    ("empty-version", {"package": {"ecosystem": "PyPI", "name": "test-wheel"}, "versions": [""]}),
    ("empty-osv-events", {"package": {"ecosystem": "PyPI", "name": "test-wheel"},
                          "ranges": [{"type": "ECOSYSTEM", "events": []}]})
]:
    with tempfile.TemporaryDirectory() as tmp:
        base = shared["make_source"]()
        body = json.loads(base.content)
        body["affected"] = [affected]
        raw = json.dumps(body).encode()
        src = shared["snapshot"]("osv", base.uri, raw, retrieved_at=shared["NOW"])
        path = Path(tmp) / "s.db"
        scout = shared["ThreatScout"](path)
        event, = scout.ingest(src)
        worker = shared["OfflineHandoff"](path)
        provider = shared["ScriptedProvider"]({"proposed_outcome": "unaffected", "claims": [], "uncertainties": []})
        decision = worker.consume(event.sequence, shared["VID"], shared["ASSET"], provider, now=shared["NOW"])
        rows = worker.history("osv", shared["ADVISORY"])
        outcomes.append(decision.outcome == "held" and not rows)
        print(json.dumps({"case": name, "outcome": decision.outcome, "reason": decision.reason,
                          "revision": src.sha256, "visible": [[r["status"], r["research"]["candidate"]["reportable_outcome"]] for r in rows]}))
        worker.close()
        scout.close()
assert all(outcomes), outcomes
