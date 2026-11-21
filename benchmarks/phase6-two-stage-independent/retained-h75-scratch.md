# Retained h75 abstention through scratch admission

The saved live B draft proposed `unknown` with an empty ID list. A locally scripted A singleton matched the original PyPI row at `/affected/1` solely to exercise linked B and scratch admission. This run has one observed provider reply, for B only. See [the original B scoring report](live-h75.md) for the response, draft and attempt digests and the limits of local receipt provenance.

Both B arms reproduced the 1,189-byte wire with SHA-256 `4ba3b36148fecd4c4b081d0731cfb5a2e8bec1594c3b1a9d7499358a90e661b0`. Both checks returned `abstained`, reportable `unknown`, and zero references. Scratch admission held with reason `unverified-two-stage-bundle`. Fresh history was empty before and after, the asset report had no current row, and a separate read-only query found zero rows for the pending key. The Scout ingest and all reads used a disposable local database.

## Reproduce offline

From the checkout root, use the reviewed Python 3.12 environment and set `RECEIPTS_DIR` to the private directory containing the four existing `h75-two-stage-B.*.json` receipts. The command prints an aggregate and leaves the original receipts intact.

```sh
PYTHONPATH=src:benchmarks/phase6-offline-fixture-freeze python3.12 -B - "$RECEIPTS_DIR" <<'PY'
from datetime import datetime
import json
from pathlib import Path
import sys

from aegis.intelligence.feeds import FeedClient, snapshot
from aegis.intelligence.handoff import read_history
from aegis.intelligence.models import Asset
from aegis.intelligence.report import read_asset_report
from osv_row_selection import canonical, load_target
from osv_two_stage import check_a, check_b, prepare_a, prepare_b
from replay_retained import digest, native_rows, retained
import scratch_history_admission as scratch
import two_stage_trial as bridge

raw, target_bytes = bridge.fixture("h75")
b_draft, oracle_result, attempt = retained(Path(sys.argv[1]), "h75", "B")
a = prepare_a(raw, target_bytes)
assert a["request_sha256"] == "fbef57e551cde0865e01eeecba73cb7aecc431b72c4f33789ac2597d12a771dd"
row_id = a["payload"]["candidate_rows"][1]["row_id"]
a_draft = canonical({"identity_outcome": "match", "selected_row_ids": [row_id]})
identity = check_a(raw, target_bytes, a_draft)
assert identity["status"] == "verified" and identity["matched_pointers"] == ["/affected/1"]
linked = prepare_b(raw, target_bytes, a_draft, arm="linked")
wire = bridge.build_request("B", linked)
assert wire == bridge.request_body("B", case="h75")
assert len(wire) == 1189 and digest(wire) == attempt["wire_sha256"]
linked_result = check_b(raw, target_bytes, a_draft, b_draft, arm="linked")
assert linked_result == {**oracle_result, "arm": "linked"}
assert (linked_result["status"], linked_result["reportable_outcome"],
        linked_result["references"]) == ("abstained", "unknown", [])

freeze, _ = scratch.sealed_inputs()
now = datetime.fromisoformat(freeze["clock"])
advisory = json.loads(raw)["id"]
source = snapshot("osv", FeedClient().canonical_uri("osv", advisory), raw, retrieved_at=now)
target = load_target(target_bytes)
asset = Asset(asset_id="retained-h75", identity_kind="purl",
              identity=f"pkg:pypi/{target.package}", version=target.version)
subject = scratch.asset_digest(asset)
with scratch.scratch() as trial:
    db = trial.path
    event, = trial.scout.ingest(source)
    before = read_history(db, "osv", advisory)
    receipt = trial.admit(event.sequence, advisory, source.sha256, asset, target_bytes,
                          a_draft, b_draft, now=now)
    assert (receipt.outcome, receipt.reason) == ("held", "unverified-two-stage-bundle")
    after = read_history(db, "osv", advisory)
    report = read_asset_report(db, "osv", advisory, advisory, subject)
    assert before == after == report["history"] == [] and report["current"] is None
    assert native_rows(db, advisory, subject, event.sequence) == []
assert not db.parent.exists()
print(json.dumps({"fixture": "h75", "A": "scripted-verified-match",
                  "B": "retained-live-abstention", "B_wire_sha256": digest(wire),
                  "B_draft_sha256": attempt["draft_sha256"], "references": 0,
                  "admission": receipt.outcome, "reason": receipt.reason,
                  "fresh_rows": [len(before), len(after)]}, sort_keys=True))
PY
```
