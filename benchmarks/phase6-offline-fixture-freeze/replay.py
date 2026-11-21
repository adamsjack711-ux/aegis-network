"""Replay the sealed Phase 6 synthetic input set with the offline research APIs."""

import argparse
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.handoff import OfflineHandoff, read_history
from aegis.intelligence.investigator import AdvisoryInput, ScriptedProvider, investigate
from aegis.intelligence.models import Asset
from aegis.intelligence.scout import ThreatScout

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)
MANIFEST = Path(__file__).with_name("manifest.json")
MANIFEST_SHA256 = "ca3dfdcccda451db78458f8a2b4cd21e7da680960bb858f1a8f326b36a94181c"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def verified_bytes(path, digest):
    content = path.read_bytes()
    require(sha256(content).hexdigest() == digest, f"digest mismatch for {path.name}")
    return content


def load_freeze(directory):
    manifest = json.loads(verified_bytes(MANIFEST, MANIFEST_SHA256))
    artifacts = {
        name: verified_bytes(directory / name, pin["sha256"])
        for name, pin in manifest["artifacts"].items()
    }
    cases = {case["id"]: case for case in json.loads(artifacts["inputs"])}
    labels = {case["id"]: case for case in json.loads(artifacts["labels"])}
    capture = json.loads(artifacts["output"])
    reference = {case["id"]: case for case in capture["cases"]}
    require(capture["pin"] == manifest["capture_source_commit"], "reference source pin mismatch")
    require(capture["inputs_sha256"] == manifest["artifacts"]["inputs"]["sha256"],
            "reference inputs mismatch")
    require(datetime.fromisoformat(capture["now"]) == NOW, "reference clock mismatch")
    for plan in manifest["cases"]:
        case_id = plan["id"]
        case, label, earlier = cases[case_id], labels[case_id], reference[case_id]
        require(sha256(canonical(case)).hexdigest() == plan["case_sha256"],
                f"{case_id} input mismatch")
        require(label["category"] == plan["category"], f"{case_id} label category mismatch")
        for step, expected, gold, saved in zip(
            case["steps"], plan["steps"], label["steps"], earlier["steps"], strict=True
        ):
            digest = sha256(canonical(step["body"])).hexdigest()
            require(digest == expected["body_sha256"] == saved["source_digest"],
                    f"{case_id} revision digest mismatch")
            label_rows = [
                dict(status=row["status"], structured=row["structured"], applicable_refs=row["pointers"])
                for row in expected["history"]
            ]
            require(label_rows == gold["history"] and expected["receipt"] == gold["receipt"],
                    f"{case_id} expected history disagrees with sealed label")
    malformed = json.loads(artifacts["malformed_input"])[0]
    require(malformed["id"] == manifest["malformed"]["case"]
            and sha256(canonical(malformed)).hexdigest() == manifest["malformed"]["case_sha256"],
            "malformed case input mismatch")
    return manifest, cases, reference, malformed


def stable_history(history):
    """The frozen capture measures elapsed wall time on a different run."""
    return [
        {**row, "research": {**row["research"], "audit": {
            key: value for key, value in row["research"]["audit"].items() if key != "latency_ms"
        }}}
        for row in history
    ]


def verify_step(observed, expected, reference, bodies, earlier_rows):
    event = observed["event"]
    receipt = observed["receipt"]
    saved_event, = reference["ingest_consume"]["result"]["events"]
    require(
        saved_event == {**event, "seq": receipt["sequence"],
                        "receipt": receipt["outcome"], "reason": receipt["reason"]}
        and receipt["outcome"] == expected["receipt"],
        "event or receipt mismatch",
    )
    rows = observed["history"]
    saved_read, = reference["fresh_reader"]["result"]
    require(stable_history(rows) == stable_history(saved_read["rows"]),
            "fresh history differs from frozen reference apart from measured latency")
    for row, wanted in zip(rows, expected["history"], strict=True):
        origin = wanted["origin"]
        digest = sha256(bodies[origin]).hexdigest()
        research = row["research"]
        candidate = research["candidate"]
        references = candidate["applicability_references"]
        require(row["sequence"] == origin and row["revision"] == digest
                and row["status"] == wanted["status"], "history origin, digest or currency mismatch")
        require(research["check"]["deterministic_outcome"] == candidate["baseline_outcome"]
                == wanted["structured"], "structured outcome mismatch")
        require(candidate["reportable_outcome"] == wanted["reportable"],
                "reportable outcome mismatch")
        require([r["pointer"] for r in references] == wanted["pointers"]
                and all(r["sha256"] == digest for r in references), "structured reference mismatch")
        require(candidate["independently_verified"] is False, "research authority promoted")
        for excerpt in candidate["excerpts"]:
            source = bodies[origin]
            start, end = excerpt["byte_start"], excerpt["byte_end"]
            require(excerpt["source_id"] == "S1" and excerpt["source_sha256"] == digest
                    and 0 <= start < end <= len(source)
                    and source[start:end] == excerpt["quote"].encode(), "byte attribution mismatch")
        if origin in earlier_rows:
            require({k: v for k, v in row.items() if k != "status"} == earlier_rows[origin],
                    "previously stored row changed")
        earlier_rows[origin] = {k: v for k, v in row.items() if k != "status"}


def replay_case(path, case, plan, reference, observations):
    asset = Asset.model_validate(case["asset"])
    key = case["steps"][0]["body"]["id"]
    bodies = {}
    earlier_rows = {}
    with closing(ThreatScout(path)) as scout, closing(OfflineHandoff(path)) as handoff:
        for index, (step, expected, saved) in enumerate(
            zip(case["steps"], plan["steps"], reference["steps"], strict=True), 1
        ):
            observed = observations[index - 1]
            observed["status"] = "attempted"
            bodies[index] = canonical(step["body"])
            source = snapshot("osv", step["uri"], bodies[index], retrieved_at=NOW)
            observed["source_digest"] = source.sha256
            emitted = scout.ingest(source)
            observed["emitted"] = [event.model_dump(mode="json") for event in emitted]
            event, = emitted
            receipt = handoff.consume(event.sequence, case["vid"], asset,
                                      ScriptedProvider(step["provider"]), now=NOW)
            observed["receipt"] = asdict(receipt)
            observed["event"] = dict(kind=event.kind, source_kind=event.advisory.source_kind,
                                     advisory_id=event.advisory.advisory_id)
            # read_history opens and closes its own read-only SQLite connection.
            observed["history"] = read_history(path, "osv", key)
            require(event.sequence == index and observed["event"]["advisory_id"] == key,
                    "Scout sequence or advisory mismatch")
            verify_step(observed, expected, saved, bodies, earlier_rows)
            observed["status"] = "matched"


def replay_malformed(case, wanted, observed):
    # Reproduce sample(0) and the extra-field mutation from the pinned test.
    sources = tuple(snapshot(s["kind"], s["uri"], canonical(s["body"]),
                             retrieved_at=datetime.fromisoformat(s["retrieved_at"]))
                    for s in case["sources"])
    advisory = AdvisoryInput(advisory_id=case["id"], vulnerability_id=case["vulnerability_id"],
                             asset=Asset.model_validate(case["asset"]), sources=sources)
    quote = case["sources"][0]["body"].get("summary", sources[0].content.decode()[:25])
    response = {"proposed_outcome": case["gold"], "claims": [
        {"kind": "applicability", "source_id": "S1", "quote": quote}],
        "uncertainties": [], "extra": "unauthorized"}
    result = investigate(advisory, ScriptedProvider(response), now=NOW)
    observed["research"] = result.model_dump(mode="json")
    require(result.check.deterministic_outcome == result.candidate.baseline_outcome
            == wanted["structured"] and result.candidate.reportable_outcome == wanted["reportable"]
            and result.check.status == wanted["check"] and list(result.candidate.excerpts) == wanted["excerpts"]
            and result.check.excerpt_count == 0 and result.candidate.independently_verified is False,
            "malformed response did not fail closed")
    observed["status"] = "matched"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path, help="directory of exact Git blobs named by manifest key")
    args = parser.parse_args()
    report = {
        "clock": NOW.isoformat(), "manifest_sha256": MANIFEST_SHA256, "synthetic_only": True,
        "fixture_comparison": "failed", "cases": [], "malformed": {"status": "not-run"},
    }
    try:
        manifest, cases, reference, malformed = load_freeze(args.artifacts)
        report["source_commit"] = manifest["source_commit"]
        report["artifact_sha256"] = {
            name: pin["sha256"] for name, pin in manifest["artifacts"].items()
        }
        report["cases"] = [
            {"id": plan["id"], "steps": [
                {"revision": i, "status": "not-run"} for i in range(1, len(plan["steps"]) + 1)
            ]}
            for plan in manifest["cases"]
        ]
        with tempfile.TemporaryDirectory(prefix="aegis-phase6-") as folder:
            for plan, observation in zip(manifest["cases"], report["cases"], strict=True):
                case_id = plan["id"]
                replay_case(Path(folder) / f"{case_id}.sqlite", cases[case_id], plan,
                            reference[case_id], observation["steps"])
        report["malformed"]["status"] = "attempted"
        replay_malformed(malformed, manifest["malformed"], report["malformed"])
        report["fixture_comparison"] = "matched"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    print(json.dumps(report, sort_keys=True, indent=2))
    return int(report["fixture_comparison"] != "matched")


if __name__ == "__main__":
    raise SystemExit(main())
