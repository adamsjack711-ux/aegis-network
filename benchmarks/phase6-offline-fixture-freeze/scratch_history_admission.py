"""Explicit disposable SQLite benchmark for scripted two-stage history admission."""

from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from aegis.intelligence.baseline import assess, normalize
from aegis.intelligence.feeds import FeedClient, snapshot
from aegis.intelligence.handoff import OfflineHandoff, Receipt, read_history
from aegis.intelligence.investigator import AdvisoryInput, ScriptedProvider, investigate, verify_investigation
from aegis.intelligence.models import Asset, SourceSnapshot
from aegis.intelligence.report import read_asset_report
from aegis.intelligence.scout import AdvisoryInput as ScoutInput, ThreatScout

from osv_row_selection import canonical, load_target
from osv_two_stage import check_b, prepare_a, prepare_b

SEAL = Path(__file__).resolve().parents[1] / "phase6-two-stage-independent/seal"
SEAL_SUMS_SHA256 = "8592c493d1a3eba903bad74defe667baa25603546f3ca390249bd05e29c3eb4c"
FRESHNESS_WINDOW = timedelta(days=7)
WITHDRAWAL = "2026-11-19T23:59:00Z"


class Held(ValueError):
    """A deterministic benchmark hold, without a research insert."""


def asset_digest(asset):
    return sha256(canonical(asset.model_dump(mode="json"))).hexdigest()


def scripted(outcome, quotes=()):
    return ScriptedProvider({
        "proposed_outcome": outcome, "uncertainties": [], "claims": [
            {"kind": "applicability", "source_id": "S1", "quote": quote} for quote in quotes
        ],
    })


@dataclass
class _ScratchTrial:
    path: Path
    scout: ThreatScout
    writer: OfflineHandoff

    def snapshot_at(self, sequence, advisory_id, digest):
        row = self.writer.db.execute("""
            SELECT s.status, s.record, b.content FROM research_revision_state s
            LEFT JOIN snapshots b ON b.digest = s.digest WHERE s.sequence = ?
        """, (sequence,)).fetchone()
        if row is None:
            raise Held("unknown-event")
        status, record, content = row
        if status != "current":
            raise Held(status)
        scout = ScoutInput.model_validate_json(record)
        if (scout.content_sha256 != digest or scout.advisory_id != advisory_id
                or advisory_id not in scout.vulnerability_ids or scout.source_kind != "osv"
                or scout.acquisition != "fixture"):
            raise Held("source-binding-mismatch")
        return SourceSnapshot(kind=scout.source_kind, uri=scout.source_uri,
                              retrieved_at=scout.retrieved_at, acquisition=scout.acquisition,
                              sha256=digest, content=content)

    def admit(self, sequence, advisory_id, digest, asset, target_bytes, identity_draft, version_draft,
              *, now, commit_now=None, before_lock=None):
        """Evaluate a scripted bundle, then bind and check it on the scratch writer."""
        commit_now = now if commit_now is None else commit_now
        try:
            target = load_target(target_bytes)
            prefix = {"PyPI": "pypi", "npm": "npm"}[target.ecosystem]
            if (asset.identity_kind != "purl" or asset.identity != f"pkg:{prefix}/{target.package}"
                    or asset.version != target.version or asset.configuration is not None):
                raise Held("target-binding-mismatch")
            evaluated = self.snapshot_at(sequence, advisory_id, digest)
            proof = check_b(evaluated.content, target_bytes, identity_draft, version_draft, arm="linked")
            if proof["status"] != "verified":
                raise Held("unverified-two-stage-bundle")
            outcome = proof["reportable_outcome"]
            references = proof["references"]
            data = AdvisoryInput(advisory_id=advisory_id, vulnerability_id=advisory_id,
                                 asset=asset, sources=(evaluated,))
            quotes = [ref["osv_row"] for ref in references]
            result = investigate(data, scripted(outcome, quotes), now=now)
            if before_lock is not None:
                before_lock(result)

            with self.writer.db:
                self.writer.db.execute("BEGIN IMMEDIATE")
                current = self.snapshot_at(sequence, advisory_id, digest)
                if current != evaluated:
                    raise Held("snapshot-binding-changed")
                if (current.retrieved_at > commit_now
                        or commit_now - current.retrieved_at > FRESHNESS_WINDOW):
                    raise Held("stale-or-future-source")
                conservative = assess(asset, normalize(current), advisory_id, now=commit_now)
                if conservative.outcome != outcome:
                    raise Held("conservative-policy-disagreement")
                current_input = data.model_copy(update={"sources": (current,)})
                verify_investigation(current_input, result, now=commit_now)
                candidate = result.candidate
                if result.check.status != "research-consistent" or candidate.reportable_outcome != outcome:
                    raise Held("investigator-check-not-determinate")
                expected_refs = {(ref["pointer"], ref["source_sha256"]) for ref in references}
                checked_refs = {(ref.pointer, ref.sha256) for ref in candidate.applicability_references}
                expected_spans = [
                    (ref["source_sha256"], ref["byte_start"], ref["byte_end"], ref["osv_row"])
                    for ref in references
                ]
                checked_spans = [
                    (excerpt.source_sha256, excerpt.byte_start, excerpt.byte_end, excerpt.quote)
                    for excerpt in candidate.excerpts
                ]
                if checked_refs != expected_refs or checked_spans != expected_spans:
                    raise Held("selected-evidence-binding-mismatch")

                # The existing native _commit opens its own transaction. Keep the
                # prototype's eligibility and insertion together on this scratch
                # connection without changing that product method.
                inserted = self.writer.db.execute("""
                    INSERT INTO research_results(sequence,vulnerability_id,asset_digest,investigation)
                    VALUES (?,?,?,?)
                    ON CONFLICT(sequence,vulnerability_id,asset_digest) DO NOTHING
                """, (sequence, advisory_id, asset_digest(asset), result.model_dump_json()))
                if not inserted.rowcount:
                    return Receipt("duplicate", sequence, "already-recorded")
                return Receipt("committed", sequence, "verified-two-stage-current-at-commit")
        except Held as exc:
            return Receipt("held", sequence, str(exc))
        except (ValueError, TypeError, KeyError):
            return Receipt("held", sequence, "invalid-source-or-research-input")


@contextmanager
def scratch():
    """Create an owned temporary database; the CLI never accepts a DB path."""
    with TemporaryDirectory(prefix="aegis-phase6-history-") as folder:
        path = Path(folder) / "history.sqlite"
        with closing(ThreatScout(path)) as scout, closing(OfflineHandoff(path)) as writer:
            yield _ScratchTrial(path, scout, writer)


def sealed_inputs():
    manifest = (SEAL / "SHA256SUMS").read_bytes()
    if sha256(manifest).hexdigest() != SEAL_SUMS_SHA256:
        raise ValueError("frozen lifecycle manifest changed")
    entries = {name: digest for digest, name in (line.split(maxsplit=1) for line in
                                                   manifest.decode().splitlines())}

    def read(name):
        raw = (SEAL / name).read_bytes()
        if sha256(raw).hexdigest() != entries["./" + name]:
            raise ValueError("frozen lifecycle input changed")
        return raw

    freeze = json.loads(read("oracle/lifecycle.json"))
    pairs = {}
    for item in freeze["controls"]:
        case = item["case"]
        prefix = f"inputs/original/{case}"
        pairs[case] = read(f"{prefix}/source.json"), read(f"{prefix}/target.json")
    return freeze, pairs


def stage_drafts(raw, target, matches, selected, outcome):
    a = prepare_a(raw, target)
    ids = [row["row_id"] for row in a["payload"]["candidate_rows"]]
    identity = canonical({"identity_outcome": "match", "selected_row_ids": [ids[pos] for pos in matches]})
    b = prepare_b(raw, target, identity, arm="linked")
    ids = [row["row_id"] for row in b["payload"]["candidate_rows"]]
    version = canonical({"proposed_outcome": outcome, "selected_row_ids": [ids[pos] for pos in selected]})
    return identity, version


def case_setup(name, pair, *, matches, selected, outcome):
    raw, target = pair
    advisory_id = json.loads(raw)["id"]
    uri = FeedClient().canonical_uri("osv", advisory_id)
    wanted = load_target(target)
    prefix = {"PyPI": "pypi", "npm": "npm"}[wanted.ecosystem]
    asset = Asset(asset_id=f"synthetic-{name}", identity_kind="purl",
                  identity=f"pkg:{prefix}/{wanted.package}", version=wanted.version)
    drafts = stage_drafts(raw, target, matches, selected, outcome)
    return raw, target, advisory_id, uri, asset, drafts


def append_observation(trial, advisory_id, asset, before, receipt, *, history_status, count):
    after = read_history(trial.path, "osv", advisory_id)
    view = read_asset_report(trial.path, "osv", advisory_id, advisory_id, asset_digest(asset))
    assert len(after) == count
    if before:
        assert after == [row | {"status": history_status} for row in before]
    if receipt.outcome == "held":
        assert view["current"] is None
    return {"receipt": asdict(receipt), "rows_before": len(before), "rows_after": len(after),
            "before_history": before, "history": after, "fresh_subject_report": view}


def h28(pair, now, *, retrieval, commit_now=None):
    raw, target, advisory_id, uri, asset, drafts = case_setup("h28", pair, matches=[1], selected=[0],
                                                             outcome="affected")
    with scratch() as trial:
        source = snapshot("osv", uri, raw, retrieved_at=retrieval)
        event, = trial.scout.ingest(source)
        before = read_history(trial.path, "osv", advisory_id)
        receipt = trial.admit(event.sequence, advisory_id, source.sha256, asset, target, *drafts,
                              now=now, commit_now=commit_now)
        expected = now if commit_now is None else commit_now
        stale = expected - retrieval > FRESHNESS_WINDOW
        assert receipt.outcome == ("held" if stale else "committed")
        if stale:
            assert receipt.reason == "stale-or-future-source"
        entry = append_observation(trial, advisory_id, asset, before, receipt,
                                   history_status="current", count=0 if stale else 1)
        if not stale:
            current = entry["fresh_subject_report"]["current"]
            assert current["reportable_outcome"] == "affected"
            assert current["applicability_references"][0]["pointer"] == "/affected/1"
            row, = entry["history"]
            reference, = row["research"]["candidate"]["excerpts"]
            assert raw[reference["byte_start"]:reference["byte_end"]] == reference["quote"].encode()
            retry = trial.admit(event.sequence, advisory_id, source.sha256, asset, target, *drafts, now=now)
            assert retry.outcome == "duplicate" and read_history(trial.path, "osv", advisory_id) == entry["history"]
            entry["retry"] = asdict(retry)
        return entry


def h53(pair, now, *, advance_modified):
    raw, target, advisory_id, uri, asset, drafts = case_setup("h53", pair, matches=[2], selected=[0],
                                                             outcome="unaffected")
    with scratch() as trial:
        source = snapshot("osv", uri, raw, retrieved_at=now)
        event, = trial.scout.ingest(source)
        assert trial.writer.consume(event.sequence, advisory_id, asset, scripted("unaffected"),
                                    now=now).outcome == "committed"
        before = read_history(trial.path, "osv", advisory_id)
        changed = json.loads(raw) | {"withdrawn": WITHDRAWAL}
        if advance_modified:
            changed["modified"] = WITHDRAWAL
        trial.scout.ingest(snapshot("osv", uri, canonical(changed), retrieved_at=now))
        receipt = trial.admit(event.sequence, advisory_id, source.sha256, asset, target, *drafts, now=now)
        status = "withdrawn" if advance_modified else "conflict"
        assert (receipt.outcome, receipt.reason) == ("held", status)
        return append_observation(trial, advisory_id, asset, before, receipt, history_status=status, count=1)


def h31(pair, now):
    raw, target, advisory_id, uri, asset, drafts = case_setup("h31", pair, matches=[0], selected=[0],
                                                             outcome="affected")
    pending = asset.model_copy(update={"asset_id": "synthetic-h31-pending"})
    pending_digest = asset_digest(pending)
    with scratch() as trial:
        source = snapshot("osv", uri, raw, retrieved_at=now)
        event, = trial.scout.ingest(source)
        assert trial.writer.consume(event.sequence, advisory_id, asset, scripted("affected"),
                                    now=now).outcome == "committed"
        before = read_history(trial.path, "osv", advisory_id)
        schedule = {}

        def supersede(evaluated):
            assert evaluated.check.status == "research-consistent"
            assert evaluated.candidate.reportable_outcome == "affected"
            schedule["evaluated_check"] = evaluated.check.status
            schedule["evaluated_outcome"] = evaluated.candidate.reportable_outcome
            schedule["pending_before"] = read_asset_report(trial.path, "osv", advisory_id, advisory_id,
                                                          pending_digest)
            assert schedule["pending_before"]["history"] == []
            changed = json.loads(raw) | {"modified": now.isoformat().replace("+00:00", "Z"),
                                         "summary": "Replacement synthetic revision."}
            with closing(ThreatScout(trial.path)) as replacement:
                newer, = replacement.ingest(snapshot("osv", uri, canonical(changed), retrieved_at=now))
            schedule["replacement_sequence"] = newer.sequence
            assert newer.sequence != event.sequence and newer.kind == "changed"

        receipt = trial.admit(event.sequence, advisory_id, source.sha256, pending, target, *drafts,
                              now=now, before_lock=supersede)
        assert (receipt.outcome, receipt.reason) == ("held", "superseded")
        result = append_observation(trial, advisory_id, pending, before, receipt,
                                    history_status="superseded", count=1)
        assert result["fresh_subject_report"]["history"] == []
        assert before[0]["asset_digest"] != pending_digest
        return result | {"schedule": schedule}


def h62(pair, now):
    original, target = pair
    augmented = json.loads(original)
    augmented["affected"].append({"package": {"ecosystem": "PyPI", "name": "tarnlark-fan"},
                                  "versions": ["2.0"]})
    raw, target, advisory_id, uri, asset, drafts = case_setup(
        "h62", (canonical(augmented), target), matches=[1, 2], selected=[0], outcome="affected",
    )
    with scratch() as trial:
        source = snapshot("osv", uri, raw, retrieved_at=now)
        event, = trial.scout.ingest(source)
        before = read_history(trial.path, "osv", advisory_id)
        standalone = check_b(raw, target, *drafts, arm="linked")
        assert standalone["reportable_outcome"] == "affected"
        conservative = assess(asset, normalize(source), advisory_id, now=now)
        assert conservative.outcome == "conflicting"
        receipt = trial.admit(event.sequence, advisory_id, source.sha256, asset, target, *drafts, now=now)
        assert (receipt.outcome, receipt.reason) == ("held", "conservative-policy-disagreement")
        result = append_observation(trial, advisory_id, asset, before, receipt,
                                    history_status="current", count=0)
        return result | {"standalone": standalone["reportable_outcome"], "conservative": conservative.outcome}


def run():
    freeze, pairs = sealed_inputs()
    now = datetime.fromisoformat(freeze["clock"])
    return {
        "clock": now.isoformat(),
        "h28-fresh": h28(pairs["h28"], now, retrieval=now),
        "h28-stale": h28(pairs["h28"], now, retrieval=datetime(2026, 11, 10, tzinfo=timezone.utc)),
        "h28-expired-at-commit": h28(pairs["h28"], now, retrieval=now - FRESHNESS_WINDOW,
                                     commit_now=now + timedelta(microseconds=1)),
        "h53-frozen-conflict": h53(pairs["h53"], now, advance_modified=False),
        "h53-advanced-withdrawal": h53(pairs["h53"], now, advance_modified=True),
        "h31-pending-superseded": h31(pairs["h31"], now),
        "h62-mixed-policy": h62(pairs["h62"], now),
    }


if __name__ == "__main__":
    import argparse

    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(run(), sort_keys=True, indent=2))
