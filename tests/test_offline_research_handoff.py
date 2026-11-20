"""Forced schedules over three real connections. Run with pytest -s to retain observations."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.handoff import OfflineHandoff
from aegis.intelligence.investigator import ScriptedProvider
from aegis.intelligence.models import Asset
from aegis.intelligence.scout import ThreatScout

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)
ROW = json.loads((Path(__file__).parent / 'fixtures/scout-corpus-v1.json').read_text())['entries'][0]
VID = 'CVE-2099-0001'
AID = 'OSV-2099-1'
ASSET = Asset(asset_id='local', identity_kind='purl', identity='pkg:pypi/acme-parser', version='1.5')
QUOTE = '"fixed":"2.0"'
PROVIDER = ScriptedProvider(dict(proposed_outcome='affected', uncertainties=[], claims=[
    dict(source_id='S1', kind='applicability', quote=QUOTE)]))


def source(**edit):
    content = json.dumps(ROW['body'] | edit, sort_keys=True, separators=(',', ':')).encode()
    return snapshot('osv', ROW['uri'], content, retrieved_at=NOW)


@pytest.mark.parametrize('case', ['normal', 'before-pickup', 'during-processing', 'result-first', 'replay-restart'])
def test_frozen_schedule(tmp_path, case):
    path = tmp_path / 'local.sqlite'
    scout = ThreatScout(path)
    worker = OfflineHandoff(path)
    reader = OfflineHandoff(path)
    trace = []

    def observe(label, statuses):
        rows = reader.history('osv', AID)
        observed = [row['status'] for row in rows]
        trace.append(dict(point=label, visible=observed))
        assert observed == statuses
        return rows

    def ingest(src):
        event, = scout.ingest(src)
        trace.append(dict(commit='scout', sequence=event.sequence, revision=src.sha256,
                          withdrawn=event.advisory.withdrawn_at))
        return event.sequence

    def withdraw():
        assert ingest(source(modified='2026-11-20T00:00:00Z', withdrawn='2026-11-20T00:00:00Z')) == 2

    def consume(outcome):
        receipt = worker.consume(seq, VID, ASSET, PROVIDER, now=NOW)
        trace.append(dict(commit=receipt.outcome, reason=receipt.reason, pinned=receipt.sequence))
        assert receipt.outcome == outcome
        if outcome == 'held':
            assert receipt.reason == 'withdrawn'

    try:
        seq = ingest(source())
        assert seq == 1 and source().sha256 == ROW['sha256']
        observe('queued', [])
        if case == 'before-pickup':
            withdraw()
            with patch('aegis.intelligence.handoff.investigate', side_effect=AssertionError('stale pickup')):
                consume('held')
            observe('after-pickup', [])
        elif case == 'during-processing':
            commit = worker._commit

            def paused(*args):
                observe('prepared-before-final-write', [])
                withdraw()
                observe('withdrawal-committed-before-resume', [])
                return commit(*args)

            with patch.object(worker, '_commit', paused):
                consume('held')
            observe('after-resume', [])
        else:
            consume('committed')
            record, = observe('after-result', ['current'])
            result = record['research']['candidate']
            assert record['revision'] == result['source_dispositions'][0]['source_sha256'] == ROW['sha256']
            assert record['advisory_id'] == result['advisory_id'] == AID and record['sequence'] == seq
            assert record['source_uri'] == ROW['uri'] and record['provenance'] == 'synthetic-fixture'
            assert result['vulnerability_id'] == VID and result['reportable_outcome'] == 'affected'
            assert result['independently_verified'] is False and result['provider'] == 'scripted'
            excerpt, = result['excerpts']
            assert source().content[excerpt['byte_start']:excerpt['byte_end']] == QUOTE.encode()
            trace.append(dict(advisory=AID, selected_id=VID, revision=record['revision'],
                              source_uri=record['source_uri'], excerpt=excerpt, asset_digest=record['asset_digest']))
            if case == 'normal':
                consume('duplicate')
                observe('duplicate-delivery', ['current'])
            else:
                withdraw()
                old, = observe('after-withdrawal', ['withdrawn'])
                assert old == record | {'status': 'withdrawn'}
                if case == 'replay-restart':
                    consume('held')
                    worker.close()
                    worker = OfflineHandoff(path)
                    trace.append(dict(point='consumer-reopened'))
                    assert scout.ingest(source()) == ()
                    consume('held')
                    assert observe('after-replay-and-restart', ['withdrawn']) == [old]
    finally:
        print(json.dumps(dict(case=case, advisory=AID, trace=trace), sort_keys=True))
        worker.close()
        reader.close()
        scout.close()


def test_mapping_holds(tmp_path):
    path = tmp_path / 's'
    scout = ThreatScout(path)
    worker = OfflineHandoff(path)
    try:
        seq, = scout.ingest(source())
        assert worker.consume(seq.sequence, 'unselected', ASSET, PROVIDER).reason == 'unknown-vulnerability-id'
        with scout.db:
            scout.db.execute("UPDATE snapshots SET content=x'7b7d'")
        assert worker.consume(seq.sequence, VID, ASSET, PROVIDER).outcome == 'held'
        assert worker.history('osv', AID) == []
    finally:
        worker.close()
        scout.close()


@pytest.mark.parametrize('edit', [
    {'affected': []},
    {'affected': [{'package': {'name': 'acme-parser', 'ecosystem': 'PyPI'}}]},
    {'affected': [{'versions': ['1.5']}]},
    {'affected': [{'package': {'name': 'acme-parser', 'ecosystem': 'PyPI'},
                   'ranges': [{'type': 'GIT', 'events': [{'introduced': '0'}]}]}]},
])
def test_incomplete_or_unsupported_projection_holds(tmp_path, edit):
    path = tmp_path / 'local.sqlite'
    scout = ThreatScout(path)
    worker = OfflineHandoff(path)
    try:
        event, = scout.ingest(source(**edit))
        assert worker.consume(event.sequence, VID, ASSET, PROVIDER, now=NOW).outcome == 'held'
        assert worker.history('osv', AID) == []
    finally:
        worker.close()
        scout.close()


def test_archive_preserves_uncertainty_and_conflict_blocks_even_if_pointer_stays(tmp_path):
    path = tmp_path / 'local.sqlite'
    scout = ThreatScout(path)
    worker = OfflineHandoff(path)
    try:
        event, = scout.ingest(source().model_copy(update={'acquisition': 'https'}))
        different = ASSET.model_copy(update={'identity': 'pkg:pypi/other'})
        assert worker.consume(event.sequence, VID, different, PROVIDER, now=NOW).outcome == 'committed'
        row, = worker.history('osv', AID)
        assert (row['provenance'], row['redistribution']) == ('unverified-archive', 'unknown')
        assert row['research']['candidate']['reportable_outcome'] == 'unknown'
        assert row['research']['candidate']['independently_verified'] is False
        conflict, = scout.ingest(source(summary='Incompatible same-time revision'))
        assert conflict.kind == 'conflict'
        assert worker.consume(event.sequence, VID, different, PROVIDER, now=NOW).reason == 'conflict'
        assert worker.history('osv', AID)[0]['status'] == 'conflict'
    finally:
        worker.close()
        scout.close()
