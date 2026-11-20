"""Forced schedules over three real connections. Run with pytest -s to retain observations."""
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from aegis.intelligence.feeds import snapshot
from aegis.intelligence.handoff import OfflineHandoff, read_history
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


def test_read_history_on_readonly_fixture(tmp_path, monkeypatch):
    folder = tmp_path / 'report'
    folder.mkdir()
    path = folder / 'research #1?.sqlite'
    scout = ThreatScout(path)
    worker = OfflineHandoff(path)
    try:
        event, = scout.ingest(source())
        assert worker.consume(event.sequence, VID, ASSET, PROVIDER, now=NOW).outcome == 'committed'
        # Seed a stored result in the candidate format that preceded structured references.
        current, = worker.history('osv', AID)
        legacy = json.loads(json.dumps(current['research']))
        legacy['candidate']['schema_version'] = 'research-candidate-v1'
        del legacy['candidate']['applicability_references']
        with worker.db:
            worker.db.execute('INSERT INTO research_results VALUES (?, ?, ?, ?)',
                              (event.sequence, VID, '0' * 64, json.dumps(legacy)))
        expected = worker.history('osv', AID)
        assert [row['research'] for row in expected] == [legacy, current['research']]
    finally:
        worker.close()
        scout.close()

    statements = []
    connect = sqlite3.connect

    def trace_connect(database, **kwargs):
        assert database == path.resolve().as_uri() + '?mode=ro' and kwargs == {'uri': True}
        db = connect(database, **kwargs)
        db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(sqlite3, 'connect', trace_connect)
    path.chmod(0o444)
    folder.chmod(0o555)
    try:
        if os.geteuid() != 0:
            assert not os.access(path, os.W_OK) and not os.access(folder, os.W_OK)
        assert read_history(path, 'osv', AID) == expected
        query, = statements
        assert query.lstrip().startswith('SELECT ')
        assert list(folder.iterdir()) == [path]
    finally:
        folder.chmod(0o755)
        path.chmod(0o644)


def test_read_history_after_withdrawal(tmp_path):
    path = tmp_path / 'local.sqlite'
    scout = ThreatScout(path)
    worker = OfflineHandoff(path)
    try:
        event, = scout.ingest(source())
        assert worker.consume(event.sequence, VID, ASSET, PROVIDER, now=NOW).outcome == 'committed'
        row, = read_history(path, 'osv', AID)
        assert row['status'] == 'current'
        scout.ingest(source(modified='2026-11-20T00:00:00Z', withdrawn='2026-11-20T00:00:00Z'))
        assert read_history(path, 'osv', AID) == worker.history('osv', AID) == [row | {'status': 'withdrawn'}]
    finally:
        worker.close()
        scout.close()


def test_read_history_requires_initialized_database(tmp_path):
    path = tmp_path / 'empty.sqlite'
    path.touch()
    with pytest.raises(sqlite3.OperationalError, match='Initialize this database'):
        read_history(path, 'osv', AID)
    assert path.read_bytes() == b''


@pytest.mark.parametrize('unreadable', [False, True], ids=['missing', 'unreadable'])
def test_read_history_open_diagnostic(tmp_path, monkeypatch, unreadable):
    monkeypatch.chdir(tmp_path)
    path = Path('private #1.sqlite')
    if unreadable:
        if os.geteuid() == 0:
            pytest.skip('file permission denial requires an unprivileged reader')
        ThreatScout(path).close()
        OfflineHandoff(path).close()
        original = path.read_bytes()
        path.chmod(0)
    try:
        if unreadable:
            assert not os.access(path, os.R_OK)
        before = set(tmp_path.iterdir())
        with pytest.raises(sqlite3.OperationalError) as caught:
            read_history(path, 'osv', AID)
        exc = caught.value
        assert exc.sqlite_errorcode == sqlite3.SQLITE_CANTOPEN
        assert exc.sqlite_errorname == 'SQLITE_CANTOPEN'
        assert str(path.resolve()) in str(exc)
        assert 'Check that the file exists' in str(exc)
        assert 'reader can read it' in str(exc)
        assert 'traverse its parent directories' in str(exc)
        assert set(tmp_path.iterdir()) == before
    finally:
        if unreadable:
            path.chmod(0o600)
    if unreadable:
        assert path.read_bytes() == original
        assert read_history(path, 'osv', AID) == []
