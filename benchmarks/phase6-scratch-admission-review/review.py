"""Independent, scratch-only admission probes. The only argument is the candidate checkout."""
import sys
import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime,timedelta
from hashlib import sha256
from pathlib import Path
root=Path(sys.argv[1]).resolve()
sys.path[:0]=[str(root/'src'),str(root/'benchmarks/phase6-offline-fixture-freeze')]
from scratch_history_admission import scratch
from aegis.intelligence.models import Asset
from aegis.intelligence.scout import ThreatScout
from aegis.intelligence.feeds import snapshot
from aegis.intelligence.handoff import read_history
from osv_two_stage import prepare_a,prepare_b
seal=Path(__file__).resolve().parents[1]/'phase6-two-stage-independent/seal'
clock=datetime.fromisoformat('2026-11-20T00:00:00+00:00')
def pack(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def dig(x):return sha256(x).hexdigest()
def case(k):
    folder=seal/'inputs/original'/k
    return json.loads((folder/'source.json').read_bytes()),json.loads((folder/'target.json').read_bytes())
def setup(trial,k,lookup,selected,outcome,age=0,mixed=False):
    osv,target=case(k)
    if mixed:osv['affected'].append({'package':{'ecosystem':'PyPI','name':'tarnlark-fan'},'versions':['2.0']})
    src,tgt=pack(osv),pack(target); aid=osv['id']
    uri=f'https://api.osv.dev/v1/vulns/{aid}'
    snap=snapshot('osv',uri,src,retrieved_at=clock-timedelta(days=age))
    seq,=trial.scout.ingest(snap)
    asset=Asset(asset_id='independent-fixture',identity_kind='purl',identity=f"pkg:{target['ecosystem'].lower()}/{target['package']}",version=target['version'])
    ap=prepare_a(src,tgt)['payload']['candidate_rows']
    ad=pack({'identity_outcome':'match','selected_row_ids':[ap[i]['row_id'] for i in lookup]})
    bp=prepare_b(src,tgt,ad,arm='linked')['payload']['candidate_rows']
    ids=[r['row_id'] for r in bp if r['osv_row'].encode() in [pack(osv['affected'][i]) for i in selected]]
    bd=pack({'proposed_outcome':outcome,'selected_row_ids':ids})
    return (seq.sequence,aid,dig(src),asset,tgt,ad,bd),osv,uri
def raw_rows(path):
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as reader:
        return reader.execute('SELECT sequence,vulnerability_id,asset_digest,investigation FROM research_results ORDER BY 1,2,3').fetchall()
def trace(trial,events):
    def note(sql):
        text=' '.join(sql.split()).upper()
        if text in ('BEGIN IMMEDIATE','ROLLBACK','COMMIT'):events.append(text)
        if 'FROM RESEARCH_REVISION_STATE S' in text and 'S.STATUS' in text:
            events.append('snapshot inside transaction' if trial.writer.db.in_transaction else 'snapshot before lock')
        if text.startswith('INSERT INTO RESEARCH_RESULTS'):
            events.append('insert while locked' if trial.writer.db.in_transaction else 'insert unlocked')
            with closing(sqlite3.connect(trial.path,timeout=0)) as competitor:
                try:competitor.execute('BEGIN IMMEDIATE')
                except sqlite3.OperationalError as e:events.append('competitor busy' if e.sqlite_errorcode==sqlite3.SQLITE_BUSY else e.sqlite_errorname)
                else:competitor.rollback();events.append('competitor acquired writer lock')
            events.append(f'{len(raw_rows(trial.path))} visible before insert')
    trial.writer.db.set_trace_callback(note)
def test(mode):
    k,lookup,sel,decision={
        'fresh':('h28',[1],[1],'affected'),'stale':('h28',[1],[1],'affected'),
        'boundary-age':('h28',[1],[1],'affected'),'superseded':('h31',[0],[0],'affected'),
        'conflict':('h53',[2],[2],'unaffected'),'withdrawal':('h53',[2],[2],'unaffected'),
        'mixed':('h62',[1,2],[1],'affected')}[mode]
    events=[]
    with scratch() as trial:
        args,osv,uri=setup(trial,k,lookup,sel,decision,age=10 if mode=='stale' else 7 if mode=='boundary-age' else 0,mixed=mode=='mixed')
        seq,aid,digest,asset,target,ad,bd=args
        if mode in ('superseded','conflict','withdrawal'):
            # Seed using the actual scratch path, then attempt a different, unused subject key.
            assert trial.admit(*args,now=clock).outcome=='committed'
            pending=asset.model_copy(update={'asset_id':'fresh-independent-subject'})
            args=(seq,aid,digest,pending,target,ad,bd)
        before=raw_rows(trial.path)
        before_read=read_history(trial.path,'osv',aid)
        def change_head(evaluated):
            assert evaluated.check.deterministic_outcome==decision and evaluated.candidate.reportable_outcome==decision
            updated=dict(osv)
            if mode=='superseded':
                updated.update(modified='2026-11-20T00:00:00Z',summary='Replacement synthetic revision.')
            else:
                updated['withdrawn']='2026-11-19T23:59:00Z'
                if mode=='withdrawal':updated['modified']=updated['withdrawn']
            with closing(ThreatScout(trial.path)) as other:
                event,=other.ingest(snapshot('osv',uri,pack(updated),retrieved_at=clock))
            events.append(f'separate Scout {event.kind} committed')
        trace(trial,events)
        hook=change_head if mode in ('superseded','conflict','withdrawal') else None
        end_clock=clock+timedelta(microseconds=1) if mode=='boundary-age' else clock
        receipt=trial.admit(*args,now=clock,commit_now=end_clock,before_lock=hook)
        trial.writer.db.set_trace_callback(None)
        after=raw_rows(trial.path);fresh=read_history(trial.path,'osv',aid)
        if mode=='fresh':
            assert receipt.outcome=='committed' and len(after)==1 and len(before)==0
            assert events==['snapshot before lock','BEGIN IMMEDIATE','snapshot inside transaction','insert while locked','competitor busy','0 visible before insert','COMMIT'], events
            candidate=fresh[0]['research']['candidate'];ref,=candidate['applicability_references'];excerpt,=candidate['excerpts']
            assert candidate['reportable_outcome']==decision and ref['pointer']=='/affected/1' and ref['sha256']==digest
            assert pack(osv)[excerpt['byte_start']:excerpt['byte_end']]==excerpt['quote'].encode()==pack(osv['affected'][1])
            assert trial.admit(*args,now=clock).outcome=='duplicate' and raw_rows(trial.path)==after
        else:
            expected={'stale':'stale-or-future-source','boundary-age':'stale-or-future-source','conflict':'conflict','withdrawal':'withdrawn','superseded':'superseded','mixed':'conservative-policy-disagreement'}[mode]
            assert (receipt.outcome,receipt.reason)==('held',expected),receipt
            assert before==after and len(fresh)==len(before_read)
            assert 'BEGIN IMMEDIATE' in events and 'snapshot inside transaction' in events and events[-1]=='ROLLBACK' and 'insert while locked' not in events
            if before_read:
                assert fresh==[r|{'status':expected} for r in before_read]
                assert all(r['asset_digest']!=dig(pack(args[3].model_dump(mode='json'))) for r in fresh)
    return {'receipt':asdict(receipt),'row_count_before':len(before),'row_count_after':len(after),'status_after':[r['status'] for r in fresh],'transaction_events':events}
if __name__=='__main__':print(json.dumps({m:test(m) for m in ('fresh','stale','boundary-age','conflict','withdrawal','superseded','mixed')},indent=2))
