"""Measure the two applicability policies on the pre-frozen mixed-row control."""
from datetime import datetime
from pathlib import Path
import sys
from score import a_draft,b_draft,load,pack

def run(checkout):
    sys.path[:0]=[str(checkout/'src'),str(checkout/'benchmarks/phase6-offline-fixture-freeze')]
    import osv_two_stage as stage
    from aegis.intelligence.baseline import assess,normalize
    from aegis.intelligence.feeds import snapshot
    from aegis.intelligence.models import Asset
    from json import dumps
    folder=Path('seal/inputs/original/h62')
    target=load(folder/'target.json')
    osv=load(folder/'source.json')
    osv['affected'].append({'package':{'ecosystem':'PyPI','name':'tarnlark-fan'},'versions':['2.0']})
    raw,tgt=pack(osv),pack(target)
    a=stage.prepare_a(raw,tgt)
    lookup={f'/affected/{i}':r['row_id'] for i,r in enumerate(a['payload']['candidate_rows'])}
    identity=a_draft('match',['/affected/1','/affected/2'],lookup)
    b=stage.prepare_b(raw,tgt,identity,arm='linked')
    pos,=[r for r in b['payload']['candidate_rows'] if r['osv_row'].encode()==pack(osv['affected'][1])]
    sel=b_draft('affected',['/affected/1'],{'/affected/1':pos['row_id']})
    result=stage.check_b(raw,tgt,identity,sel,arm='linked')
    clock=datetime.fromisoformat('2026-11-20T00:00:00+00:00')
    source=snapshot('osv','https://example.invalid/'+osv['id'],raw,retrieved_at=clock)
    asset=Asset(asset_id='synthetic',identity_kind='purl',identity='pkg:pypi/tarnlark-fan',version='1.8')
    conservative=assess(asset,normalize(source),osv['id'],now=clock)
    assert result['reportable_outcome']=='affected' and conservative.outcome=='conflicting'
    print(dumps({'case':'h62 augmented per lifecycle freeze','standalone':result,
        'pinned_aegis_assess':conservative.outcome,'history_writes':0},indent=2))
if __name__=='__main__':
    run(Path(sys.argv[1]).resolve())
