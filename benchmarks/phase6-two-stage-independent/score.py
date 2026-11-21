"""Offline independent scorer. Run from the evidence directory with a candidate checkout."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import sys

def pack(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def raw_hash(data):
    return hashlib.sha256(data).hexdigest()
def load(path):
    return json.loads(Path(path).read_bytes())
def case_inputs(label):
    folder=Path('seal/inputs')/label['variant']/label['case']
    source=(folder/'source.json').read_bytes()
    target=(folder/'target.json').read_bytes()
    assert raw_hash(source)==label['source_sha256'] and raw_hash(target)==label['target_sha256']
    for row in label['rows']:
        span=source[row['byte_start']:row['byte_end']]
        assert raw_hash(span)==row['row_sha256'] and json.loads(span)==json.loads(source)['affected'][int(row['pointer'].split('/')[-1])]
    return source,target
def bound_ids(lookup,pointers):
    bad=next(iter(lookup.values()),'r-').split('-')[0]+'-'+'0'*24
    assert bad not in lookup.values()
    return [lookup[p] if p!='UNISSUED' else bad for p in pointers]
def a_draft(outcome,pointers,lookup):
    return pack({'identity_outcome':outcome,'selected_row_ids':bound_ids(lookup,pointers)})
def b_draft(outcome,pointers,lookup):
    return pack({'proposed_outcome':outcome,'selected_row_ids':bound_ids(lookup,pointers)})
def verify_version_observation(report,label,source,expected):
    if expected is None:
        assert report['status']=='blocked' and not report.get('references')
        return
    if expected=='unknown':
        assert report['status']=='abstained' and not report.get('references')
        return
    assert report['status']=='verified' and report['reportable_outcome']==expected
    refs=report['references']
    assert sorted(r['pointer'] for r in refs)==sorted(label['support'])
    for ref in refs:
        row,=[r for r in label['rows'] if r['pointer']==ref['pointer']]
        assert ref['source_sha256']==label['source_sha256'] and (ref['byte_start'],ref['byte_end'])==(row['byte_start'],row['byte_end'])
        assert source[ref['byte_start']:ref['byte_end']]==ref['osv_row'].encode()

def primary(selector,label):
    src,target=case_inputs(label)
    # A renderer receives only source and target, before labels are consulted.
    a=selector.prepare_a(src,target)
    assert a['status']=='prepared'
    payload=a['payload']
    ctx=json.loads(target)
    assert set(payload)=={'asset_context','candidate_rows'}
    assert payload['asset_context']=={k:ctx[k] for k in ('ecosystem','package')}
    rows=json.loads(src)['affected']
    assert len(payload['candidate_rows'])==len(rows)
    a_lookup={}
    for i,(fields,row) in enumerate(zip(payload['candidate_rows'],rows,strict=True)):
        package=row['package']
        assert set(fields)=={'row_id','ecosystem','package','purl','purl_present'}
        assert fields['ecosystem']==package['ecosystem'] and fields['package']==package['name']
        assert fields['purl']==package.get('purl') and fields['purl_present']==('purl' in package)
        a_lookup[f'/affected/{i}']=fields['row_id']
    assert len(set(a_lookup.values()))==len(rows)
    # Changing only version evidence and the target version cannot alter A's request or IDs.
    changed=json.loads(src)
    for row in changed['affected']:
        row.pop('ranges',None);row['versions']=['0.0.0']
    check_blind=selector.prepare_a(pack(changed),pack(ctx|{'version':'0.0.1'}))
    assert a['request_sha256']==check_blind['request_sha256']
    gold=label['identity']
    ad=a_draft(gold,label['matching'],a_lookup)
    checked=selector.check_a(src,target,ad)
    assert checked['identity_outcome']==gold and checked['matched_pointers']==label['matching']
    assert checked['status']==('abstained' if gold=='unknown' else 'verified')
    admission={'oracle':pack({'matched_pointers':label['matching']}),'linked':ad}
    reports={}
    b_maps={}
    bhashes={}
    for arm,data in admission.items():
        bp=selector.prepare_b(src,target,data,arm=arm)
        if label['version'] is None:
            assert bp['status']=='blocked' and 'payload' not in bp
            reports[arm]=bp
            continue
        assert bp['status']=='prepared'
        bp_payload=bp['payload']
        assert set(bp_payload)=={'asset_context','candidate_rows'}
        assert bp_payload['asset_context']=={'version':ctx['version']}
        bhashes[arm]=bp['request_sha256']
        b_map={}
        for presented in bp_payload['candidate_rows']:
            assert set(presented)=={'row_id','osv_row'}
            raw=presented['osv_row'].encode()
            bound,=[r for r in label['rows'] if src[r['byte_start']:r['byte_end']]==raw]
            b_map[bound['pointer']]=presented['row_id']
        assert sorted(b_map)==sorted(label['matching'])
        assert len(bp_payload['candidate_rows'])==len(set(b_map.values()))==len(label['matching'])
        b_maps[arm]=b_map
        bd=b_draft(label['version'],label['support'],b_map)
        reports[arm]=selector.check_b(src,target,data,bd,arm=arm)
        verify_version_observation(reports[arm],label,src,label['version'])
    if bhashes: assert bhashes['oracle']==bhashes['linked']
    return ({'case':label['case'],'variant':label['variant'],'A':checked,'B':reports,
             'A_request_sha256':a['request_sha256'],'B_request_sha256':bhashes},
            (src,target,a_lookup,ad,b_maps,admission))

def negative(selector,test,contexts,labels):
    key=test['case']
    src,target,alook,ad,b_maps,admissions=contexts[key]
    arm=test['arm']
    draft=test.get('draft')
    if arm=='A':
        raw=b'{' if isinstance(draft,str) else a_draft(draft['identity_outcome'],draft['pointers'],alook)
        report=selector.check_a(src,target,raw)
        assert report['status']==test['expect'] and report['matched_pointers']==[]
        linked=selector.prepare_b(src,target,raw,arm='linked')
        assert linked['status']==test['linked'] and not linked.get('references') and 'payload' not in linked
        oracle=None
        if test['oracle'] is not None:
            label=labels[key]
            braw=b_draft(label['version'],label['support'],b_maps['oracle'])
            oracle=selector.check_b(src,target,admissions['oracle'],braw,arm='oracle')
            verify_version_observation(oracle,label,src,test['oracle'])
        return {'A':report,'linked':linked,'oracle':oracle}
    if arm=='oracle-admission':
        bad=pack({'matched_pointers':test['admit']})
        block=selector.prepare_b(src,target,bad,arm='oracle')
        assert block['status'] in ('blocked','refused') and not block.get('references') and 'payload' not in block
        return {'oracle':block}
    both={}
    for arm,data in admissions.items():
        raw=b'{' if isinstance(draft,str) else b_draft(draft['proposed_outcome'],draft['pointers'],b_maps[arm])
        both[arm]=selector.check_b(src,target,data,raw,arm=arm)
        assert both[arm]['status']==test['expect'] and not both[arm]['references'] and both[arm]['reportable_outcome']=='unknown'
    return both

def main(checkout):
    sys.path[:0]=[str(checkout/'src'),str(checkout/'benchmarks/phase6-offline-fixture-freeze')]
    import osv_two_stage as selector
    outputs=[]
    contexts={}
    labels={}
    for lab in load('seal/oracle/labels.json'):
        record,ctx=primary(selector,lab)
        outputs.append(record)
        if lab['variant']=='original':
            contexts[lab['case']]=ctx
            labels[lab['case']]=lab
    pairs={}
    for rec in outputs:
        sem=(rec['A']['identity_outcome'],{
            arm:(report['status'],report['reportable_outcome'],sorted(raw_hash(r['osv_row'].encode()) for r in report['references']))
            for arm,report in rec['B'].items()})
        if rec['variant']=='original':
            pairs[rec['case']]=sem
        else:
            assert pairs[rec['case']]==sem
    negatives=[{'run':n['run'],'observed':negative(selector,n,contexts,labels)} for n in load('seal/oracle/controls.json')]
    print(json.dumps({'primary_and_pairs':outputs,'negative_controls':negatives},indent=2))
if __name__=='__main__':
    main(Path(sys.argv[1]).resolve())
