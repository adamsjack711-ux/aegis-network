"""Independent scoring of frozen scripted decisions. Run from the evidence directory."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import sys
from copy import deepcopy

def read(name):
    return json.loads(Path(name).read_bytes())
def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def summarize(attempts, labels, expected):
    scores=Counter()
    for a in attempts:
        target=labels[a['case']]
        submitted=a['requested_pointers']
        refs=a['accepted_pointers']
        gold=set(target['support'])
        d=a['reportable']
        scores['attempts']+=1
        scores['guard_match']+=d==expected[a['run']]
        scores['decision_match']+=d==target['decision']
        scores['false_affected']+=d=='affected' and d!=target['decision']
        scores['false_unaffected']+=d=='unaffected' and d!=target['decision']
        scores['abstentions_including_refusals']+=d=='unknown'
        scores['misses_on_determinate']+=target['decision']!='unknown' and target['decision']!=d
        scores['determinate_targets']+=target['decision']!='unknown'
        scores['covered_determinate']+=target['decision']!='unknown' and set(refs)==gold and d==target['decision']
        scores['submitted_pointers']+=len(submitted)
        scores['submitted_correct_pointer_identity']+=sum(p in gold for p in submitted)
        scores['emitted_pointers']+=len(refs)
        scores['emitted_correct_pointer_identity']+=sum(p in gold for p in refs)
    return dict(scores)

def make_target(case):
    purl=case['asset']['identity']
    ecosystem,package=purl.removeprefix('pkg:').split('/',1)
    return canonical({'ecosystem':{'pypi':'PyPI','npm':'npm'}[ecosystem],
                      'package':package,'version':case['asset']['version']})

def resolve_ids(report,case):
    payload=report['payload']
    raw_rows=case['body']['affected']
    rows=payload['candidate_rows']
    assert len(rows)==len(raw_rows)
    assert all(set(row)=={'row_id','osv_row'} for row in rows)
    assert len({r['row_id'] for r in rows})==len(rows)
    oid={}
    for i,original in enumerate(raw_rows):
        match,=[r for r in rows if r['osv_row'].encode()==canonical(original)]
        oid[f'/affected/{i}']=match['row_id']
    return oid

def scores(all_rows,initial_labels,scenario_expected):
    overrides=read('contract/union.json')
    result={}
    for policy in ('conservative','union'):
        labels=deepcopy(initial_labels)
        expected=dict(scenario_expected)
        if policy=='union':
            for k,v in overrides['case_overrides'].items():
                labels[k].update(v)
            expected.update(overrides['run_overrides'])
        result[policy]={
            key:summarize(batch,labels,expected) for key,batch in
            [('primary',all_rows[:7]),('controls',all_rows[7:]),('all',all_rows)]}
    return result

def check_controls(selector, case):
    body=case['body']
    target=make_target(case)
    blob=canonical(body)
    original=canonical(body['affected'][2])
    spaced=json.dumps(body['affected'][2],indent=1).encode()
    formatted=blob.replace(original,spaced)
    prep=selector.prepare(formatted,target)
    row,=[r for r in prep['payload']['candidate_rows'] if r['osv_row'].encode()==spaced]
    selection=canonical({'proposed_outcome':'affected','selected_row_ids':[row['row_id']]})
    checked=selector.check(formatted,target,selection)
    ref,=checked['references']
    assert ref['pointer']=='/affected/2' and formatted[ref['byte_start']:ref['byte_end']]==spaced
    assert ref['source_sha256']==sha(formatted)
    results={'original_whitespace':'exact'}
    padded=deepcopy(body)
    padded['affected'][0]['database_specific']={'fixture_padding':'x'*12000}
    many=deepcopy(body)
    many['affected']=many['affected']*6
    for key,data in [('duplicate-member',b'{"id":"other",'+blob[1:]),
                     ('17-plus-rows',canonical(many)),('source-bytes',blob+b' '*24000),
                     ('rendered-request',canonical(padded))]:
        report=selector.prepare(data,target)
        assert report['status']=='refused' and not report['references'] and 'payload' not in report
        results[key]=report['reason']
    report=selector.check(blob,target,b' '*4097)
    assert report['status']=='refused' and not report['references']
    results['draft-bytes']=report['reason']
    return results

def main(candidate):
    sys.path[:0]=[str(candidate/'src'),str(candidate/'benchmarks/phase6-offline-fixture-freeze')]
    import osv_row_selection as selector
    fixtures={c['id']:c for c in read('seal/inputs.json')}
    labels={c['id']:c for c in read('seal/labels.json')}
    scripts=read('seal/scripts.json')
    attempts=[]
    for script in scripts:
        case=fixtures[script['case']]
        source=canonical(case['body'])
        assert sha(source)==labels[case['id']]['source_sha256']
        target=make_target(case)
        prep=selector.prepare(source,target)
        assert prep['status']=='prepared' and prep['source_sha256']==sha(source)
        assert set(prep['payload'])=={'candidate_rows','asset_context'}
        assert prep['payload']['asset_context']==json.loads(target)
        ids=resolve_ids(prep,case)
        selected=[ids[p] if p!='unissued' else 'r-'+'0'*24 for p in script['select']]
        assert all(i not in ids.values() for i,p in zip(selected,script['select']) if p=='unissued')
        draft=canonical({'proposed_outcome':script['proposal'],'selected_row_ids':selected})
        report=selector.check(source,target,draft)
        accepted=report['references']
        for ref in accepted:
            pointer=ref['pointer']
            b,e=ref['byte_start'],ref['byte_end']
            assert ref['source_sha256']==sha(source) and ref['row_id']==ids[pointer]
            assert ref['osv_row'].encode()==source[b:e]==canonical(case['body']['affected'][int(pointer.split('/')[-1])])
        if report['status']=='verified':
            assert len(accepted)==len(selected)
        else:
            assert report['reportable_outcome']=='unknown' and accepted==[]
        attempts.append({'run':script['run'],'case':case['id'],'proposal':script['proposal'],
                         'requested_pointers':script['select'],'reportable':report['reportable_outcome'],
                         'accepted_pointers':[r['pointer'] for r in accepted],
                         'prepared_request_sha256':prep['request_sha256'],'scripted_draft':json.loads(draft),
                         'observed':report})
    result={'attempts':attempts, 'scores':scores(attempts,labels,{s['run']:s['expected_reportable'] for s in scripts}),
            'interface_controls':check_controls(selector,fixtures['s17'])}
    print(json.dumps(result,indent=2))
if __name__=='__main__':
    main(Path(sys.argv[1]).resolve())
