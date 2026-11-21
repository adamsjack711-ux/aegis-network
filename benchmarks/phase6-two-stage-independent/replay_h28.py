"""Score a native stage response against the independently preselected h28 label."""
from pathlib import Path
import sys,json
from score import case_inputs,load,pack,raw_hash
def replay(candidate,stage,raw):
    sys.path[:0]=[str(candidate/'src'),str(candidate/'benchmarks/phase6-offline-fixture-freeze')]
    import osv_two_stage as checker
    selection=load('live-preselection.json')
    label,=[l for l in load('seal/oracle/labels.json') if l['case']==selection['case'] and l['variant']==selection['variant']]
    assert raw_hash(pack(label))==selection['case_gold_sha256']
    source,target=case_inputs(label)
    raw_bytes=raw.read_bytes()
    r=json.loads(raw_bytes)
    assert r['object']=='response' and r['status']=='completed' and r['model']=='gpt-5.4-mini-2026-03-17'
    msg,=[m for m in r['output'] if m['type']=='message'];part,=msg['content']
    assert msg['role']=='assistant' and msg['status']=='completed' and part['type']=='output_text'
    draft=part['text'].encode()
    if stage=='A':
        prepared=checker.prepare_a(source,target)
        result=checker.check_a(source,target,draft)
        gold=selection['A']
        exact=(result['identity_outcome']==gold['expected'] and result['matched_pointers']==gold['exact_pointers'])
        ptrs=result['matched_pointers'];desired=gold['exact_pointers']
    else:
        gold=selection['oracle_B']
        admission=pack({'matched_pointers':gold['admission_pointers']})
        prepared=checker.prepare_b(source,target,admission,arm='oracle')
        result=checker.check_b(source,target,admission,draft,arm='oracle')
        ptrs=[ref['pointer'] for ref in result['references']]
        desired=[ref['pointer'] for ref in gold['exact_source_support']]
        exact=result['reportable_outcome']==gold['expected']
        for ref in result['references']:
            assert ref['source_sha256']==raw_hash(source) and source[ref['byte_start']:ref['byte_end']]==ref['osv_row'].encode()
    assert prepared['instructions']==r['instructions']
    expected=sorted(desired)
    return {'stage':stage,'gold':gold['expected'],'draft':json.loads(draft),'observed':result,
        'decision_or_complete_identity_correct':bool(exact),'exact_gold_pointers':sorted(ptrs)==expected,
        'pointer_hits':len(set(ptrs)&set(expected)),'emitted':len(ptrs),'gold_count':len(expected),
        'raw_reply_sha256':raw_hash(raw_bytes),'raw_draft_sha256':raw_hash(draft),'prepared_request_sha256':prepared['request_sha256'],
        'usage':{'input_tokens':r['usage']['input_tokens'],'output_tokens':r['usage']['output_tokens']}}

def main(candidate,records,bodies):
    import json
    notes={}
    for stage in 'AB':
        def artifact(key):
            return records/f'h28-two-stage-{stage}.{key}.json'
        notes[stage]=n=replay(candidate,stage,artifact('response'))
        import two_stage_trial as trial
        from osv_two_stage import prepare_b
        e=trial.replay(stage,artifact('response').read_bytes())
        t=load(artifact('transport'))
        assert e==t and n['observed']==t['check'] and n['draft']==t['draft']
        assert n['usage']=={k:t[k] for k in ('input_tokens','output_tokens')}
        assert n['raw_draft_sha256']==t['draft_sha256'] and n['raw_reply_sha256']==t['response_sha256']
        wire=(bodies/f'{stage}.json').read_bytes()
        assert trial.request_body(stage)==wire
        attempt=load(artifact('attempt'))
        assert attempt['attempt']==1 and load(artifact('http'))=={'http_status':200}
        assert raw_hash(wire)==attempt['request_sha256']==t['evaluated_contract_body_sha256']
        n.update(http_status=200,recorded_attempt=1,retained_wire_sha256=raw_hash(wire),model=t['model'])
    source,target=trial.fixture()
    linked=prepare_b(source,target,pack(notes['A']['draft']),arm='linked')
    assert trial.build_request('B',linked)==(bodies/'B.json').read_bytes()
    span,=notes['B']['observed']['references']
    gold,=load('live-preselection.json')['oracle_B']['exact_source_support']
    assert all(span[k]==gold[k] for k in ('pointer','byte_start','byte_end')) and raw_hash(span['osv_row'].encode())==gold['row_sha256']
    print(json.dumps({'case':'original/h28','review_pin':'703d32413bfd6da4877a4de3b4a892a339dec042','live_probes':notes,
      'linked_B_constructed_offline_equals_oracle_B_wire':True,'linked_B_live_calls':0,
      'request_provenance':'reconciled local attempt, HTTP, response, transport and wire files; not provider-attested request digests'},indent=2))
if __name__=='__main__':
    main(*(Path(arg).resolve() for arg in sys.argv[1:]))
