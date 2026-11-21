"""Read the coordinator's retained s43 records and replay this singleton abstention offline."""
import json
import sys
from pathlib import Path
from score import canonical, make_target, read, sha

def replay(candidate, records):
    sys.path[:0]=[str(candidate/'src'),str(candidate/'benchmarks/phase6-offline-fixture-freeze')]
    from osv_row_selection import check
    def artifact(kind):
        return (records/f's43-multirow-selection.{kind}.json').read_bytes()
    response=artifact('response')
    r=json.loads(response)
    t=json.loads(artifact('transport'))
    a=json.loads(artifact('attempt'))
    assert json.loads(artifact('http'))=={'http_status':200}
    assert sha(response)==t['raw_reply_sha256'] and a['request_sha256']==t['create_sha256'] and a['attempt']==1
    assert r['model']==t['model'] and r['status']=='completed'
    message,=r['output']
    part,=message['content']
    assert message['type']=='message' and message['role']=='assistant' and part['type']=='output_text'
    raw_draft=part['text'].encode()
    assert json.loads(raw_draft)=={'proposed_outcome':'unknown','claims':[],'uncertainties':[]}
    assert t['model_proposal']=='unknown'
    assert r['usage']['input_tokens']==t['input_tokens'] and r['usage']['output_tokens']==t['output_tokens']
    case,=[c for c in read('seal/inputs.json') if c['id']=='s43']
    label,=[c for c in read('seal/labels.json') if c['id']=='s43']
    binding=read('contract/single-case.json')
    source=canonical(case['body'])
    assert sha(canonical(label))==binding['case_label_sha256'] and sha(source)==binding['source_sha256']
    assert label['decision']=='unaffected' and label['support']==['/affected/0']
    row=case['body']['affected'][0]
    assert row['package']=={'ecosystem':'PyPI','name':'lilac-cairn'} and row['ranges'][0]['events']==[{'introduced':'2.0'},{'fixed':'2.5'}]
    assert case['asset']['version']=='2.5' and case['asset']['identity']=='pkg:pypi/lilac-cairn'
    target=make_target(case)
    local=check(source,target,canonical({'proposed_outcome':'unknown','selected_row_ids':[]}))
    assert all(t[k]==v for k,v in local.items())
    saved,=[a for a in read('observations.json')['attempts'] if a['run']=='r02']
    scripted=check(source,target,canonical(saved['scripted_draft']))
    assert scripted==saved['observed'] and scripted['reportable_outcome']==label['decision']
    assert [ref['pointer'] for ref in scripted['references']]==label['support']
    print(json.dumps({'case':'s43','model':r['model'],'http_status':200,'saved_attempt_number':a['attempt'],
        'raw_reply_sha256':sha(response),'raw_draft_sha256':sha(raw_draft),'recorded_create_sha256':t['create_sha256'],
        'local_replay':local,'gold':label['decision'],'determinate_misses':1,'correct_decisions':0,'denominator':1,
        'false_affected':0,'false_unaffected':0,'pointer_precision':None,'gold_pointer_coverage':'0/1',
        'scripted_r02':{'reportable':scripted['reportable_outcome'],'pointers':label['support']},
        'provider_reported_tokens':[t['input_tokens'],t['output_tokens']],'billing_verified':t['billing_verified']},indent=2))

if __name__=='__main__':
    replay(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
