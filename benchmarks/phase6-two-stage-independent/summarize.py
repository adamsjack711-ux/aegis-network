"""Summarize observations using the precommitted denominators."""
from collections import Counter
from pathlib import Path
import json
import sys

def count(rows,field):
    return dict(Counter(r[field] for r in rows))
def group(outputs,gold):
    identity=[r['A'] for r in outputs]
    summary={'A':{'cases':len(outputs),'status':count(identity,'status'),'decisions':count(identity,'identity_outcome')}}
    a=summary['A']
    a['gold_matching_pointers']=sum(len(gold[r['case']]['matching']) for r in outputs)
    a['extra_ids']=sum(len(set(r['A']['matched_pointers'])-set(gold[r['case']]['matching'])) for r in outputs)
    a['missed_ids']=sum(len(set(gold[r['case']]['matching'])-set(r['A']['matched_pointers'])) for r in outputs)
    a['correct_identity_decision_and_set']=sum(r['A']['identity_outcome']==gold[r['case']]['identity'] and sorted(r['A']['matched_pointers'])==sorted(gold[r['case']]['matching']) for r in outputs)
    for arm in ('oracle','linked'):
        rs=[r['B'][arm] for r in outputs]
        col=summary[arm]={'cases_including_blocks':len(rs),'status':count(rs,'status')}
        col.update({k:0 for k in ('determinate','correct_determinate','warranted_unknown','correct_warranted_unknown','false_affected','false_unaffected','supported_refs','emitted_refs')})
        for ctx,r in zip(outputs,rs,strict=True):
            label=gold[ctx['case']]
            v=label['version']
            d=r['reportable_outcome']
            if v in ('affected','unaffected'):
                col['determinate']+=1
                col['correct_determinate']+=v==d
            if v=='unknown':
                col['warranted_unknown']+=1
                col['correct_warranted_unknown']+=r['status']=='abstained' and d=='unknown'
            col['false_affected']+=d=='affected' and d!=v
            col['false_unaffected']+=d=='unaffected' and d!=v
            col['supported_refs']+=sum(ref['pointer'] in label['support'] for ref in r['references'])
            col['emitted_refs']+=len(r['references'])
    return summary

def main(path):
    evidence=json.loads(Path(path).read_bytes())
    gold={l['case']:l for l in json.loads(Path('seal/oracle/labels.json').read_bytes()) if l['variant']=='original'}
    summary={}
    for variant in ('original','reverse'):
        outputs=[r for r in evidence['primary_and_pairs'] if r['variant']==variant]
        mapping=gold if variant=='original' else {l['case']:l for l in json.loads(Path('seal/oracle/labels.json').read_bytes()) if l['variant']==variant}
        summary[variant]=group(outputs,mapping)
    entries=evidence['negative_controls']
    summary['controls']={'scenarios':len(entries),'status_by_arm':{}}
    for arm in ('A','oracle','linked'):
        records=[r['observed'][arm] for r in entries if r['observed'].get(arm)]
        summary['controls']['status_by_arm'][arm]=count(records,'status')
    print(json.dumps(summary,indent=2))

if __name__=='__main__':
    main(sys.argv[1])
