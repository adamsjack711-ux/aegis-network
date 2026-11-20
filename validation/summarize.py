"""Aggregate each frozen unit once and independently verify install artifact pins."""
import gzip
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

root = Path(__file__).resolve().parent
load = lambda p: json.loads(p.read_bytes())
wheel = 'aegis_network-0.1.0-py3-none-any.whl'
preflight = load(root/'preflight.json')
expected = preflight['artifacts']['build-1'][wheel]
privacy = load(root/'privacy/summary.json')['cells']
cells = []
for name, effects in privacy.items():
    base = root/'console'/name
    installs = load(base/'install.json')['install']
    item = next(i for i in installs if urlparse(i['download_info']['url']).path.endswith('/'+wheel))
    assert item['download_info']['archive_info']['hashes']['sha256'] == expected
    outputs = [load(p) for p in sorted(base.glob('*-json.json'))]
    humans = [load(p) for p in sorted(base.glob('*-human.json'))]
    assert len(outputs) == len(humans) == 21 and all(r['passed'] for r in outputs+humans)
    assert effects['privacy_fail_invocations'] == 42
    assert (base/'uninstall.exit').read_text().strip() == '0'
    groups = [load(root/'resource/results'/name/f'{budget}m'/'summary.json') for budget in [512,256]]
    kids=[r for g in groups for r in g['children']]
    assert len({r['id'] for r in kids}) == len(kids) == 17
    cells.append(dict(cell=name,image=next(c['image'] for c in load(root.parent/'supply-prep/checks.json') if c['cell']==name),wheel_sha256=expected,install='PASS',uninstall='PASS',console_functional_pass=21,console_logical_with_privacy={'passed':0,'failed':21,'unrun':0},cache_attempts=effects['runtime_cache_write_attempts'],resource={'passed':sum(bool(r['pass']) for r in kids),'failed':[r['id'] for r in kids if not r['pass']],'unrun':0},hard_256=[{k:r[k] for k in ('id','exit_code','wall_seconds','cpu_seconds','peak_rss_mib','stdout_bytes','all_rows_exact','cgroup_oom_kill_delta','pass')} for r in groups[1]['children']]))
(root/'matrix.json').write_text(json.dumps(dict(candidate=preflight['candidate'],approval=preflight['approval'],decision='NO-GO',cells=cells),indent=2)+'\n')
