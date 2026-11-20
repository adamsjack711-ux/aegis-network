"""Cross-check final artifacts, pip receipts, console denominators and resource limits."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
candidate = '7f9f2a23909ad4f3aee7a5860ea1d5bed8e57730'
wheel = 'd537263a4e15e56dd2ffc940b2ad99c3b4e78486d09b21e52fd69383eb64f50b'
sdist = '8bf568725cc7f39b291a531b4cbd6018cef171e56a546e2bbb0e1d5f41e45ed2'
def read(path):
    return json.loads(path.read_bytes())

for i in (1, 2):
    report = read(root / 'builds' / f'final-{i}.json')
    assert report['source_commit'] == candidate
    for key, digest in [('wheel', wheel), ('sdist', sdist)]:
        artifact = report[key]
        assert artifact['sha256'] == digest
        assert hashlib.sha256((root / 'builds' / artifact['file']).read_bytes()).hexdigest() == digest

privacy = read(root / 'independent/analysis.json')
scoped = read(root / 'independent/explicit-state.json')
cells = []
for env in read(root.parent / 'supply-prep/checks.json'):
    cell = env['cell']
    console = root / 'console' / cell
    assert (console / 'docker.exit').read_text().strip() == '0'
    assert (console / 'uninstall.exit').read_text().strip() == '0'
    assert (console / 'wheel.sha256').read_text().split()[0] == wheel
    pkg, = [r for r in read(console / 'install.json')['install'] if r['metadata']['name'] == 'aegis-network']
    assert pkg['download_info']['archive_info']['hashes']['sha256'] == wheel
    assert pkg['metadata']['version'] == '0.1.0'
    traces = [r for r in privacy['cases'] if r['cell'] == cell]
    for fmt in ('json','human'):
        rows = [r for r in traces if r['case'].endswith('-' + fmt)]
        assert len(rows) == 21
        for row in rows:
            case = row['case']
            assert read(console / (case + '.json'))['passed']
            assert row['status'] == 'pass' or (row['status'] == 'review' and case in scoped[cell])
            assert row['runtime_cache_write_attempts'] == 0
    resource = root / 'resource/results' / cell
    groups = [read(resource / f'{budget}m/summary.json')['children'] for budget in (512, 256)]
    hard = groups[1]
    assert len({r['id'] for group in groups for r in group}) == 17
    assert all(r['pass'] for group in groups for r in group)
    assert len(hard) == 3 and all(r['all_rows_exact'] and r['rows'] == 100000 and r['cgroup_oom_kill_delta'] == 0 for r in hard)
    cells.append(dict(cell=cell, image=env['image'], wheel_sha256=wheel, install='PASS', uninstall='PASS',
                      console_pass_fail_unrun=[21,0,0], traced_invocations=len(traces),
                      resource_pass_fail_unrun=[17,0,0], hard_peak_rss_mib=max(r['peak_rss_mib'] for r in hard),
                      hard_max_wall_s=max(r['wall_seconds'] for r in hard), hard_max_cpu_s=max(r['cpu_seconds'] for r in hard)))
print(json.dumps(dict(candidate=candidate, sdist_sha256=sdist, cells=cells),indent=2))
