"""Probe frozen local image identities. Never pull or mount host files."""
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent
cells = json.loads((root.parent / 'phase5b-release-acceptance/prerequisites.json').read_text())['cells']
results = []
for cell in cells:
    row = {'cell': cell['id'], 'image': cell['image_id'], 'verdict': 'BLOCKED'}
    if cell['image_id']:
        cmd = ['docker', '--context', 'colima', 'run', '--pull=never', '--rm', '--network=none',
               '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=65534:65534',
               '--workdir=/tmp', '--entrypoint=sh', cell['image_id'], '-c',
               'cat /etc/os-release && id && python3 -V; command -v strace || true']
        proc = subprocess.run(cmd, capture_output=True, text=True)
        row.update(command=cmd, exit=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    else:
        row['reason'] = 'No reviewed image ID supplied for this cell.'
    results.append(row)
(root / 'cells.json').write_text(json.dumps(results, indent=2) + '\n')
