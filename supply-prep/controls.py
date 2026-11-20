import json, subprocess
from pathlib import Path
base=Path('supply-prep')
for row in json.loads((base/'checks.json').read_text()):
    args=row['command'][:]
    args[args.index('/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777')]='/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777'
    pos=args.index('--entrypoint')
    args[pos:pos]=['--tmpfs','/tmp/venv:rw,exec,nosuid,nodev,uid=65534,gid=65534,mode=0700,size=256m','-v',str((base/'trace-control.py').resolve())+':/control.py:ro']
    args[-1]='set -eu; python3 -m venv /tmp/venv; /tmp/venv/bin/pip --version; /inputs/strace -f -e trace=%file,%network,%process,%creds -o /tmp/sample /tmp/venv/bin/python -B /control.py; cat /tmp/sample'
    p=subprocess.run(args,capture_output=True,text=True)
    log=base/(row['cell']+'-control.txt')
    log.write_text(p.stdout+p.stderr)
    assert p.returncode==0 and all(v in p.stdout for v in ['/tmp/control-write','/control-denied','connect(','/bin/true','setuid(0)','EPERM']), log
