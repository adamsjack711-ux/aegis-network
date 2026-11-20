import json, subprocess
from pathlib import Path
cells=json.loads(Path('benchmarks/linux-alpha-fc4a/cells.json').read_text())
cells[-2]['image']=subprocess.check_output(['docker','--context','colima','image','inspect','aegis-noble-312:fc4a','--format','{{.Id}}'],text=True).strip()
cells[-1]['image']=subprocess.check_output(['docker','--context','colima','image','inspect','aegis-noble-313:fc4a','--format','{{.Id}}'],text=True).strip()
results=[]
for cell in cells:
    cmd=['docker','--context','colima','run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user=65534:65534','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777','-v',str(Path('../alpha-fc4a-inputs').resolve())+':/inputs:ro','--entrypoint','sh',cell['image'],'-c',"""cat /etc/os-release; id; python3 -V
python3 -m venv /tmp/venv && /tmp/venv/bin/pip --isolated install --no-index --no-cache-dir --find-links /inputs/wheels hatchling==1.33.0 'cryptography>=44,<47' 'pydantic>=2.10,<3' 'fastapi>=0.115,<1' 'httpx>=0.27,<1' 'nats-py>=2.9,<3' 'psycopg[binary]>=3.2,<4' 'uvicorn>=0.30,<1' && /tmp/venv/bin/pip check
echo resolution_exit=$?
/inputs/strace -f -e trace=%file,%network,%process,%creds -o /tmp/sample python3 -B -c 'import socket,os; open("/tmp/sample-file","w").close(); socket.socket().close(); os.getuid()'
echo tracer_exit=$?
cat /tmp/sample"""]
    p=subprocess.run(cmd,capture_output=True,text=True)
    Path('supply-prep',cell['cell']+'.log').write_text(p.stdout+p.stderr)
    results.append(dict(cell=cell['cell'],image=cell['image'],command=cmd,markers=[v for v in p.stdout.splitlines() if v.startswith(('resolution_exit','tracer_exit','Python ','VERSION_ID'))]))
Path('supply-prep/checks.json').write_text(json.dumps(results,indent=2)+'\n')
