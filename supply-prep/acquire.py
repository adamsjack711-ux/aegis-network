import json, subprocess, sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
root=Path('/private/tmp/aegis-fc4a-acquisition')
cells=json.loads(Path('benchmarks/linux-alpha-fc4a/cells.json').read_text())
requirements=['hatchling==1.33.0','cryptography>=44,<47','pydantic>=2.10,<3','fastapi>=0.115,<1','httpx>=0.27,<1','nats-py>=2.9,<3','psycopg[binary]>=3.2,<4','uvicorn>=0.30,<1']
def acquire(cell):
    dest=root/cell['cell']
    dest.mkdir(exist_ok=True)
    cmd=['docker','--context','colima','run','--pull=never','--rm','--cap-drop=ALL','--security-opt=no-new-privileges','--user=65534:65534','--entrypoint','sh',cell['image'],'-ec','mkdir /tmp/download; python3 -m pip "$@" >&2; tar -C /tmp/download -cf - .','sh','--isolated','--disable-pip-version-check','download','--index-url','https://pypi.org/simple','--no-cache-dir','--only-binary=:all:','-d','/tmp/download',*requirements]
    with (dest/'originals.tar').open('wb') as stream:
        p=subprocess.run(cmd,stdout=stream,stderr=subprocess.PIPE,text=True)
    Path('supply-prep',cell['cell']+'-download.log').write_text(p.stderr+'\nexit='+str(p.returncode))
    if p.returncode == 0:
        subprocess.run(['tar','-xf',str(dest/'originals.tar'),'-C',str(dest)],check=True)
with ThreadPoolExecutor(2) as pool:
    list(pool.map(acquire,cells[:2]))
