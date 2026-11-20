import base64, copy, hashlib, json, os, subprocess, sys, tarfile, tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aegis.artifact import Finding, Revocation, sign, sign_revocation, canonical_bytes
import alpha_linux_release as release
base=Path(__file__).resolve().parent
root=base.parents[1]
inputs=root.parent/'alpha-bytecode-inputs'
wheel=next((inputs/'build-1').glob('*.whl'))
pin='fa8272b507a9b86168b4dd4d85e75a48d9b1699b'
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(p,o):p.write_text(json.dumps(o,indent=2)+'\n')
prov=release.validate_provenance(inputs/'wheels')
# Original independent review binds the unchanged dependency supply to the parent.
release.verify_install_review('fc4a17bc6f9f0c289a645c4fb7006c999ba90e99',prov)
assert subprocess.check_output(['git','rev-parse',pin+'^'],text=True).strip()=='fc4a17bc6f9f0c289a645c4fb7006c999ba90e99'
for name in ('build-1','build-2'):
    report=json.loads((inputs/name/'build-report.json').read_text())
    assert report['source_commit']==pin and report['wheel']['sha256']==digest(wheel)
assert digest(wheel)=='d537263a4e15e56dd2ffc940b2ad99c3b4e78486d09b21e52fd69383eb64f50b'
assert digest(inputs/'strace')=='e4f0c42a07574df2fc6b353f5bc24423099d8c896cee72c605671d878fedeb5a'
def fixture(g, distro):
    orig=root/'fixtures/phase-next-cli'
    key=Ed25519PrivateKey.generate()
    grant=json.loads((orig/'trust.json').read_text())
    entry=grant['grants'][0]
    now=datetime.now(timezone.utc)
    entry.update(public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),not_before=(now-timedelta(days=2)).isoformat(),expires_at=(now+timedelta(days=1)).isoformat())
    save(g/'trust.json',grant)
    save(g/'wrong-role.json',{'grants':[dict(entry,roles=['revocation'])]})
    save(g/'revoked.json',{'grants':[dict(entry,revoked_at=(now-timedelta(minutes=1)).isoformat())]})
    def obj(name):return json.loads((orig/('signed-'+name+'.json')).read_text())['events']
    def payload(name):
        f=obj(name)[0]['finding']
        f['software']['purl']='pkg:deb/'+distro+'/curl'
        return Finding.model_validate(f)
    def signed(f):return sign(f,key,'validator').model_dump(mode='json')
    def feed(name,*events):save(g/(name+'.json'),dict(adapter_version='mesh-events-v1',events=events))
    f=payload('current')
    a=signed(f)
    feed('current',a)
    feed('expired',signed(payload('expired')))
    feed('range',signed(payload('unsupported-range')))
    rev=obj('withdrawn')[1]['revocation']
    rev['target_sha256']=hashlib.sha256(canonical_bytes(f)).hexdigest()
    feed('withdrawn',a,sign_revocation(Revocation.model_validate(rev),key,'validator').model_dump(mode='json'))
    feed('future',signed(f.model_copy(update={'issued_at':now+timedelta(hours=1)})))
    feed('signature',dict(a,signature=base64.b64encode(bytes(64)).decode()))
    feed('conflict',a,signed(f.model_copy(update={'vulnerability_id':'AEGIS-CONFLICT'})))
    (g/'malformed.json').write_text('{invalid')
    for item in g.iterdir():item.chmod(0o444)
    g.chmod(0o555)

script="""set -eu
mkdir -p /tmp/raw
cd /tmp
id >raw/uid; python3 -V >raw/python; cat /etc/os-release >raw/os-release
sha256sum /dist/*.whl >raw/wheel.sha256
python3 -m venv /tmp/venv
/tmp/venv/bin/pip --isolated install --no-index --no-cache-dir --find-links /wheels --report /tmp/raw/install.json /dist/*.whl >raw/install.log
/tmp/venv/bin/python /worker.py >raw/worker.out 2>raw/worker.err || echo $? >raw/worker.failure
/tmp/venv/bin/pip --isolated uninstall -y aegis-network >raw/uninstall.log
test ! -e /tmp/venv/bin/aegis
/tmp/venv/bin/python -c 'import importlib.util,importlib.metadata as m; assert importlib.util.find_spec("aegis") is None; assert not list(m.distributions(name="aegis-network"))'
echo 0 >raw/uninstall.exit
tar -C raw -czf - .
"""
def run(row):
    dest=base/row['cell'];dest.mkdir()
    with tempfile.TemporaryDirectory(dir=root.parent) as tmp:
        g=Path(tmp);fixture(g,row['cell'].split('-')[0])
        try:
            (dest/'custody.txt').write_bytes(subprocess.check_output(['ls','-lde',*map(str,[*g.parents,g,*sorted(g.iterdir())])]))
            save(dest/'issuer.json',dict(issuer_uid=os.getuid(),custodian_uid=os.getuid(),consumer_uid=65534,digests={p.name:digest(p) for p in g.iterdir()}))
            cmd=['docker','--context','colima','run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user','65534:65534','--tmpfs','/tmp:rw,noexec,nosuid,nodev,mode=1777,size=512m','--tmpfs','/tmp/venv:rw,exec,nosuid,nodev,mode=0700,uid=65534,gid=65534,size=256m','--tmpfs','/var/lib/dpkg:rw,noexec,nosuid,nodev,mode=0700,uid=65534,gid=65534','-e','GRANT_SHA='+digest(g/'trust.json'),'-e','HOME=/tmp/home','-e','XDG_STATE_HOME=/tmp/xdg','-e','PIP_DISABLE_PIP_VERSION_CHECK=1']
            for host,mount in [(inputs/'wheels','/wheels'),(wheel.parent,'/dist'),(inputs/'strace','/strace'),(base/'worker.py','/worker.py'),(g,'/grants')]:cmd+=['-v',f'{host}:{mount}:ro']
            cmd+=['--entrypoint','sh',row['image'],'-c',script]
            save(dest/'command.json',cmd)
            with tempfile.TemporaryFile() as f:
                p=subprocess.run(cmd,stdout=f,stderr=subprocess.PIPE)
                (dest/'docker.stderr').write_bytes(p.stderr)
                (dest/'docker.exit').write_text(str(p.returncode))
                if p.returncode==0:
                    f.seek(0)
                    with tarfile.open(fileobj=f,mode='r:gz') as t:t.extractall(dest,filter='data')
                    release.verify_pip_report(json.loads((dest/'install.json').read_text()),prov,wheel)
        finally:g.chmod(0o700)
with ThreadPoolExecutor(2) as pool:list(pool.map(run,json.loads((root/'supply-prep/checks.json').read_text())))
