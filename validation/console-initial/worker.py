import gzip, hashlib, json, os, shutil, stat, subprocess, uuid
from pathlib import Path

out=Path('/tmp/raw')
out.mkdir(exist_ok=True)
cli='/tmp/venv/bin/aegis'
def save(name,data):
    (out/name).write_text(json.dumps(data,indent=2)+'\n')
def sha(b):return hashlib.sha256(b).hexdigest()
def shell(args):
    return subprocess.run(args,text=True,capture_output=True)

pkg=Path('/var/lib/dpkg/status')
normal='Package: curl\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1:8.0-1\n\n'
pkg.write_text(normal)
Path('/tmp/outside').mkdir()
Path('/tmp/alias').symlink_to('/tmp/outside')
for key in ('HOME','XDG_STATE_HOME'):Path(os.environ[key]).mkdir(exist_ok=True)
save('mounts.json',Path('/proc/self/mountinfo').read_text().splitlines())
grant=Path('/grants/trust.json')
digest=sha(grant.read_bytes())
assert digest==os.environ['GRANT_SHA'] and not os.access(grant,os.W_OK) and not os.access(grant.parent,os.W_OK)
save('consumer.json',dict(uid=os.getuid(),gid=os.getgid(),grant_sha=digest,file_mode=oct(grant.stat().st_mode),dir_mode=oct(grant.parent.stat().st_mode)))
cache={}
def tree():
    result={}
    for root in ['/tmp','/var/lib/dpkg','/dev','/etc/hosts','/etc/resolv.conf','/etc/hostname']:
        def visit(p):
            if p==out or str(p) in ('/dev/pts','/dev/mqueue'):return
            s=p.lstat()
            row=[s.st_mode,s.st_uid,s.st_gid,s.st_mtime_ns]
            if stat.S_ISREG(s.st_mode):
                k=(s.st_dev,s.st_ino,s.st_ctime_ns,s.st_size)
                if k not in cache:cache[k]=sha(p.read_bytes())
                row.append(cache[k])
            elif p.is_symlink():row.append(os.readlink(p))
            result[str(p)]=row
            if stat.S_ISDIR(s.st_mode):
                for child in p.iterdir():visit(child)
        visit(Path(root))
    return result

def feed(name,trust='trust'):
    return ['findings','--feed','/grants/'+name+'.json','--trust','/grants/'+trust+'.json']
cases={'status':['status'],'inventory':['inventory'],'no-feed':['findings'],'missing':feed('missing'),'doctor':['doctor'],'explain':['explain','missing'],'current':feed('current'),'expired':feed('expired'),'withdrawn':feed('withdrawn'),'range':feed('range'),'malformed':feed('malformed'),'duplicate':feed('current'),'signature':feed('signature'),'grant':feed('current','wrong-role'),'future':feed('future'),'revoked':feed('current','revoked'),'conflict':feed('conflict')}
for case,path in [('create','chosen'),('repeat','chosen'),('ancestor','alias/chosen'),('final','alias')]:
    cases[case]=['--state-dir','/tmp/'+path,'inventory']
first={}
for fmt in ['json','human']:
    chosen=Path('/tmp/chosen')
    if chosen.exists():shutil.rmtree(chosen)
    for name,args in cases.items():
        pkg.write_text(normal*(2 if name=='duplicate' else 1))
        run=name+'-'+fmt
        trace=out/(run+'.trace')
        argv=[cli,*args]+(['--json'] if fmt=='json' else [])
        before=tree()
        proc=shell(['/strace','-f','-s','320','-yy','-e','trace=%file,%network,%process,%creds','-o',str(trace),*argv])
        after=tree()
        with gzip.open(str(trace)+'.gz','wb') as f:f.write(trace.read_bytes())
        trace.unlink()
        changed={k:[before.get(k),after.get(k)] for k in sorted(before.keys()|after.keys()) if before.get(k)!=after.get(k)}
        expected=0 if name in ('inventory','current','create','repeat') else 2
        okay=proc.returncode==expected and 'Traceback' not in proc.stderr
        try:
            if fmt=='json':
                d=json.loads(proc.stdout)
                if name in ('current','expired','withdrawn','range','duplicate','future'):
                    row=d['findings'][0]
                    match='unknown' if name in ('range','duplicate') else 'matched'
                    local={'expired':'expired','withdrawn':'withdrawn-in-supplied-file','future':'future'}.get(name,'current-in-supplied-file')
                    okay &= row['software_match']==match and row['local_claim_status']==local and row['independent_status']==row['overall_assessment']=='unknown' and row['publisher_authenticity']=='verified'
                    if name=='duplicate':okay &= not d['inventory_complete']
                elif name=='doctor':okay &= d['independent_status']=='unknown' and d['enforcement']=='unavailable'
                elif name=='status':okay &= d['mode']=='observation-only' and d['independent_status']=='unknown'
                elif name in ('inventory','create','repeat'):okay &= d['inventory_complete'] and d['package_count']==1
                else:okay &= d['status']==d['independent_status']=='unknown' and bool(d['error'])
            else:
                okay &= bool(proc.stdout.strip() or proc.stderr.strip())
                if name in ('current','expired','withdrawn','range','duplicate','future'):okay &= 'independent Evidence status unknown' in proc.stdout
            if name in ('create','repeat'):
                ident=json.loads((chosen/'identity.json').read_text())['asset_id']
                okay &= uuid.UUID(ident).version==4 and chosen.stat().st_mode&0o777==0o700 and (chosen/'identity.json').stat().st_mode&0o777==0o600
                if name=='create':first[fmt]=ident
                else:okay &= ident==first[fmt]
            if name=='create':okay &= set(changed)<= {'/tmp','/tmp/chosen','/tmp/chosen/identity.json'}
            else:okay &= not changed
        except Exception as exc:
            okay=False
            proc.stderr+='\noracle: '+repr(exc)
        save(run+'.json',dict(case=name,argv=argv,rc=proc.returncode,stdout=proc.stdout,stderr=proc.stderr,passed=okay,change=changed,before_sha256=sha(json.dumps(before,sort_keys=True).encode()),after_sha256=sha(json.dumps(after,sort_keys=True).encode())))
