import email, hashlib, json, lzma, subprocess, urllib.request
from pathlib import Path
root=Path('../alpha-fc4a-inputs/debian').resolve()
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
sig=subprocess.run(['gpgv','--keyring',str(root/'keyring.gpg'),str(root/'InRelease')],check=True,capture_output=True,text=True)
release=(root/'InRelease').read_text().split('\nSHA256:\n')[1].split('\n-----')[0]
index=root/'Packages.xz'
assert any(line.split()==[digest(index),str(index.stat().st_size),'main/binary-arm64/Packages.xz'] for line in release.splitlines())
para=next(p for p in lzma.decompress(index.read_bytes()).decode().split('\n\n') if p.startswith('Package: strace\n'))
pkg=email.message_from_string(para)
assert pkg['Version']=='6.13+ds-1' and pkg['Architecture']=='arm64'
url='https://deb.debian.org/debian/'+pkg['Filename']
deb=root/'strace.deb'
deb.write_bytes(urllib.request.urlopen(url).read())
assert digest(deb)==pkg['SHA256']
cmd=['docker','--context','colima','run','--rm','--pull=never','--network=none','--read-only','--user','65534:65534','--cap-drop=ALL','--tmpfs','/tmp','-v',str(root)+':/in:ro','--entrypoint','sh','e48f59cdba69','-ec','dpkg-deb -x /in/strace.deb /tmp/pkg; sha256sum /tmp/pkg/usr/bin/strace']
h=subprocess.check_output(cmd,text=True).split()[0]
assert h==digest(root.parent/'strace')
Path('supply-prep/tracer-verification.json').write_text(json.dumps(dict(package_url=url,package_sha256=digest(deb),signature=sig.stderr,release_sha256=digest(root/'InRelease'),keyring_sha256=digest(root/'keyring.gpg'),index_sha256=digest(index),tracer_sha256=h),indent=2)+'\n')
