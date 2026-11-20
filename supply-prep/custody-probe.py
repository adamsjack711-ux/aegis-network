"""Exercise a disposable public grant mount, without logging keys or grant bytes."""
import base64, hashlib, json, os, subprocess, tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

rows = json.loads(Path('supply-prep/checks.json').read_bytes())
reports = []
for row in rows:
    with tempfile.TemporaryDirectory(dir=Path('..').resolve()) as name:
        path = Path(name) / 'grant.json'
        now = datetime.now(timezone.utc)
        key = Ed25519PrivateKey.generate()
        pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        grant = dict(publisher_id='fixture', key_id='fixture-key', public_key=pub, roles=['finding'], not_before=now.isoformat(), expires_at=(now+timedelta(minutes=10)).isoformat(), revoked_at=None)
        del key
        path.write_text(json.dumps({'grants':[grant]}))
        path.chmod(0o444)
        path.parent.chmod(0o555)
        try:
            host=subprocess.check_output(['ls','-lde',str(path),*[str(p) for p in path.parents]],text=True)
            cmd=['docker','--context','colima','run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user','65534:65534','-v',name+':/grants:ro','--entrypoint','sh',row['image'],'-ec',"""id; stat -c '%n %u:%g %a' / /grants /grants/grant.json; test -r /grants/grant.json; test ! -w /grants/grant.json; test ! -w /grants; sha256sum /grants/grant.json; awk '$5 == "/grants" {print $5,$6}' /proc/self/mountinfo"""]
            out=subprocess.check_output(cmd,text=True)
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            assert digest in out and '/grants ro,' in out
            reports.append(dict(cell=row['cell'],issuer_uid=os.getuid(),custodian_uid=os.getuid(),public_grant_sha256=digest,host_permissions=host,consumer=out))
        finally:
            path.parent.chmod(0o700)
Path('supply-prep/custody.json').write_text(json.dumps(reports,indent=2)+'\n')
