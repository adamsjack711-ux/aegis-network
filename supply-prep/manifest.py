import email, hashlib, json, shutil, urllib.request, zipfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
root=Path('/private/tmp/aegis-fc4a-acquisition')
out=root/'wheels'
for item in sorted(root.glob('debian*/*.whl')):
    target=out/item.name
    if target.exists(): assert target.read_bytes()==item.read_bytes()
    else: shutil.copyfile(item,target)
def inspect(p):
    with zipfile.ZipFile(p) as z:
        meta=email.message_from_bytes(z.read(next(n for n in z.namelist() if n.endswith('.dist-info/METADATA'))))
        tags=email.message_from_bytes(z.read(next(n for n in z.namelist() if n.endswith('.dist-info/WHEEL')))).get_all('Tag')
    name,ver=meta['Name'],meta['Version']
    with urllib.request.urlopen(f'https://pypi.org/pypi/{name}/{ver}/json',timeout=30) as r: data=json.load(r)
    info=next(f for f in data['urls'] if f['filename']==p.name)
    sha=hashlib.sha256(p.read_bytes()).hexdigest()
    assert info['url'].startswith('https://files.pythonhosted.org/') and info['digests']['sha256']==sha
    lic=meta['License-Expression'] or meta['License'] or ', '.join(c for c in meta.get_all('Classifier',[]) if c.startswith('License ::'))
    assert lic,(name,ver)
    return dict(file=p.name,distribution=name,version=ver,license=lic,source=info['url'],sha256=sha,tags=tags,role='build' if name.lower() in {'hatchling','pathspec','tomlkit','packaging','pluggy','trove-classifiers'} else 'both' if name.lower()=='packaging' else 'runtime')
with ThreadPoolExecutor(6) as pool: rows=list(pool.map(inspect,sorted(out.glob('*.whl'))))
for fname,record in [('manifest.json',dict(schema='aegis-offline-wheelhouse-v1',wheels=[{k:r[k] for k in ('file','sha256','source','license')} for r in rows])),('provenance.json',dict(schema='aegis-release-provenance-v1',review_commit=None,wheels=rows))]:
    for folder in [out,Path('supply-prep')]: (folder/fname).write_text(json.dumps(record,indent=2)+'\n')
