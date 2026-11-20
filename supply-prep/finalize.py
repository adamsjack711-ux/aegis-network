"""Publish the independently reviewed fixture record to the local input directory."""
import hashlib
import json
from pathlib import Path

base = Path(__file__).resolve().parent
inputs = base.parents[1] / 'alpha-fc4a-inputs' / 'wheels'
binding = json.loads((base / 'install-review.json').read_text())
record = json.loads((base / 'provenance.json').read_bytes())
record['review_commit'] = binding['review_commit']
encoded = (json.dumps(record, indent=2) + '\n').encode()
if (hashlib.sha256(encoded).hexdigest() != binding['provenance_sha256'] or
    hashlib.sha256((inputs / 'manifest.json').read_bytes()).hexdigest() != binding['manifest_sha256']):
    raise SystemExit('input records differ from independent review')
for item in record['wheels']:
    if hashlib.sha256((inputs / item['file']).read_bytes()).hexdigest() != item['sha256']:
        raise SystemExit('wheel differs from reviewed archive: ' + item['file'])
(inputs / 'provenance.json').write_bytes(encoded)
