"""Verify first-launch output and attempted bytecode writes in the raw installed trace."""
import json
import re
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parent
with tarfile.open(root / 'results.tar.gz') as archive:
    def read(name):
        return archive.extractfile('./' + name).read().decode()

    assert not read('caches-before').strip()
    assert read('installed-path').strip() == '/tmp/venv/bin/aegis'
    assert read('exit').strip() == '2'
    assert 'mode: observation-only' in read('stdout').splitlines()
    assert 'independent_status: unknown' in read('stdout').splitlines()
    assert not read('stderr').strip()
    trace = read('status.trace').splitlines()
    cache = [line for line in trace if '__pycache__' in line or '.pyc' in line]
    mutation = re.compile(r'\b(?:mkdir\w*|rename\w*|unlink\w*|link\w*|symlink\w*|chmod\w*|chown\w*|truncate\w*|utime\w*|creat)\(|\bO_(?:RDWR|WRONLY|CREAT|TRUNC|APPEND)\b')
    attempts = [line for line in cache if mutation.search(line)]
    assert not attempts, attempts
    print(json.dumps({'exit': 2, 'cache_path_syscalls': len(cache), 'bytecode_write_attempts': len(attempts)}))
