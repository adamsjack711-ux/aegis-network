"""Benign attempted-effect controls inside the disposable, networkless fixture."""
import os
import socket
import subprocess

with open('/tmp/control-write','w') as output:
    output.write('sample')
try:
    with open('/control-denied','w'):
        pass
except PermissionError:
    pass
except OSError as error:
    if error.errno != 30:
        raise
with socket.socket() as sock:
    assert sock.connect_ex(('127.0.0.1', 1)) != 0
subprocess.run(['/bin/true'], check=True)
try:
    os.setuid(0)
except PermissionError:
    pass
else:
    raise AssertionError('privilege control unexpectedly succeeded')
