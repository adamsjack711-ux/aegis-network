set -eu
cd /tmp
mkdir proof
python3 -m venv /tmp/venv
. /tmp/venv/bin/activate
pip --isolated install --no-index --no-compile --no-cache-dir --find-links /inputs/wheels /inputs/smoke/*.whl >proof/install.log
find /tmp/venv/lib -path '*/aegis/*.pyc' >proof/caches-before
test ! -s proof/caches-before
test -z "${PYTHONDONTWRITEBYTECODE+x}"
command -v aegis >proof/installed-path
set +e
/inputs/strace -f -yy -s 320 -e trace=%file,%network,%process,%creds -o proof/status.trace aegis status >proof/stdout 2>proof/stderr
rc=$?
set -e
echo "$rc" >proof/exit
tar -czf - -C proof .
