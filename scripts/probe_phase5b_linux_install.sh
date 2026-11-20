#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "usage: $0 {debian312|ubuntu312|debian313|debian312-preinstalled} HOST_WHEEL_DIRECTORY" >&2
  exit 2
fi
case "$1" in
  debian312|debian312-preinstalled)
    image=sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e ;;
  ubuntu312)
    image=sha256:706130e55f22d2c81e272e0bf987be194bbbca232ab554b440f3116e74b00b60 ;;
  debian313)
    image=sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 ;;
  *) echo "unknown matrix cell: $1" >&2; exit 2 ;;
esac
wheel_dir=$(cd "$2" && pwd)
docker image inspect "$image" --format '{{.Id}} {{.Os}}/{{.Architecture}}' >&2

if [[ $1 == debian312-preinstalled ]]; then
  command='python -m venv --system-site-packages /tmp/aegis-venv
    /tmp/aegis-venv/bin/python -m pip install --no-index --no-deps --no-cache-dir --force-reinstall /wheels/aegis_network-0.1.0-py3-none-any.whl
    /tmp/aegis-venv/bin/python /tmp/aegis-venv/bin/aegis --help >/tmp/help.txt
    /tmp/aegis-venv/bin/python /tmp/aegis-venv/bin/aegis inventory --json >/tmp/inventory.json
    /tmp/aegis-venv/bin/python /tmp/aegis-venv/bin/aegis doctor --json >/tmp/doctor.json
    /tmp/aegis-venv/bin/python -c '\''import json; i=json.load(open("/tmp/inventory.json")); d=json.load(open("/tmp/doctor.json")); assert i["inventory_complete"] and i["package_count"] > 0 and i["asset_id"] is None; assert d["independent_status"] == "unknown"; print("inventory", i["distribution"], i["package_count"], i["identity_scope"]); print("doctor", d["independent_status"])'\''
    /tmp/aegis-venv/bin/python -m pip uninstall -y --no-input aegis-network
    test ! -e /tmp/aegis-venv/bin/aegis
    echo uninstall-pass'
elif [[ $1 == ubuntu312 ]]; then
  command='python -m virtualenv --no-download /tmp/aegis-venv
    /tmp/aegis-venv/bin/python -m pip install --no-index --find-links /wheels /wheels/aegis_network-0.1.0-py3-none-any.whl
    /tmp/aegis-venv/bin/python /tmp/aegis-venv/bin/aegis doctor --json
    /tmp/aegis-venv/bin/python -m pip uninstall -y --no-input aegis-network'
else
  command='python -m venv /tmp/aegis-venv
    /tmp/aegis-venv/bin/python -m pip install --no-index --find-links /wheels /wheels/aegis_network-0.1.0-py3-none-any.whl
    /tmp/aegis-venv/bin/python /tmp/aegis-venv/bin/aegis doctor --json
    /tmp/aegis-venv/bin/python -m pip uninstall -y --no-input aegis-network'
fi

docker run --rm --pull never --network none --read-only \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,size=128m,mode=1777 \
  --mount "type=bind,src=$wheel_dir,dst=/wheels,readonly" \
  --entrypoint sh "$image" -ec "$command"
