#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="aegis_phase4_baseline-coordinator:latest"
scratch="$(mktemp -d "$repo_root/.phase5b-linux.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

# The image must already be present; Docker is forbidden to pull one.
docker image inspect "$image" --format '{{.Id}} {{.Os}}/{{.Architecture}}'
uv build --offline --wheel --out-dir "$scratch/dist" "$repo_root"
cp "$repo_root/scripts/phase_next_probe_cli.py" "$scratch/dist/probe.py"
docker run --rm --pull never --network none --read-only \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m --cpus 1 --tmpfs /tmp:rw,exec,size=128m,mode=1777 \
  --mount "type=bind,src=$scratch/dist,dst=/wheels,readonly" \
  --entrypoint sh "$image" -ec '
    python -m venv --system-site-packages /tmp/aegis-venv
    /tmp/aegis-venv/bin/python -m pip install --no-index --no-deps --no-cache-dir --force-reinstall /wheels/aegis_network-*.whl
    # The candidate entry point must execute directly; source import is not a packaging test.
    XDG_STATE_HOME=/tmp/implicit-state /tmp/aegis-venv/bin/aegis inventory --json >/tmp/inventory.json
    test ! -e /tmp/implicit-state
    /tmp/aegis-venv/bin/python -c '\''import json; x=json.load(open("/tmp/inventory.json")); assert x["schema_version"] == "inventory-v2" and x["identity_scope"] == "none" and x["asset_id"] is None and x["inventory_complete"] and x["package_count"] > 0'\''
    PYTHONDONTWRITEBYTECODE=1 /tmp/aegis-venv/bin/python /wheels/probe.py >/tmp/probe.json
    /tmp/aegis-venv/bin/python -c '\''import json; x=json.load(open("/tmp/probe.json")); assert len(x) == 5; assert all(not row["created"] for name,row in x.items() if name != "inventory_explicit_state"); assert x["inventory_explicit_state"]["created"] == ["chosen", "chosen/identity.json"]; print("Five-case Linux default-state probe passed: 4 zero-write implicit cases, 1 explicit opt-in")'\''
    /tmp/aegis-venv/bin/python -m pip uninstall -y --no-input aegis-network
    test ! -e /tmp/aegis-venv/bin/aegis
    printf "Phase 5B offline non-root Linux wheel, direct console, no-write inventory and uninstall passed\\n"
  '
