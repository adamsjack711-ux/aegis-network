#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "$repo_root/.phase5b-alpha-linux.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

# All images must already be cached. Neither build nor containers use network.
debian_image="aegis_phase4_baseline-coordinator:latest"
ubuntu_image="mcr.microsoft.com/playwright/python:v1.50.0-noble"
docker image inspect "$debian_image" "$ubuntu_image" --format '{{.RepoTags}} {{.Id}} {{.Os}}/{{.Architecture}}'
pin="$(git -C "$repo_root" rev-parse HEAD)"
printf 'candidate commit: %s\n' "$pin"
bash "$repo_root/scripts/build_phase5b_alpha.sh" "$pin" "$scratch/wheels" >"$scratch/build.log" 2>&1
shasum -a 256 "$scratch"/wheels/*.whl
cp "$repo_root/scripts/phase5b_alpha_probe.py" "$scratch/wheels/probe.py"
cp "$repo_root/scripts/phase_next_probe_cli.py" "$scratch/wheels/frozen-default-state.py"
cp "$repo_root/scripts/benchmark_phase5b_alpha.py" "$scratch/wheels/benchmark.py"
printf 'Package: broken\nStatus: install ok installed\nVersion: 1\n\n' >"$scratch/wheels/malformed-status"

# Ubuntu's cached Python has no ensurepip or cryptography/pydantic. Export
# already installed Debian wheels as read-only test dependencies. The Aegis
# distribution is removed so Ubuntu must import the newly installed wheel.
docker run --rm --pull never --network none \
  --mount "type=bind,src=$scratch,dst=/out" --entrypoint sh "$debian_image" \
  -ec 'tar -C /usr/local/lib/python3.12/site-packages --exclude=./aegis --exclude=./aegis_network-0.1.0.dist-info -cf /out/deps.tar .'
mkdir "$scratch/deps"
tar -xf "$scratch/deps.tar" -C "$scratch/deps"
test ! -e "$scratch/deps/aegis"

for distro in debian ubuntu; do
  if [[ "$distro" == debian ]]; then image="$debian_image"; else image="$ubuntu_image"; fi
  for mode in actual malformed; do
    mounts=(--mount "type=bind,src=$scratch/wheels,dst=/wheels,readonly"
            --mount "type=bind,src=$scratch/deps,dst=/deps,readonly")
    if [[ "$mode" == malformed ]]; then
      mounts+=(--mount "type=bind,src=$scratch/wheels/malformed-status,dst=/var/lib/dpkg/status,readonly")
    fi
    docker run --rm --pull never --network none --read-only \
      --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
      --memory 256m --cpus 1 --tmpfs /tmp:rw,size=192m,mode=1777 \
      "${mounts[@]}" -e "ALPHA_DIST=$distro" -e "ALPHA_MODE=$mode" \
      --entrypoint sh "$image" -ec '
        if [ "$ALPHA_DIST" = debian ]; then
          python -m venv --system-site-packages /tmp/alpha
        else
          python -m venv --without-pip /tmp/alpha
          export PYTHONPATH=/deps
        fi
        python -m pip --python /tmp/alpha/bin/python install --no-index --no-deps --no-cache-dir --force-reinstall /wheels/aegis_network-*.whl
        if [ "$ALPHA_MODE" = malformed ]; then
          /tmp/alpha/bin/python /wheels/probe.py --malformed
        else
          /tmp/alpha/bin/python /wheels/probe.py "$ALPHA_DIST"
          /tmp/alpha/bin/python /wheels/frozen-default-state.py | /tmp/alpha/bin/python -c '\''import json,sys; x=json.load(sys.stdin); assert len(x)==5 and all(not row["created"] for name,row in x.items() if name!="inventory_explicit_state"); assert x["inventory_explicit_state"]["created"]==["chosen", "chosen/identity.json"]; print("frozen five-case state oracle passed")'\''
          count=$(/tmp/alpha/bin/python /tmp/alpha/bin/aegis inventory --json | /tmp/alpha/bin/python -c '\''import json,sys; print(json.load(sys.stdin)["package_count"])'\'')
          /tmp/alpha/bin/python /wheels/benchmark.py "$ALPHA_DIST" "$count"
        fi
        python -m pip --python /tmp/alpha/bin/python uninstall -y --no-input aegis-network
        test ! -e /tmp/alpha/bin/aegis
        test ! -e /tmp/alpha/lib/python3.12/site-packages/aegis
        test -z "$(find /tmp/alpha -name "aegis_network-*.dist-info" -print)"
        printf "%s %s: offline install, probe and uninstall passed\n" "$ALPHA_DIST" "$ALPHA_MODE"
      '
  done
done
