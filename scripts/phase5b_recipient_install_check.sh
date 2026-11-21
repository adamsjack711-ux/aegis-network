#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || { [ "$#" -eq 2 ] && [ "$2" != --verify-only ]; }; then
    printf 'Usage: %s RECIPIENT_ARCHIVE [--verify-only]\n' "$0" >&2
    exit 2
fi

archive=$1
mode=${2-}
archive_sha=d4745deb7eb9524092f42a430eaa32682d3b18d4c93af6d0dae7f25076bd306c
wheel_sha=549a4048bdb2f3034f9c4d26a82f6806a9d52ee7d64a112d015e1294f535d68d
wheel_name=aegis_network-0.1.0-py3-none-any.whl
image=sha256:6d620701a04f97b737f115f6e750d1fc3b8084d56acd801decfe781893c7443d

umask 077
stage=$(mktemp -d "$HOME/.aegis-phase5b-recipient.XXXXXX")
trap 'chmod -R u+rwX "$stage" && rm -rf "$stage"' 0
cp "$archive" "$stage/recipient.tar.gz"
(
    cd "$stage"
    printf '%s  recipient.tar.gz\n' "$archive_sha" | shasum -a 256 -c -
)
tar -xpzf "$stage/recipient.tar.gz" -C "$stage"
bundle=$stage/aegis-tester-50ba781-recipient
(
    cd "$bundle"
    shasum -a 256 -c SHA256SUMS
    printf '%s  wheels/%s\n' "$wheel_sha" "$wheel_name" | shasum -a 256 -c -
)
printf 'Verified recipient snapshot for 50ba781: archive=%s wheel=%s\n' "$archive_sha" "$wheel_sha"
if [ "$mode" = --verify-only ]; then
    exit 0
fi

printf 'Using the recorded local image %s\n' "$image"
docker --context colima run --rm -i --pull=never --platform=linux/arm64 --network=none \
    --read-only --cap-drop=ALL --security-opt=no-new-privileges --user=65534:65534 \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=512m \
    --mount "type=bind,source=$bundle,target=/bundle,readonly" \
    --entrypoint sh "$image" -s <<'GUEST'
set -eu
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
test "$(uname -m)" = aarch64
test "$(id -u)" = 65534
test "$(python3 -IB -c 'import platform; print(platform.python_version())')" = 3.12.13
test ! -w /bundle/grants
test ! -w /bundle/grants/trust.json
test ! -w /bundle/empty-feed.json
printf '%s | %s | %s | ' "$PRETTY_NAME" "$(uname -m)" "$(uname -r)"
python3 -V
id

cd /tmp
scratch=$(mktemp -d /tmp/aegis-recipient-check.XXXXXX)
export HOME="$scratch/home"
mkdir "$HOME"
venv=$scratch/venv
python3 -m venv "$venv"
python=$venv/bin/python
launcher=$venv/bin/aegis
"$python" -m pip --isolated install --no-index --no-cache-dir --no-compile \
    --only-binary=:all: --find-links=/bundle/wheels /bundle/wheels/aegis_network-0.1.0-py3-none-any.whl
"$python" -m pip --isolated check
test -x "$launcher"
before=$(sha256sum /bundle/grants/trust.json /bundle/empty-feed.json)
status_home=$scratch/status-home
mkdir "$status_home"

observe_status() {
    label=$1
    shift
    rc=0
    env -i HOME="$status_home" PATH="$venv/bin:/usr/bin:/bin" XDG_STATE_HOME="$scratch/implicit-state" \
        aegis status --json "$@" >"$scratch/$label.json" 2>"$scratch/$label.stderr" || rc=$?
    printf '%s exit=%s\n' "$label" "$rc"
    cat "$scratch/$label.json" "$scratch/$label.stderr"
    test "$rc" -eq 2
    test ! -s "$scratch/$label.stderr"
}

observe_status plain
observe_status empty-feed --feed /bundle/empty-feed.json --trust /bundle/grants/trust.json
test ! -e "$scratch/implicit-state"
test ! -L "$scratch/implicit-state"
test -z "$(find "$status_home" -mindepth 1 -print -quit)"
test "$before" = "$(sha256sum /bundle/grants/trust.json /bundle/empty-feed.json)"
"$python" -IB - "$scratch" <<'PY'
import json
from pathlib import Path
import sys

folder = Path(sys.argv[1])
for name in ("plain", "empty-feed"):
    record = json.loads((folder / f"{name}.json").read_bytes())
    assert record["schema_version"] == "status-v2"
    assert record["cli_version"] == "0.1.0" and record["distribution"] == "ubuntu"
    assert record["mode"] == "observation-only" and record["network"] == "offline"
    assert record["asset_id"] is None and record["identity_scope"] == "none"
    assert record["independent_status"] == record["overall_assessment"] == "unknown"
    if name == "empty-feed":
        assert record["claim_count"] == record["potential_findings"] == record["unknown_claims"] == 0
PY
"$python" -m pip --isolated uninstall -y aegis-network
test ! -e "$launcher"
"$python" -IB -c 'import importlib.util; from importlib import metadata; assert importlib.util.find_spec("aegis") is None and not list(metadata.distributions(name="aegis-network"))'
printf 'PASS 50ba781 recipient console smoke, Ubuntu arm64 CPython 3.12.13\n'
GUEST
