#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase5b-install.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

uv build --offline --wheel --out-dir "$scratch/dist" "$repo_root"
uv venv "$scratch/venv"
uv pip install --offline --python "$scratch/venv/bin/python" "$scratch"/dist/aegis_network-*.whl
"$scratch/venv/bin/aegis" --help >/dev/null
XDG_STATE_HOME="$scratch/implicit-state" "$scratch/venv/bin/aegis" doctor --json >"$scratch/doctor.json" || test "$?" -eq 2
test ! -e "$scratch/implicit-state"
"$scratch/venv/bin/python" -c 'import json,sys; x=json.load(open(sys.argv[1])); assert x["schema_version"] == "doctor-v2" and x["asset_id"] is None and x["identity_scope"] == "none" and x["independent_status"] == "unknown" and x["network"] == "disabled; no sockets or listeners" and x["enforcement"] == "unavailable"' "$scratch/doctor.json"
uv pip uninstall --offline --python "$scratch/venv/bin/python" aegis-network
test ! -e "$scratch/venv/bin/aegis"
printf 'Phase 5B offline wheel install, no-write invocation, and uninstall passed\n'
