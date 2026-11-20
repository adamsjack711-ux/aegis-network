#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s FULL_COMMIT OUTPUT_DIR\n' "$0" >&2
  exit 2
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin="$(git -C "$repo_root" rev-parse --verify "$1^{commit}")"
if [[ "$1" != "$pin" ]]; then
  printf 'FULL_COMMIT must be an exact 40-character commit ID\n' >&2
  exit 2
fi
output="$(mkdir -p "$2" && cd "$2" && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase5b-build.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/source"
git -C "$repo_root" archive "$pin" pyproject.toml src/aegis | tar -xf - -C "$scratch/source"
# The approved baseline timestamp fixes ZIP metadata across rebuilds.
SOURCE_DATE_EPOCH=1795143126 uv build --offline --wheel --out-dir "$output" "$scratch/source"
shasum -a 256 "$output"/aegis_network-0.1.0-py3-none-any.whl
