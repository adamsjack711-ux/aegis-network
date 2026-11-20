#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 FULL_COMMIT_ID OUTPUT_DIRECTORY" >&2
  exit 2
fi
: "${UV_CACHE_DIR:?set UV_CACHE_DIR to a locally reviewed offline build cache}"

root=$(git rev-parse --show-toplevel)
git -C "$root" cat-file -e "$1^{commit}"
mkdir -p "$2"
output=$(cd "$2" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
git -C "$root" archive "$1" pyproject.toml src/aegis | tar -x -C "$stage"
SOURCE_DATE_EPOCH=1735689600 uv build --offline --wheel --out-dir "$output" "$stage"
shasum -a 256 "$output"/aegis_network-0.1.0-py3-none-any.whl
