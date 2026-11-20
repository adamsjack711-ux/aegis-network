#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 FULL_COMMIT_ID OUTPUT_DIRECTORY" >&2
  exit 2
fi
: "${UV_CACHE_DIR:?set UV_CACHE_DIR to a reviewed local build cache}"

root=$(git rev-parse --show-toplevel)
pin=$1
output=$2
git -C "$root" cat-file -e "$pin^{commit}"
mkdir -p "$output"
output=$(cd "$output" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
git -C "$root" archive "$pin" pyproject.toml src/aegis | tar -x -C "$stage"
SOURCE_DATE_EPOCH=1735689600 uv build --offline --wheel --out-dir "$output" "$stage"
