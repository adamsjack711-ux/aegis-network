#!/usr/bin/env bash
set -euo pipefail

# The install/uninstall proof is the offline Debian and Ubuntu matrix.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$repo_root/scripts/smoke_phase5b_linux.sh"
