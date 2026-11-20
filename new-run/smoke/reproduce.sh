#!/bin/sh
set -eu
inputs=${1:?canonical path to the reviewed wheels, tracer and smoke wheel}
docker --context colima run --rm --pull=never --network=none --read-only \
    --user=65534:65534 --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=512m \
    -v "$inputs:/inputs:ro" -i --entrypoint sh \
    sha256:67898a5e53a2ebb1138a9e17b0dfb22e52aabca270854cf86d21372f179a003e \
    < "$(dirname "$0")/run.sh"
