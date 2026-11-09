#!/bin/sh
# Usage: run.sh upstream|fork|test UPSTREAM_CHECKOUT TASK_VOLUME RETAINED_LOG_DIR
# Caller admits resources, serializes target writers and preserves the logs.
set -eu
[ "$#" -eq 4 ]
stage=$1
volume_mode=
[ "$stage" != test ] || volume_mode=,readonly
upstream=$(cd "$2" && pwd)
volume=$3
logs=$(cd "$4" && pwd)
fork=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
[ "$(git -C "$upstream" rev-parse HEAD)" = 79ee9c2c90b683a37bfd80ac3102c06ed35d3aa8 ]
[ -z "$(git -C "$upstream" status --porcelain)" ]
exec docker run --rm --name fips-upstream-interop-build \
    --cpus=2 --memory=6g --memory-swap=6g --pids-limit=512 \
    --mount "type=volume,source=$volume,target=/work$volume_mode" \
    --mount "type=bind,source=$upstream,target=/upstream,readonly" \
    --mount "type=bind,source=$fork,target=/fork,readonly" \
    --mount "type=bind,source=$logs,target=/logs" \
    -e "INTEROP_STAGE=$stage" \
    rust@sha256:ccba3c5d98fc76a5ac6eade9bcbbb946635657457c3d269982396633a66da08d \
    timeout 1200 sh /fork/scripts/upstream-interop/container.sh
