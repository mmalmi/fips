#!/bin/bash
# Build two git refs into separate FIPS test images and run the same static
# iperf3 topology against each one. This keeps performance PR evidence
# repeatable: compare origin/master with a candidate branch using identical
# configs, topology, duration, and parallelism.
#
# Usage:
#   ./testing/static/scripts/iperf-compare-refs.sh <base-ref> <candidate-ref> [mesh|chain]
#
# Environment:
#   DURATION=10        iperf3 duration passed through to iperf-test.sh
#   PARALLEL=8         iperf3 parallel streams passed through to iperf-test.sh
#   SETTLE_SECONDS=3   topology startup delay passed through to iperf-test.sh
#   IPERF_TIMEOUT      per-path timeout, defaults to DURATION + 30
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 <base-ref> <candidate-ref> [mesh|chain]" >&2
    exit 2
fi

BASE_REF="$1"
CANDIDATE_REF="$2"
PROFILE="${3:-mesh}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/testing/static/docker-compose.yml"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fips-iperf-compare.XXXXXX")"
WORKTREES=()
FAILED_RUNS=0

cleanup() {
    docker compose -f "$COMPOSE_FILE" --profile "$PROFILE" down >/dev/null 2>&1 || true
    for wt in "${WORKTREES[@]}"; do
        git -C "$PROJECT_ROOT" worktree remove --force "$wt" >/dev/null 2>&1 || true
    done
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

slug_ref() {
    echo "$1" \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/[^a-z0-9_.-]/-/g; s/^-*//; s/-*$//' \
        | cut -c1-48
}

image_tag() {
    local label="$1"
    local ref="$2"
    local slug
    slug="$(slug_ref "$ref")"
    [ -n "$slug" ] || slug="ref"
    printf 'fips-test:compare-%s-%s\n' "$label" "$slug"
}

build_ref_image() {
    local label="$1"
    local ref="$2"
    local tag="$3"

    local wt="$TMP_DIR/$label"
    local target_dir="$PROJECT_ROOT/target/iperf-compare-$label-$(slug_ref "$ref")"

    echo ""
    echo "=== Building $label: $ref -> $tag ==="
    git -C "$PROJECT_ROOT" worktree add --detach "$wt" "$ref"
    WORKTREES+=("$wt")

    mkdir -p "$target_dir"
    ln -s "$target_dir" "$wt/target"
    (
        cd "$wt"
        CARGO_TARGET_DIR="$wt/target" ./testing/scripts/build.sh
    )
    docker tag fips-test:latest "$tag"
}

run_profile() {
    local label="$1"
    local image="$2"
    local log="$TMP_DIR/$label.log"
    local duration="${DURATION:-10}"
    local parallel="${PARALLEL:-8}"
    local settle_seconds="${SETTLE_SECONDS:-3}"
    local iperf_timeout="${IPERF_TIMEOUT:-$((duration + 30))}"

    echo ""
    echo "=== Running $label with $image ==="
    FIPS_TEST_IMAGE="$image" docker compose -f "$COMPOSE_FILE" --profile "$PROFILE" up -d --force-recreate
    if DURATION="$duration" PARALLEL="$parallel" \
        SETTLE_SECONDS="$settle_seconds" IPERF_TIMEOUT="$iperf_timeout" \
        "$SCRIPT_DIR/iperf-test.sh" "$PROFILE" | tee "$log"; then
        :
    else
        local status="$?"
        echo "=== $label exited with status $status ===" | tee -a "$log"
        FAILED_RUNS=1
    fi
    docker compose -f "$COMPOSE_FILE" --profile "$PROFILE" down
}

print_summary() {
    local label="$1"
    local log="$TMP_DIR/$label.log"

    awk -v label="$label" '
        /^=== .* ===$/ && $0 !~ /FIPS iperf3 Bandwidth Test/ && $0 !~ /Results:/ {
            test=$0
            sub(/^=== /, "", test)
            sub(/ ===$/, "", test)
        }
        /^Bandwidth:/ {
            print label "\t" test "\t" $2 " " $3
        }
    ' "$log"
}

"$SCRIPT_DIR/generate-configs.sh" "$PROFILE"

BASE_IMAGE="$(image_tag base "$BASE_REF")"
CANDIDATE_IMAGE="$(image_tag candidate "$CANDIDATE_REF")"

build_ref_image base "$BASE_REF" "$BASE_IMAGE"
build_ref_image candidate "$CANDIDATE_REF" "$CANDIDATE_IMAGE"

run_profile base "$BASE_IMAGE"
run_profile candidate "$CANDIDATE_IMAGE"

echo ""
echo "=== Summary ==="
printf 'ref\ttest\tbandwidth\n'
print_summary base
print_summary candidate

exit "$FAILED_RUNS"
