#!/bin/bash
# Publish FIPS library crates to crates.io in dependency tiers.
#
# Usage:
#   ./scripts/publish.sh           # Publish all publishable crates
#   ./scripts/publish.sh --dry-run # Verify package/publish metadata only
#   ./scripts/publish.sh --plan    # Print publish order

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DRY_RUN=""
PLAN_ONLY=0
ALLOW_DIRTY="--allow-dirty"
WAIT_TIME="${CARGO_PUBLISH_WAIT_SECS:-30}"
FAILED_CRATES=()

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN="--dry-run"
            ;;
        --plan)
            PLAN_ONLY=1
            ;;
        --no-allow-dirty)
            ALLOW_DIRTY=""
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

TIER_1_CRATES=(
    "fips-identity"
)

TIER_2_CRATES=(
    "fips-core"
)

TIER_3_CRATES=(
    "fips-endpoint"
)

ALL_CRATES=(
    "${TIER_1_CRATES[@]}"
    "${TIER_2_CRATES[@]}"
    "${TIER_3_CRATES[@]}"
)

publish_crate() {
    local crate="$1"
    local output
    local cargo_args=(-p "$crate")

    if [[ -n "$DRY_RUN" ]]; then
        cargo_args+=("$DRY_RUN")
    fi
    if [[ -n "$ALLOW_DIRTY" ]]; then
        cargo_args+=("$ALLOW_DIRTY")
    fi
    if [[ -n "$DRY_RUN" && "$crate" == "fips-endpoint" ]]; then
        cargo_args+=(--config 'patch.crates-io.fips-core.path="crates/fips-core"')
    fi

    echo ""
    echo "=========================================="
    echo "Publishing: ${crate}"
    echo "=========================================="

    if output=$(cargo publish "${cargo_args[@]}" 2>&1); then
        echo "$output"
        echo "[ok] ${crate} published successfully"
    elif echo "$output" | grep -q "already exists"; then
        echo "[ok] ${crate} already published at this version (skipping)"
    else
        echo "$output"
        echo "[fail] Failed to publish ${crate} (continuing...)"
        return 1
    fi

    return 0
}

publish_tier() {
    local tier_name="$1"
    shift

    local crates=("$@")
    local log_dir
    log_dir=$(mktemp -d "${TMPDIR:-/tmp}/fips-publish.XXXXXX")
    local pids=()
    local crate

    echo ""
    echo "=== ${tier_name}: ${crates[*]} ==="

    for crate in "${crates[@]}"; do
        publish_crate "$crate" >"${log_dir}/${crate}.log" 2>&1 &
        pids+=("$!")
    done

    local published=0
    local status=0
    local i
    for i in "${!pids[@]}"; do
        crate="${crates[$i]}"
        if ! wait "${pids[$i]}"; then
            FAILED_CRATES+=("$crate")
            status=1
        fi

        cat "${log_dir}/${crate}.log"
        if grep -q "published successfully" "${log_dir}/${crate}.log"; then
            published=1
        fi
    done

    rm -rf "$log_dir"

    if [[ "$status" -eq 0 && "$published" -eq 1 && -z "$DRY_RUN" ]]; then
        echo ""
        echo "Waiting ${WAIT_TIME}s for crates.io to index this tier..."
        sleep "$WAIT_TIME"
    fi
}

if [[ "$PLAN_ONLY" -eq 1 ]]; then
    printf '%s\n' "${ALL_CRATES[@]}"
    exit 0
fi

if [[ -n "$DRY_RUN" ]]; then
    echo "=== DRY RUN MODE ==="
fi

echo "Publishing FIPS crates to crates.io"
cd "$REPO_DIR"

publish_tier "Tier 1" "${TIER_1_CRATES[@]}"
publish_tier "Tier 2" "${TIER_2_CRATES[@]}"
publish_tier "Tier 3" "${TIER_3_CRATES[@]}"

echo ""
echo "=========================================="
if [[ ${#FAILED_CRATES[@]} -eq 0 ]]; then
    echo "[ok] All crates published successfully!"
else
    echo "[fail] Failed to publish: ${FAILED_CRATES[*]}"
    exit 1
fi
echo "=========================================="
