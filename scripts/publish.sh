#!/bin/bash
# Publish FIPS library crates to crates.io in dependency order.
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

    echo ""
    echo "=========================================="
    echo "Publishing: ${crate}"
    echo "=========================================="

    if output=$(cargo publish -p "$crate" $DRY_RUN $ALLOW_DIRTY 2>&1); then
        echo "$output"
        echo "✓ ${crate} published successfully"
        if [[ -z "$DRY_RUN" ]]; then
            echo "Waiting ${WAIT_TIME}s for crates.io to index..."
            sleep "$WAIT_TIME"
        fi
    elif echo "$output" | grep -q "already exists"; then
        echo "✓ ${crate} already published at this version (skipping)"
    else
        echo "$output"
        echo "✗ Failed to publish ${crate} (continuing...)"
        FAILED_CRATES+=("$crate")
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

for crate in "${ALL_CRATES[@]}"; do
    publish_crate "$crate"
done

echo ""
echo "=========================================="
if [[ ${#FAILED_CRATES[@]} -eq 0 ]]; then
    echo "✓ All crates published successfully!"
else
    echo "✗ Failed to publish: ${FAILED_CRATES[*]}"
    exit 1
fi
echo "=========================================="
