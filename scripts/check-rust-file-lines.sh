#!/usr/bin/env bash
# Keep Rust modules small enough to review and refactor safely.
#
# New Rust files must stay below FIPS_RUST_FILE_MAX_LINES (default: 1000).
# Existing oversized files are ratcheted at their current line count: they may
# shrink, but they must not grow without deliberately updating this baseline.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MAX_LINES="${FIPS_RUST_FILE_MAX_LINES:-1000}"

case "$MAX_LINES" in
  ''|*[!0-9]*)
    echo "error: FIPS_RUST_FILE_MAX_LINES must be a positive integer" >&2
    exit 2
    ;;
esac

if [[ "$MAX_LINES" -lt 1 ]]; then
  echo "error: FIPS_RUST_FILE_MAX_LINES must be greater than zero" >&2
  exit 2
fi

baseline_for() {
  case "$1" in
    *) echo "$MAX_LINES" ;;
  esac
}

baseline_paths() {
  cat <<'PATHS'
PATHS
}

failures=0
checked=0
oversized_baselines=0

while IFS= read -r rel; do
  [[ -z "$rel" ]] && continue
  if [[ ! -f "$ROOT_DIR/$rel" ]]; then
    echo "stale baseline: $rel no longer exists; remove it from scripts/check-rust-file-lines.sh" >&2
    failures=$((failures + 1))
  fi
done < <(baseline_paths)

roots=()
for root in crates src examples testing; do
  [[ -d "$ROOT_DIR/$root" ]] && roots+=("$ROOT_DIR/$root")
done

while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  rel="${file#$ROOT_DIR/}"
  lines="$(awk 'END { print NR }' "$file")"
  allowed="$(baseline_for "$rel")"
  checked=$((checked + 1))
  if [[ "$allowed" -gt "$MAX_LINES" ]]; then
    oversized_baselines=$((oversized_baselines + 1))
  fi
  if [[ "$lines" -gt "$allowed" ]]; then
    if [[ "$allowed" -gt "$MAX_LINES" ]]; then
      echo "too large: $rel has $lines lines; baseline is $allowed, target is $MAX_LINES" >&2
    else
      echo "too large: $rel has $lines lines; limit is $MAX_LINES" >&2
    fi
    failures=$((failures + 1))
  fi
done < <(find "${roots[@]}" -type f -name '*.rs' -not -path '*/target/*' | LC_ALL=C sort)

if [[ "$failures" -gt 0 ]]; then
  echo "Rust file line check failed: $failures issue(s)." >&2
  exit 1
fi

echo "Rust file line check passed: $checked files, max target $MAX_LINES lines, $oversized_baselines baseline exception(s)."
