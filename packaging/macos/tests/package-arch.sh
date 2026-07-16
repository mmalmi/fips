#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../package-lib.sh
source "${SCRIPT_DIR}/../package-lib.sh"

assert_eq() {
    local expected="$1"
    local actual="$2"
    local label="$3"

    if [[ "${actual}" != "${expected}" ]]; then
        echo "FAIL: ${label}: expected '${expected}', got '${actual}'" >&2
        exit 1
    fi
}

arm_arch="$(macos_arch_for_target aarch64-apple-darwin)"
x86_arch="$(macos_arch_for_target x86_64-apple-darwin)"

assert_eq arm64 "${arm_arch}" "aarch64 target mapping"
assert_eq x86_64 "${x86_arch}" "x86_64 target mapping"
assert_eq \
    fips-0.4.4-macos-arm64.pkg \
    "$(macos_package_name 0.4.4 "${arm_arch}")" \
    "arm64 package name"
assert_eq \
    fips-0.4.4-macos-x86_64.pkg \
    "$(macos_package_name 0.4.4 "${x86_arch}")" \
    "x86_64 package name"

if macos_arch_for_target powerpc-apple-darwin >/dev/null 2>&1; then
    echo "FAIL: unsupported targets must be rejected" >&2
    exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
touch "${tmp_dir}/arm-bin" "${tmp_dir}/x86-bin"

lipo() {
    if [[ "$1" != "-archs" ]]; then
        return 2
    fi
    case "$2" in
        */arm-bin) echo arm64 ;;
        */x86-bin) echo x86_64 ;;
        *) return 2 ;;
    esac
}

macos_require_thin_arch "${tmp_dir}/arm-bin" arm64
macos_require_thin_arch "${tmp_dir}/x86-bin" x86_64

if macos_require_thin_arch "${tmp_dir}/x86-bin" arm64 >/dev/null 2>&1; then
    echo "FAIL: mislabeled binary architecture must be rejected" >&2
    exit 1
fi

echo "PASS: macOS package architecture mapping, naming, and content checks"
