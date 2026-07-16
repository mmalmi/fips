#!/usr/bin/env bash

macos_arch_for_target() {
    case "${1:?missing macOS target}" in
        aarch64-apple-darwin|aarch64|arm64)
            echo arm64
            ;;
        x86_64-apple-darwin|x86_64)
            echo x86_64
            ;;
        *)
            echo "Unsupported macOS target: $1" >&2
            return 1
            ;;
    esac
}

macos_package_name() {
    local version="${1:?missing package version}"
    local arch="${2:?missing package architecture}"

    case "${arch}" in
        arm64|x86_64) ;;
        *)
            echo "Unsupported macOS package architecture: ${arch}" >&2
            return 1
            ;;
    esac

    echo "fips-${version}-macos-${arch}.pkg"
}

macos_require_thin_arch() {
    local binary="${1:?missing binary path}"
    local expected="${2:?missing expected architecture}"
    local actual

    actual="$(lipo -archs "${binary}")" || return 1
    if [[ "${actual}" != "${expected}" ]]; then
        echo "Wrong architecture for ${binary}: expected ${expected}, got ${actual}" >&2
        return 1
    fi
}
