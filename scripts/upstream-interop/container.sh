#!/bin/sh
# Development interoperability only; the release qualification keeps its own pins.
set -eu
if [ "$INTEROP_STAGE" = test ]; then
    export FIPS_UPSTREAM_BIN=/work/target/debug/fips
    export FIPS_UPSTREAM_ECHO=/work/target/debug/examples/native-echo
    export FIPS_UPSTREAM_CLIENT=/work/target/debug/upstream-native-client
    export FIPS_INTEROP_LOG_DIR=/logs
    read -r binary < /work/fork-test-binary
    sha256sum -c /work/fork-test-binary.sha256
    exec "$binary" endpoint::tests::upstream:: --ignored --test-threads=1 --nocapture
fi
mkdir -p /work/apks
cd /work/apks
set --
while read -r checksum name; do
    if [ ! -f "$name" ]; then
        wget -q "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/$name" -O "$name"
    fi
    printf '%s  %s\n' "$checksum" "$name" | sha256sum -c -
    set -- "$@" "/work/apks/$name"
done < /fork/scripts/upstream-interop/alpine-aarch64.sha256
apk verify "$@"
apk add --no-network --no-cache "$@"
export CARGO_HOME=/work/cargo CARGO_TARGET_DIR=/work/target
export RUSTUP_TOOLCHAIN=1.96.1 CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
# bindgen loads libclang in a build script, requiring dynamic musl executables.
export RUSTFLAGS="-C target-feature=-crt-static"
export LIBCLANG_PATH=/usr/lib/llvm20/lib
case "$INTEROP_STAGE" in
    upstream)
        cd /upstream
        cargo build --locked --bin fips --example native-echo
        # Compile our small driver against the unchanged upstream library.
        set -- /work/target/debug/deps/libfips-*.rlib
        [ "$#" -eq 1 ]
        rustc --edition=2024 -C target-feature=-crt-static /fork/crates/fips-core/tests/fixtures/upstream_native_client.rs \
            --extern "fips=$1" -L dependency=/work/target/debug/deps \
            -o /work/target/debug/upstream-native-client
        sha256sum /work/target/debug/fips /work/target/debug/examples/native-echo \
            /work/target/debug/upstream-native-client | tee /work/upstream-binaries.sha256
        ;;
    fork)
        cd /fork
        cargo test --locked -p nvpn-fips-core --lib --features sim-transport --no-run \
            --message-format=json > /work/fork-build.json
        sed -n 's/.*"executable":"\([^" ]*\)".*/\1/p' /work/fork-build.json > /work/fork-test-binary
        [ "$(wc -l < /work/fork-test-binary)" -eq 1 ]
        read -r binary < /work/fork-test-binary
        sha256sum "$binary" > /work/fork-test-binary.sha256
        cat /work/fork-test-binary.sha256
        ;;
    *) echo 'unknown INTEROP_STAGE' >&2; exit 2 ;;
esac
