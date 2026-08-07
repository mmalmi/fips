#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The service wrapper must translate its environment into the current probe CLI.
cat >"$TMP/probe" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >"$FIPS_TEST_ARGS"
EOF
cat >"$TMP/timeout" <<'EOF'
#!/bin/sh
shift
exec "$@"
EOF
chmod +x "$TMP/probe" "$TMP/timeout"
PATH="$TMP:$PATH" \
FIPS_TEST_ARGS="$TMP/args" \
FIPS_HEALTH_PROBE="$TMP/probe" \
FIPS_HEALTH_TARGET_NPUB=npub1test \
FIPS_HEALTH_SEED_URLS='wss://seed-one.example wss://seed-two.example' \
FIPS_HEALTH_TIMEOUT_SECONDS=9 \
    sh "$ROOT/packaging/common/fips-healthcheck"
cat >"$TMP/expected" <<'EOF'
--target-npub
npub1test
--timeout-seconds
9
--seed-url
wss://seed-one.example
--seed-url
wss://seed-two.example
EOF
cmp "$TMP/expected" "$TMP/args" || fail "health wrapper emitted stale probe arguments"
missing_seed=$(FIPS_HEALTH_PROBE="$TMP/probe" \
    FIPS_HEALTH_TARGET_NPUB=npub1test \
    sh "$ROOT/packaging/common/fips-healthcheck" 2>&1 || true)
case "$missing_seed" in
    *FIPS_HEALTH_SEED_URLS*) ;;
    *) fail "health wrapper accepted missing seed URLs" ;;
esac

# Build a package from tiny fixtures; this checks the tarball manifest without
# spending time compiling Rust. The actual release build supplies real binaries.
if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
    echo "PASS: health wrapper uses the current probe CLI"
    echo "SKIP: tarball manifest check requires GNU tar"
    exit 0
fi
mkdir -p "$TMP/source/target/release"
cp -R "$ROOT/packaging" "$TMP/source/"
cp "$ROOT/Cargo.toml" "$TMP/source/"
for binary in fips fipsctl fipstop fips-gateway fips-health-probe; do
    cp "$TMP/probe" "$TMP/source/target/release/$binary"
done
SOURCE_DATE_EPOCH=1 STRIP=true \
    "$TMP/source/packaging/systemd/build-tarball.sh" \
    --no-build --version test --arch x86_64 >/dev/null
TARBALL="$TMP/source/deploy/fips-test-linux-x86_64.tar.gz"
for file in \
    fips-health-probe fips-healthcheck fips-health-probe.env.example \
    fips-healthcheck.service fips-healthcheck.timer; do
    tar -tzf "$TARBALL" | grep -qx "fips-test-linux-x86_64/$file" \
        || fail "tarball missing $file"
done

if [ "${FIPS_PACKAGE_INSTALL_TEST:-0}" = 1 ]; then
    command -v docker >/dev/null || fail "Docker is required for the install test"
    docker run --rm -i \
        -v "$TARBALL:/tmp/fips.tar.gz:ro" ubuntu:24.04 sh <<'EOF'
set -eu
mkdir -p /tmp/bin /etc/systemd/system /etc/tmpfiles.d
cat >/tmp/bin/systemctl <<'SH'
#!/bin/sh
case "${1:-}" in is-active|is-enabled) exit 1;; esac
exit 0
SH
cat >/tmp/bin/getent <<'SH'
#!/bin/sh
exit 0
SH
chmod +x /tmp/bin/systemctl /tmp/bin/getent
tar -xzf /tmp/fips.tar.gz -C /tmp
cd /tmp/fips-test-linux-x86_64
PATH="/tmp/bin:$PATH" ./install.sh >/dev/null
test -x /usr/local/bin/fips-health-probe
test -x /usr/lib/fips/fips-healthcheck
test -f /etc/systemd/system/fips-healthcheck.service
test -f /etc/systemd/system/fips-healthcheck.timer
FIPS_TEST_ARGS=/tmp/args \
FIPS_HEALTH_TARGET_NPUB=npub1test \
FIPS_HEALTH_SEED_URLS=wss://seed.example \
    /usr/lib/fips/fips-healthcheck
grep -qx -- --seed-url /tmp/args
! grep -Eq -- '--(relay|app)' /tmp/args
EOF
fi

echo "PASS: health wrapper and tarball package are coherent"
