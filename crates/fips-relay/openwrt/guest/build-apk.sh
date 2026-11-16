#!/bin/sh
# Package a verified static Linux ARM64 build on a root-owned staging filesystem.
set -eu
[ "$#" = 6 ] || { echo 'usage: build-apk.sh apk-tool binary arch version source-sha256 output.apk' >&2; exit 2; }
tool=$1; binary=$2; arch=$3; version=$4; source_digest=$5; output=$6
[ "$(id -u)" = 0 ] && [ -x "$tool" ] && [ -x "$binary" ] && [ ! -e "$output" ]
case "$arch" in aarch64_*) ;; *) echo 'unverified target architecture' >&2; exit 2;; esac
case "$arch:$version" in *[!A-Za-z0-9_.+:-]*) exit 2;; esac
case "$source_digest" in *[!0-9a-f]*) exit 2;; esac
[ "${#source_digest}" = 64 ] && [ -n "$version" ]
[ "$(hexdump -n 6 -v -e '1/1 "%02x"' "$binary")" = 7f454c460201 ]
[ "$(hexdump -s 18 -n 2 -v -e '1/1 "%02x"' "$binary")" = b700 ]
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
build=$(mktemp -d); trap 'rm -rf "$build"' EXIT
data=$build/data
mkdir -p "$data/usr/libexec" "$data/usr/sbin" "$data/usr/share/freedom-guest" "$data/lib/upgrade/keep.d" "$data/lib/apk/packages"
cp -R "$here/root/." "$data/"
cp "$binary" "$data/usr/sbin/freedom-guest"
cp "$here/freedom-merchant" "$data/usr/libexec/freedom-merchant"
find "$data" -type d -exec chmod 0755 {} \;
find "$data" -type f -exec chmod 0644 {} \;
chmod 0755 "$data/usr/libexec/freedom-merchant-ssh" "$data/usr/libexec/freedom-merchant" "$data/etc/init.d/freedom-guest" "$data/usr/sbin/freedom-guest"
printf '/etc/config/freedom_guest\n/etc/freedom-guest/\n' > "$data/lib/upgrade/keep.d/freedom-guest"
printf '/etc/config/freedom_guest\n' > "$data/lib/apk/packages/freedom-guest.conffiles"
printf '{"source_sha256":"%s","binary_sha256":"%s"}\n' "$source_digest" "$(sha256sum "$binary" | cut -d' ' -f1)" > "$data/usr/share/freedom-guest/build.json"
chown -R 0:0 "$data"
"$tool" mkpkg --compat 3.0.0_pre3 --info name:freedom-guest --info "version:$version" --info "arch:$arch" --info license:MIT \
 --info 'description:Freedom paid guest internet with operator-selected exits' --info 'depends:firewall4 ip-full wireguard-tools dnsmasq luci-base rpcd-mod-ucode ucode-mod-uci ucode-mod-fs ucode-mod-digest ca-bundle' \
 --script "post-install:$here/../luci-reload" --script "post-upgrade:$here/post-upgrade" --script "pre-upgrade:$here/stop-guest" --script "pre-deinstall:$here/stop-guest" --files "$data" --output "$output"
sha256sum "$output"
