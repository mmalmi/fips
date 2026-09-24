#!/bin/sh
# Build an APKv3 package from a separately cross-compiled static Linux binary.
# Run as root in an isolated build environment so packaged ownership is root.
set -eu
[ "$#" -eq 6 ] || {
	echo "usage: build-apk.sh apk-tool binary apk-architecture version source-revision output.apk" >&2
	exit 1
}
apk_tool=$1
binary=$2
architecture=$3
version=$4
revision=$5
output=$6
[ "$(id -u)" -eq 0 ] || { echo 'package creation requires root file ownership' >&2; exit 1; }
[ -x "$apk_tool" ] && [ -x "$binary" ] || exit 1
[ ! -e "$output" ] || { echo 'output already exists' >&2; exit 1; }
case "$architecture:$version" in *[!a-zA-Z0-9_.+:-]*) echo 'invalid package metadata' >&2; exit 1 ;; esac
case "$revision" in ''|*[!a-fA-F0-9]*) echo 'revision must be a Git commit hash' >&2; exit 1 ;; esac
[ -n "$architecture" ] && [ -n "$version" ] || exit 1
magic=$(od -An -N4 -tx1 < "$binary" | tr -d '[:space:]')
[ "$magic" = 7f454c46 ] || { echo 'binary is not an ELF executable' >&2; exit 1; }
machine=$(od -An -j18 -N2 -tx1 < "$binary" | tr -d '[:space:]')
case "$architecture:$machine" in
	aarch64*:b700|arm*:2800|x86_64:3e00|i386:0300|mips*:0008|mipsel*:0800|riscv64*:f300) ;;
	*) echo 'ELF machine does not match the selected package architecture' >&2; exit 1 ;;
esac

source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
build_root=$(mktemp -d "${TMPDIR:-/tmp}/fips-relay-package.XXXXXX")
trap 'rm -rf "$build_root"' EXIT
trap 'exit 1' HUP INT TERM
data=$build_root/data
umask 022
mkdir -p "$data/usr/sbin" "$data/usr/libexec" "$data/etc/init.d" \
	"$data/etc/config" "$data/etc/hotplug.d/ntp" "$data/lib/upgrade/keep.d" \
	"$data/lib/apk/packages" "$data/usr/share/fips-relay"
cp "$binary" "$data/usr/sbin/fips-relay"
cp "$source_dir/fips-relay-openwrt" "$data/usr/libexec/fips-relay-openwrt"
cp "$source_dir/fips-relay.init" "$data/etc/init.d/fips-relay"
cp "$source_dir/fips-relay.config" "$data/etc/config/fips-relay"
cp "$source_dir/90-fips-relay-ntp" "$data/etc/hotplug.d/ntp/90-fips-relay"
cp "$source_dir/../service.example.json" "$data/usr/share/fips-relay/config.example.json"
chmod 0755 "$data/usr/sbin/fips-relay" "$data/usr/libexec/fips-relay-openwrt" \
	"$data/etc/init.d/fips-relay" "$data/etc/hotplug.d/ntp/90-fips-relay"
chmod 0644 "$data/etc/config/fips-relay" "$data/usr/share/fips-relay/config.example.json"
printf '/etc/fips-relay/\n' > "$data/lib/upgrade/keep.d/fips-relay"
printf '/etc/config/fips-relay\n' > "$data/lib/apk/packages/fips-relay.conffiles"
config_hash=$(sha256sum "$data/etc/config/fips-relay" | cut -d ' ' -f 1)
printf '/etc/config/fips-relay %s\n' "$config_hash" > "$data/lib/apk/packages/fips-relay.conffiles_static"
binary_hash=$(sha256sum "$binary" | cut -d ' ' -f 1)
binary_bytes=$(wc -c < "$binary" | tr -d ' ')
printf '{"source_revision":"%s","architecture":"%s","binary_sha256":"%s","binary_bytes":%s}\n' \
	"$revision" "$architecture" "$binary_hash" "$binary_bytes" > "$data/usr/share/fips-relay/build.json"
(cd "$data" && find . -type f | sed 's|^\.|/|; s|^//|/|' | sort) > "$build_root/files"
mv "$build_root/files" "$data/lib/apk/packages/fips-relay.list"

"$apk_tool" mkpkg --compat 3.0.0 \
	--info name:fips-relay --info "version:$version" --info "arch:$architecture" \
	--info license:MIT --info 'description:Sender-funded native FIPS forwarding' \
	--info 'depends:procd jsonfilter iw uclient-fetch ca-bundle' \
	--script "pre-upgrade:$source_dir/pre-upgrade" \
	--script "post-upgrade:$source_dir/post-upgrade" \
	--script "pre-deinstall:$source_dir/pre-deinstall" \
	--files "$data" --output "$output"
sha256sum "$output"
