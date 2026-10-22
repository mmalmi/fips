#!/bin/sh
# Package the optional web UI without changing the relay executable or accounts.
set -eu
[ "$#" -eq 4 ] || {
	echo 'usage: build-luci-apk.sh apk-tool version source-revision output.apk' >&2
	exit 1
}
apk_tool=$1
version=$2
revision=$3
output=$4
[ "$(id -u)" -eq 0 ] || { echo 'package creation requires root file ownership' >&2; exit 1; }
[ -x "$apk_tool" ] && [ ! -e "$output" ] || exit 1
case "$version" in ''|*[!a-zA-Z0-9_.+:-]*) exit 1 ;; esac
case "$revision" in ''|*[!a-fA-F0-9]*) exit 1 ;; esac
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
build_root=$(mktemp -d "${TMPDIR:-/tmp}/freedom-package.XXXXXX")
trap 'rm -rf "$build_root"' EXIT
trap 'exit 1' HUP INT TERM
umask 022
data=$build_root/data
mkdir -p "$data/www" "$data/usr/share/freedom"
cp -R "$source_dir/luci/root/." "$data/"
cp -R "$source_dir/luci/htdocs/." "$data/www/"
find "$data" -type d -exec chmod 0755 {} \;
find "$data" -type f -exec chmod 0644 {} \;
printf '{"source_revision":"%s"}\n' "$revision" > "$data/usr/share/freedom/build.json"
"$apk_tool" mkpkg --compat 3.0.0_pre3 \
	--info name:luci-app-freedom --info "version:$version" --info arch:noarch \
	--info license:MIT --info 'description:Freedom mesh forwarding controls' \
	--info 'depends:fips-relay luci-base rpcd-mod-ucode ucode-mod-fs ucode-mod-uci ucode-mod-digest' \
	--script "post-install:$source_dir/luci-reload" \
	--script "post-upgrade:$source_dir/luci-reload" \
	--files "$data" --output "$output"
sha256sum "$output"
