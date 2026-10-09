"""Leased wallet-storage faults for fresh, isolated OpenWrt test accounts."""

import json
from pathlib import Path

from .paid_settlement import require
from .wifi_remote import Router, digest


class WalletFaultRouter(Router):
    def guard_restore_command(self):
        return (f'if [ -f {self.temporary}/storage-armed ]; then '
                f'sh {self.temporary}/storage-fault.sh restore; fi')

    def stage_runtime(self, binary):
        super().stage_runtime(binary)
        self.write(self.temporary + '/storage-fault.sh', self.storage_script().encode())

    def storage_fault(self, action):
        require(action in ('arm', 'restore'), 'unknown storage operation')
        output = self.guarded(f'sh {self.temporary}/storage-fault.sh {action}')
        return json.loads(output) if output.strip() else {'restored': True}


class SnapshotRouter(WalletFaultRouter):
    storage_errno = 16
    fault_kind = 'snapshot-replacement'

    def prepare(self, binary, config):
        super().prepare(binary, config)
        # Exercise the mount before funding, then remove the empty placeholder.
        self.guarded(f'mkdir -p {self.state}/wallet; '
                     f'set -C; : >{self.state}/wallet/spilman-client.json')
        try:
            self.storage_probe = {'mount': self.storage_fault('arm')}
            self.guarded(f'printf probe >{self.state}/wallet/.replace-probe; '
                         f'if mv {self.state}/wallet/.replace-probe '
                         f'{self.state}/wallet/spilman-client.json '
                         f'2>{self.temporary}/storage-error; then exit 1; fi; '
                         f'grep -qi "resource busy" {self.temporary}/storage-error')
            self.storage_probe['replacement_refused'] = True
        finally:
            restored = self.storage_fault('restore')
        self.storage_probe['restoration'] = restored
        self.guarded(f'mv {self.state}/wallet/.replace-probe '
                     f'{self.state}/wallet/spilman-client.json; '
                     f'rm {self.state}/wallet/spilman-client.json')

    def storage_script(self):
        return f'''#!/bin/sh
set -eu
snapshot={self.state}/wallet/spilman-client.json
temporary={self.temporary}
mounted() {{ awk -v p="$snapshot" '$5==p {{print $1}}' /proc/self/mountinfo; }}
identity() {{
  test -f "$snapshot" && test ! -L "$snapshot" || return 1
  device=$(awk -v p="$snapshot" '$5=="/" || p==$5 || index(p,$5"/")==1 {{
    if (length($5)>n) {{n=length($5); device=$3}}
  }} END {{if (!n) exit 1; print device}}' /proc/self/mountinfo)
  inode=$(ls -di "$snapshot" | awk '{{print $1}}')
  test -n "$inode"
  printf '%s:%s\\n' "$device" "$inode"
}}
case "$1" in
  arm)
    test ! -e "$temporary/storage-armed"
    test -z "$(mounted)"
    identity >"$temporary/storage-identity"
    rm -f "$temporary/storage-mount-id"
    touch "$temporary/storage-armed"
    mount -o bind "$snapshot" "$snapshot"
    mounted >"$temporary/storage-mount-id"
    test -s "$temporary/storage-mount-id"
    test "$(identity)" = "$(cat "$temporary/storage-identity")"
    awk -v p="$snapshot" '$5==p && $6 ~ /(^|,)rw(,|$)/ {{found++}}
      END {{exit found != 1}}' /proc/self/mountinfo
    # Native reads tighten file permissions; leave those and the lock writable.
    chmod 600 "$snapshot"
    cat "$snapshot" >/dev/null
    printf writable >{self.state}/.storage-parent-probe
    rm {self.state}/.storage-parent-probe
    echo '{{"snapshot_mounted":true,"parent_writable":true}}'
    ;;
  restore)
    test -f "$temporary/storage-armed" || exit 0
    current=$(mounted)
    if [ -n "$current" ]; then
      test "$(identity)" = "$(cat "$temporary/storage-identity")"
      # A lost mount reply can precede the saved mount ID. The fresh owned path
      # and original inode still identify that one bind; refuse stacked mounts.
      test "$(printf '%s\\n' "$current" | wc -l)" = 1
      if [ -s "$temporary/storage-mount-id" ]; then
        test "$current" = "$(cat "$temporary/storage-mount-id")"
      fi
      umount "$snapshot"
    fi
    test -z "$(mounted)"
    # Automatic payment may already replace the snapshot after unmount.
    rm "$temporary/storage-armed"
    echo '{{"snapshot_mounted":false,"restored":true}}'
    ;;
  *) exit 2;;
esac
'''


class VolumeRouter(WalletFaultRouter):
    storage_errno = 28
    fault_kind = 'full-wallet-filesystem'
    image_bytes = 8 * 1024 * 1024

    def __init__(self, *args, image, **kwargs):
        self.image = Path(image).resolve(strict=True)
        require(self.image.stat().st_size == self.image_bytes, 'wallet volume must be exactly 8 MiB')
        content = self.image.read_bytes()
        require(content[1080:1082] == b'\x53\xef'
                and int.from_bytes(content[1028:1032], 'little') == 2048
                and int.from_bytes(content[1048:1052], 'little') == 2
                and int.from_bytes(content[1116:1120], 'little') & 4,
                'wallet volume requires a journaled ext4 filesystem with 4 KiB blocks')
        self.storage_probe = {'image_sha256': digest(content), 'image_bytes': len(content)}
        super().__init__(*args, **kwargs)

    def prepare(self, binary, config):
        super().prepare(binary, config)
        self.guarded(f'test "$(df -k {self.parent} | awk \'NR==2 {{print $4}}\')" -ge 16384')
        image = self.parent + '/wallet-volume.img'
        self.write(image, self.image.read_bytes())
        require(self.remote(['sha256sum', image]).decode().split()[0]
                == self.storage_probe['image_sha256'], 'staged wallet volume checksum differs')
        self.storage_probe['volume'] = json.loads(self.guarded(
            f'sh {self.temporary}/storage-fault.sh mount'))
        self.guarded(f'printf retained >{self.state}/wallet/.sentinel')
        try:
            self.storage_probe['fault'] = self.storage_fault('arm')
            self.guarded(f'test "$(cat {self.state}/wallet/.sentinel)" = retained')
        finally:
            restored = self.storage_fault('restore')
        self.storage_probe['restoration'] = restored
        self.guarded(f'rm {self.state}/wallet/.sentinel')

    def cleanup(self):
        super().cleanup()
        if self.guard_ready:
            result = self.remote(['sh', self.temporary + '/storage-fault.sh', 'release'], timeout=45)
            self.storage_probe['closure'] = json.loads(result)
            manifest = self.remote(f'test ! -f {self.temporary}/wallet-files.sha256 || '
                                   f'cat {self.temporary}/wallet-files.sha256')
            (self.output / 'wallet-files.sha256').write_bytes(manifest)

    def storage_script(self):
        return f'''#!/bin/sh
set -eu
volume={self.state}/wallet
image={self.parent}/wallet-volume.img
temporary={self.temporary}
mounted() {{ awk -v p="$volume" '$5==p {{print $1":"$3}}' /proc/self/mountinfo; }}
validate() {{
  test -s "$temporary/storage-volume-id"
  test "$(mounted)" = "$(cat "$temporary/storage-volume-id")"
  test -d "$volume" && test ! -L "$volume"
}}
case "$1" in
  mount)
    test ! -e "$temporary/storage-volume-id"
    test -z "$(mounted)"
    # Only the just-initialized, unfunded wallet is moved onto this fresh volume.
    test -d "$volume" && test ! -L "$volume"
    test -z "$(find "$volume" -type l)"
    mkdir "$temporary/wallet-seed"
    cp -a "$volume/." "$temporary/wallet-seed/"
    (cd "$volume" && find . -type f -exec sha256sum {{}} + | sort) >"$temporary/wallet-seed.sha256"
    mount -t ext4 -o loop,noatime,nodev,nosuid,noexec "$image" "$volume"
    mounted >"$temporary/storage-volume-id"
    validate
    test "$(mounted | wc -l)" = 1
    awk -v p="$volume" '$5==p {{print $3}}' /proc/self/mountinfo >"$temporary/storage-volume-device"
    device=$(cat "$temporary/storage-volume-device")
    cat "/sys/dev/block/$device/loop/backing_file" >"$temporary/storage-volume-backing"
    test -s "$temporary/storage-volume-backing"
    test -z "$(find "$volume" -type f -o -type l)"
    cp -a "$temporary/wallet-seed/." "$volume/"
    (cd "$volume" && find . -type f -exec sha256sum {{}} + | sort) >"$temporary/wallet-mounted.sha256"
    cmp "$temporary/wallet-seed.sha256" "$temporary/wallet-mounted.sha256"
    rm -r "$temporary/wallet-seed"
    capacity=$(df -k "$volume" | awk 'NR==2 {{print $2}}')
    test "$capacity" -ge 1024 && test "$capacity" -le 8192
    echo '{{"mounted":true,"filesystem":"ext4","capacity_kib":'"$capacity"'}}'
    ;;
  arm)
    validate
    test ! -e "$temporary/storage-armed"
    test ! -e "$volume/.fips-ballast"
    touch "$temporary/storage-armed"
    # Bounded random writes exercise flash instead of compressed zero blocks.
    if dd if=/dev/urandom of="$volume/.fips-ballast" bs=4096 count=2048 2>"$temporary/storage-error"; then
      echo 'bounded wallet volume did not fill' >&2; exit 1
    fi
    grep -qi 'no space left on device' "$temporary/storage-error"
    if dd if=/dev/zero bs=1 count=1 >>"$volume/.fips-ballast" 2>"$temporary/storage-byte-error"; then
      echo 'wallet volume still accepted its final byte' >&2; exit 1
    fi
    grep -qi 'no space left on device' "$temporary/storage-byte-error"
    sync
    test "$(df -k "$volume" | awk 'NR==2 {{print $4}}')" = 0
    printf writable >{self.state}/.storage-parent-probe
    rm {self.state}/.storage-parent-probe
    test "$(df -k {self.parent} | awk 'NR==2 {{print $4}}')" -ge 8192
    echo '{{"filesystem_full":true,"last_byte_refused":true,"parent_writable":true}}'
    ;;
  restore)
    test -f "$temporary/storage-armed" || exit 0
    validate
    test ! -L "$volume/.fips-ballast" && test ! -d "$volume/.fips-ballast"
    rm -f "$volume/.fips-ballast"
    sync
    printf restored >"$volume/.write-probe"
    rm "$volume/.write-probe" "$temporary/storage-armed"
    echo '{{"filesystem_full":false,"restored":true}}'
    ;;
  release)
    test ! -f "$temporary/active"
    sh "$0" restore >/dev/null
    if [ -n "$(mounted)" ]; then
      validate
      for f in /proc/[0-9]*/fd/* /proc/[0-9]*/cwd /proc/[0-9]*/exe; do
        target=$(readlink "$f" 2>/dev/null) || continue
        case "$target" in "$volume"|"$volume"/*) exit 1;; esac
      done
      sync
      mount -o remount,ro "$volume"
      (cd "$volume" && find . -type f -exec sha256sum {{}} + | sort) >"$temporary/wallet-files.sha256"
      umount "$volume"
    fi
    test -z "$(mounted)"
    if [ -f "$temporary/storage-volume-device" ]; then
      device=$(cat "$temporary/storage-volume-device")
      backing="/sys/dev/block/$device/loop/backing_file"
      if [ -f "$backing" ]; then
        test "$(cat "$backing")" != "$(cat "$temporary/storage-volume-backing")"
      fi
    fi
    # Keep the closed filesystem image as the account recovery artifact.
    echo '{{"volume_unmounted":true,"loop_detached":true,"backing_image_retained":true}}'
    ;;
  *) exit 2;;
esac
'''
