"""Disposable KVM guest with an owned ext4 image and a pinned SSH connection.

Only explicit kernel/binary inputs and host userspace tools enter the initramfs.
No host mounts, tap interfaces, package installations or existing disks are used.
"""

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import uuid

from .paid_relay import eventually, write_json
from .paid_settlement import require


def command(args, *, data=None, timeout=60):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.decode(errors='replace')[-2000:]}")
    return result.stdout


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Guest:
    def __init__(self, root, kernel, relay):
        self.root = root.resolve()
        self.kernel, self.relay = kernel.resolve(strict=True), relay.resolve(strict=True)
        self.qemu = shutil.which('qemu-system-x86_64')
        require(self.qemu is not None and os.access('/dev/kvm', os.R_OK | os.W_OK),
                'an existing x86-64 QEMU/KVM installation is required')
        self.uuid = str(uuid.uuid4())
        self.process = self.tunnel = None
        self.boots = 0
        self.inputs = {}
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]

    def prepare(self):
        self.root.mkdir(mode=0o700)
        image = self.root / 'initramfs'
        image.mkdir(mode=0o755)
        for directory in ('bin', 'dev', 'proc', 'sys', 'run', 'tmp', 'data',
                          'root/.ssh', 'etc/ssh', 'var/empty', 'opt/bench'):
            (image / directory).mkdir(parents=True, exist_ok=True)
        for directory in [image, *(p for p in image.rglob('*') if p.is_dir())]:
            directory.chmod(0o755)
        (image / 'root').chmod(0o700)
        (image / 'root/.ssh').chmod(0o700)
        (image / 'tmp').chmod(0o1777)

        def copy(source, destination=None):
            source = Path(source)
            destination = image / (destination or str(source).lstrip('/'))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            self.inputs[str(source)] = digest(source)

        programs = [Path(shutil.which('busybox')), Path('/usr/sbin/sshd'), self.relay]
        programs += [p for name in ('sshd-session', 'sshd-auth')
                     if (p := Path('/usr/lib/openssh') / name).is_file()]
        for program in programs:
            destination = ('bin/busybox' if program.name == 'busybox' else
                           'opt/bench/fips-relay' if program == self.relay else None)
            copy(program, destination)
            libraries = subprocess.run(['ldd', str(program)], capture_output=True, text=True)
            require(libraries.returncode == 0 or 'not a dynamic executable' in
                    libraries.stdout + libraries.stderr, 'cannot determine guest libraries')
            for library in set(re.findall(r'(/[^\s()]+)', libraries.stdout)):
                copy(library)

        for name in ('client', 'host'):
            command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.root / name)])
        copy(self.root / 'client.pub', 'root/.ssh/authorized_keys')
        (image / 'root/.ssh/authorized_keys').chmod(0o600)
        copy(self.root / 'host', 'etc/ssh/ssh_host_ed25519_key')
        (image / 'etc/passwd').write_text(
            'root:x:0:0:root:/root:/bin/sh\nsshd:x:74:74:sshd:/var/empty:/bin/false\n')
        (image / 'etc/shadow').write_text('root::0:0:99999:7:::\nsshd:!:0:0:99999:7:::\n')
        (image / 'etc/shadow').chmod(0o600)
        (image / 'etc/group').write_text('root:x:0:\nsshd:x:74:\n')
        (image / 'etc/ssh/sshd_config').write_text(
            'HostKey /etc/ssh/ssh_host_ed25519_key\nPidFile /run/sshd.pid\n'
            'UsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
            'PermitRootLogin prohibit-password\nAllowTcpForwarding remote\n'
            'GatewayPorts no\nPermitTTY no\nPrintMotd no\n')
        init = image / 'init'
        init.write_text('''#!/bin/busybox sh
set -eu
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mkdir -p /run/sshd
mount -t ext4 -o data=ordered,commit=60 /dev/vda /data
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
''')
        init.chmod(0o755)
        names = ['.'] + sorted(str(p.relative_to(image)) for p in image.rglob('*'))
        archive = subprocess.run(['cpio', '--null', '-o', '-H', 'newc', '--owner=0:0'],
                                 cwd=image, input=('\0'.join(names) + '\0').encode(),
                                 capture_output=True, timeout=60)
        require(archive.returncode == 0, 'initramfs creation failed')
        with (self.root / 'initramfs.gz').open('xb') as stream:
            stream.write(gzip.compress(archive.stdout, mtime=0))
        disk = self.root / 'state.ext4'
        with disk.open('xb') as stream:
            stream.truncate(128 * 1024 * 1024)
        command(['mkfs.ext4', '-q', '-F', '-L', 'fips-test', '-E',
                 'lazy_itable_init=0,lazy_journal_init=0', str(disk)])
        host_key = (self.root / 'host.pub').read_text().split()
        (self.root / 'known_hosts').write_text(
            f'[127.0.0.1]:{self.port} {host_key[0]} {host_key[1]}\n')
        self.inputs.update({str(self.kernel): digest(self.kernel), self.qemu: digest(self.qemu)})
        write_json(self.root / 'inputs.json', {'files': self.inputs,
                   'initramfs_sha256': digest(self.root / 'initramfs.gz'),
                   'initial_disk_sha256': digest(disk), 'uuid': self.uuid})

    def ssh(self):
        return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes',
                '-o', f'UserKnownHostsFile={self.root / "known_hosts"}',
                '-i', str(self.root / 'client'), '-p', str(self.port),
                '-S', str(self.root / 'ssh-control')]

    def execute(self, args, data=None, timeout=90):
        require(self.process is not None and self.process.poll() is None, 'owned guest is not live')
        return command([*self.ssh(), 'root@127.0.0.1', shlex.join(args)],
                       data=data, timeout=timeout)

    def boot(self, mint_port):
        require(self.process is None or self.process.poll() is not None, 'guest already running')
        self.boots += 1
        args = [self.qemu, '-enable-kvm', '-machine', 'q35', '-cpu', 'host',
                '-smp', '2', '-m', '768', '-uuid', self.uuid,
                '-kernel', str(self.kernel), '-initrd', str(self.root / 'initramfs.gz'),
                '-append', 'console=ttyS0 rdinit=/init panic=-1', '-nodefaults', '-no-reboot',
                '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
                '-drive', f'file={self.root / "state.ext4"},format=raw,if=virtio,cache=none',
                '-netdev', f'user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:{self.port}-:22',
                '-device', 'virtio-net-pci,netdev=n0']
        with (self.root / f'boot-{self.boots}.log').open('xb') as log:
            self.process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log,
                                            stderr=log, start_new_session=True)
        write_json(self.root / f'boot-{self.boots}.json', {'pid': self.process.pid, 'args': args})
        boot_id = eventually('disposable guest SSH', lambda: self.execute(
            ['cat', '/proc/sys/kernel/random/boot_id'], timeout=5).decode().strip(), 45)
        with (self.root / f'tunnel-{self.boots}.log').open('xb') as log:
            self.tunnel = subprocess.Popen([*self.ssh(), '-M', '-N', '-o',
                'ExitOnForwardFailure=yes', '-R', f'127.0.0.1:{mint_port}:127.0.0.1:{mint_port}',
                'root@127.0.0.1'], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True)
        eventually('private mint tunnel', self._tunnel_ready, 15)
        info = json.loads(self.execute(['wget', '-q', '-O', '-',
                                       f'http://127.0.0.1:{mint_port}/v1/info']))
        require(isinstance(info, dict) and 'nuts' in info, 'mint tunnel returned invalid metadata')
        return boot_id

    def _tunnel_ready(self):
        require(self.tunnel.poll() is None, 'private mint tunnel exited')
        result = subprocess.run([*self.ssh(), '-O', 'check', 'root@127.0.0.1'],
                                capture_output=True, timeout=5)
        return result.returncode == 0

    def cut_power(self):
        require(self.process is not None and self.process.poll() is None, 'guest is not live')
        pid = self.process.pid
        handle = os.pidfd_open(pid)
        try:
            require(Path(f'/proc/{pid}/exe').resolve() == Path(self.qemu).resolve(),
                    'owned guest executable changed')
            args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            require(self.uuid.encode() in args and str(self.root / 'initramfs.gz').encode() in args,
                    'owned guest arguments changed')
            signal.pidfd_send_signal(handle, signal.SIGKILL)
            require(self.process.wait(timeout=15) == -signal.SIGKILL, 'guest was not killed')
        finally:
            os.close(handle)
        self.close_tunnel()

    def close_tunnel(self):
        if self.tunnel is not None and self.tunnel.poll() is None:
            self.tunnel.terminate()
            self.tunnel.wait(timeout=10)

    def shutdown(self):
        if self.process is not None and self.process.poll() is None:
            self.execute(['sh', '-c', 'sync; (sleep 1; poweroff -f) >/dev/null 2>&1 &'])
            require(self.process.wait(timeout=15) == 0, 'guest did not power off cleanly')
        self.close_tunnel()
