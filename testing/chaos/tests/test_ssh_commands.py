"""Command keepalives must detect a lost peer, not a merely silent command."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import pwd
import select
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from sim.ssh_commands import SshCommands


@unittest.skipUnless(shutil.which('ssh'), 'requires the OpenSSH client')
class SshConfigurationTests(unittest.TestCase):
    def test_inventory_cannot_disable_failure_detection_or_reuse_an_old_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'ssh_config'
            config.write_text('Host bench\n  HostName 127.0.0.1\n  ServerAliveInterval 0\n'
                              '  ServerAliveCountMax 99\n  ControlMaster auto\n  ControlPath /old-master\n')
            node = SshCommands()
            node.spec = {'ssh_config': str(config)}
            result = subprocess.run([*node.ssh_args(), '-G', 'bench'], capture_output=True,
                                    timeout=5, check=True)
            fields = dict(line.split(None, 1) for line in result.stdout.decode().splitlines())
            self.assertEqual(fields['serveraliveinterval'], '2')
            self.assertEqual(fields['serveralivecountmax'], '3')
            self.assertEqual(fields['controlmaster'], 'false')
            self.assertNotIn('controlpath', fields)


@unittest.skipUnless(all(shutil.which(tool) for tool in ('ssh', 'sshd', 'ssh-keygen')),
                     'requires local OpenSSH client, server and key generator')
class SshConnectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='fips-ssh-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        key = self.root / 'key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                       check=True, capture_output=True, timeout=5)
        config = self.root / 'sshd_config'
        config.write_text(f'HostKey {key}\nAuthorizedKeysFile {key}.pub\nStrictModes no\n'
                          'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n')
        # One local inetd-style server and an in-process TCP relay: dropping bytes
        # keeps both TCP connections open without firewall or network changes.
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.addCleanup(self.listener.close)
        with socket.socket() as backend:
            backend.bind(('127.0.0.1', 0))
            backend.listen(1)
            self.upstream = socket.create_connection(backend.getsockname(), timeout=5)
            server_socket, _ = backend.accept()
        self.addCleanup(self.upstream.close)
        self.log = (self.root / 'sshd.log').open('wb')
        self.addCleanup(self.log.close)
        with server_socket:
            self.server = subprocess.Popen([shutil.which('sshd'), '-i', '-e', '-f', str(config)],
                                           stdin=server_socket, stdout=server_socket,
                                           stderr=self.log, start_new_session=True)
        self.drop, self.stop = threading.Event(), threading.Event()
        self.relay_errors = []
        self.relay = threading.Thread(target=self.forward)
        self.relay.start()
        self.addCleanup(self.close_connection)
        client_config = self.root / 'ssh_config'
        client_config.write_text(f'Host bench\n  HostName 127.0.0.1\n'
                                 f'  Port {self.listener.getsockname()[1]}\n'
                                 f'  User {pwd.getpwuid(os.getuid()).pw_name}\n  IdentityFile {key}\n'
                                 '  IdentitiesOnly yes\n  StrictHostKeyChecking no\n'
                                 '  UserKnownHostsFile /dev/null\n  LogLevel INFO\n')
        self.node = SshCommands()
        self.node.host, self.node.output = 'bench', self.root
        self.node.spec = {'ssh_config': str(client_config)}

    def forward(self):
        try:
            with self.listener.accept()[0] as client:
                while not self.stop.is_set():
                    for source in select.select([client, self.upstream], [], [], 0.1)[0]:
                        data = source.recv(65536)
                        if not data:
                            return
                        if not self.drop.is_set():
                            (self.upstream if source is client else client).sendall(data)
        except OSError as error:
            if not self.stop.is_set():
                self.relay_errors.append(error)

    def close_connection(self):
        (self.root / 'release').touch()
        self.stop.set()
        self.relay.join(6)
        try:
            self.server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(self.server.pid, signal.SIGKILL)
            self.server.wait(timeout=3)
        self.assertFalse(self.relay.is_alive())
        self.assertEqual(self.relay_errors, [])

    def test_healthy_command_may_be_silent_longer_than_the_keepalive_failure_window(self):
        # The SSH daemon still answers keepalives while its command is silent.
        self.assertEqual(self.node.remote('sleep 9; printf completed', timeout=20), b'completed')

    def test_blackholed_established_connection_releases_the_waiting_worker(self):
        ready, release = self.root / 'ready', self.root / 'release'
        command = (f'touch {shlex.quote(str(ready))}; '
                   f'while test ! -f {shlex.quote(str(release))}; do sleep 0.1; done; printf completed')
        with ThreadPoolExecutor(max_workers=1) as pool:
            buying = pool.submit(self.node.remote, command, timeout=30)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists():
                    if buying.done():
                        buying.result()
                    self.assertLess(time.monotonic(), deadline, 'local SSH command never started')
                    time.sleep(0.01)
                self.drop.set()
                # A responsive daemon whose packets vanish is different from
                # closing a socket. The 15-second funding result wait must fit.
                with self.assertRaisesRegex(RuntimeError, 'remote operation failed'):
                    buying.result(timeout=12)
                self.assertIn(b'not responding', (self.root / 'last-error.txt').read_bytes())
                self.assertTrue(buying.done())
            finally:
                release.touch()
                self.drop.clear()
                self.stop.set()  # Also bound cleanup when the regression is RED.


if __name__ == '__main__':
    unittest.main()
