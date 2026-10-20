"""Command keepalives must detect a lost peer, not a merely silent command."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
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
from unittest.mock import patch

from sim.ssh_commands import SshCommands, remote_slot


class SshCapacityTests(unittest.TestCase):
    def node(self, host, output):
        node = SshCommands()
        node.host, node.output, node.spec = host, output, {}
        return node

    def test_same_host_commands_share_three_slots_and_other_hosts_remain_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            node = self.node('capacity-test', Path(directory))
            condition, release = threading.Condition(), threading.Event()
            active = maximum = calls = 0

            def run(*args, **kwargs):
                nonlocal active, maximum, calls
                with condition:
                    active += 1; calls += 1
                    maximum = max(maximum, active)
                    condition.notify_all()
                try:
                    self.assertTrue(release.wait(2))
                    return subprocess.CompletedProcess(args, 0, stdout=b'original', stderr=b'')
                finally:
                    with condition:
                        active -= 1

            with patch('sim.ssh_commands.subprocess.run', side_effect=run), ThreadPoolExecutor(max_workers=8) as pool:
                pending = [pool.submit(node.remote, 'original', timeout=2) for _ in range(8)]
                try:
                    with condition:
                        self.assertTrue(condition.wait_for(lambda: calls >= 3, timeout=1))
                    time.sleep(.03)
                    self.assertEqual(calls, 3)
                    other = self.node('independent-test-host', node.output)
                    with remote_slot(other, .1):
                        pass
                    config = Path(directory)/'other-config'
                    config.write_text('')
                    other.host, other.spec = node.host, {'ssh_config': str(config)}
                    with remote_slot(other, .1):
                        pass
                finally:
                    release.set()
                self.assertEqual([p.result(timeout=2) for p in pending], [b'original'] * 8)
            self.assertEqual((calls, maximum), (8, 3))

    def test_queue_consumes_deadline_and_expired_wait_never_dispatches(self):
        with tempfile.TemporaryDirectory() as directory:
            node = self.node('deadline-test', Path(directory))
            with ExitStack() as held, patch('sim.ssh_commands.subprocess.run') as run:
                for _ in range(3): held.enter_context(remote_slot(node, 1))
                started = time.monotonic()
                with self.assertRaises(TimeoutError):node.remote('never-dispatched', timeout=.04)
                self.assertLess(time.monotonic() - started, .2)
                run.assert_not_called()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(node.remote, 'queued', timeout=.3)
                    time.sleep(.04)
                    held.close()
                    run.return_value = subprocess.CompletedProcess([], 0, stdout=b'queued', stderr=b'')
                    self.assertEqual(pending.result(timeout=1), b'queued')
                self.assertGreater(run.call_args.kwargs['timeout'], 0)
                self.assertLess(run.call_args.kwargs['timeout'], .28)

    def test_timeout_or_remote_failure_releases_capacity_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            node = self.node('failure-test', Path(directory))
            for failure in (subprocess.TimeoutExpired('owned-ssh', .01),
                            subprocess.CompletedProcess([], 255, stdout=b'', stderr=b'failed')):
                with patch('sim.ssh_commands.subprocess.run', side_effect=failure if isinstance(failure, Exception) else None,
                           return_value=failure) as run:
                    with self.assertRaises((subprocess.TimeoutExpired, RuntimeError)):
                        node.remote('one-attempt', timeout=.1)
                    self.assertEqual(run.call_count, 1)
                with ExitStack() as released:
                    for _ in range(3): released.enter_context(remote_slot(node, .1))


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
