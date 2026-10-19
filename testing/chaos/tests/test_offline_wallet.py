"""Keep the original command owned across measurement, refusal and lost replies."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from sim.offline_wallet import WalletCLI


class LocalNode:
    def __init__(self, root):
        self.temporary = str(root / 'commands')
        Path(self.temporary).mkdir()
        self.binary = str(root / 'wallet')
        self.config = str(root / 'calls')
        self.lose_reply = False
        self.dispatch = None
        Path(self.binary).write_text('#!' + sys.executable + '''
import json,signal,sys,time
request=json.load(sys.stdin)
with open(sys.argv[2], 'a') as calls: calls.write('one\\n')
if request.get('ignore_term'): signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(request.get('sleep', .05))
if request.get('refuse'):
    print('storage capacity exceeded', file=sys.stderr)
    sys.exit(1)
print(json.dumps({'completed': True}))
''')
        Path(self.binary).chmod(0o700)

    def remote(self, command, timeout=20):
        if self.dispatch is not None:
            self.dispatch.poll()
        argv = ['/bin/sh', '-c', command] if isinstance(command, str) else command
        if self.lose_reply and isinstance(command, str) and command.startswith("trap '' HUP"):
            self.lose_reply = False
            self.dispatch = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            raise subprocess.TimeoutExpired(argv, 0)
        return subprocess.run(argv, capture_output=True, check=True, timeout=timeout).stdout

    def write(self, path, raw):
        with Path(path).open('xb') as output:
            output.write(raw)


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('timeout') and Path('/usr/bin/time').is_file(),
                     'requires Linux procfs, GNU timeout and process usage time')
class OfflineWalletTests(unittest.TestCase):
    def fixture(self, root):
        node = LocalNode(root)
        output = root / 'evidence'
        output.mkdir()
        cli = WalletCLI(node, shutil.which('timeout'), output, time_tool='/usr/bin/time')
        return node, cli, output

    def test_complete_and_refused_commands_keep_usage_and_all_owner_epochs(self):
        with tempfile.TemporaryDirectory() as directory:
            node, cli, output = self.fixture(Path(directory))
            self.assertEqual(cli.command('accepted', {}), {'completed': True})
            self.assertIsNone(cli.command('refused', {'refuse': True}, error='storage capacity exceeded'))
            for label, code in (('accepted', 0), ('refused', 1)):
                result = json.loads((output / label / 'result.json').read_bytes())
                self.assertEqual(result['exit_code'], code)
                self.assertGreater(result['maximum_rss_kib'], 0)
                self.assertGreaterEqual(result['cpu_seconds'], 0)
                self.assertEqual(set(result['owners']), {'child', 'timeout', 'observer', 'measurement'})
                self.assertTrue(result['recorded_owners_absent'])
            self.assertEqual(Path(node.config).read_text(), 'one\none\n')
            self.assertFalse(cli.pending)

    def test_deadline_kills_the_original_wallet_even_when_it_ignores_term(self):
        with tempfile.TemporaryDirectory() as directory:
            node, cli, output = self.fixture(Path(directory))
            with self.assertRaisesRegex(AssertionError, 'wallet command failed'):
                cli.command('deadline', {'sleep': 30, 'ignore_term': True}, seconds=1)
            result = json.loads((output / 'deadline/result.json').read_bytes())
            self.assertNotEqual(result['exit_code'], 0)
            self.assertLess(result['device_seconds'], 5)
            self.assertTrue(result['recorded_owners_absent'])
            self.assertEqual(Path(node.config).read_text(), 'one\n')
            self.assertFalse(cli.pending)

    def test_lost_reply_observes_completion_without_repeating_the_original(self):
        with tempfile.TemporaryDirectory() as directory:
            node, cli, output = self.fixture(Path(directory))
            node.lose_reply = True
            with self.assertRaises(subprocess.TimeoutExpired):
                cli.command('lost-reply', {'sleep': .2}, seconds=1)
            self.assertEqual(node.dispatch.wait(timeout=5), 0)
            self.assertEqual(Path(node.config).read_text(), 'one\n')
            self.assertTrue((output / 'lost-reply/uncertain.json').is_file())
            self.assertTrue((output / 'lost-reply/owner-release.json').is_file())
            self.assertFalse((output / 'lost-reply/result.json').exists())
            self.assertFalse(cli.pending)


if __name__ == '__main__':
    unittest.main()
