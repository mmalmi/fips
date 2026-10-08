"""Installed-service ownership, reversible UCI selection and observed paid boot."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_boot_restart import BootRestartRun
from sim.wifi_boot_service import restore_script
from sim.wifi_remote import digest
from tests.test_wifi_restart_load import journal


@unittest.skipUnless(shutil.which('sha256sum'), 'shell ownership checks require sha256sum')
class ServiceRestorationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.node = SimpleNamespace(parent=str(self.root), original_binary='/usr/sbin/fips-relay',
                                    config='/etc/test/paid.json', original_config='/etc/test/original.json')
        self.saved = b'original UCI configuration\n'
        self.selected = b'selected UCI configuration\n'
        (self.root / 'boot-uci').write_bytes(self.saved)
        (self.root / 'boot-armed').write_text(digest(self.selected) + '  -\n')
        self.uci = self.root / 'uci-config'
        self.uci.write_bytes(self.selected)
        self.candidate = '/usr/libexec/fips-relay-openwrt\n/usr/sbin/fips-relay\n/etc/test/paid.json\n'
        self.original = self.candidate.replace('/paid.json', '/original.json')
        (self.root / 'service').write_text(self.candidate)
        (self.root / 'original-command').write_text(self.original)
        (self.root / 'pending').touch()
        (self.root / 'actions').touch()
        (self.root / 'proc/42').mkdir(parents=True)
        scripts = {
            'uci': 'cat "$FIXTURE/pending"',
            'ubus': 'cat "$FIXTURE/service"',
            'jsonfilter': 'value=$(cat); printf "%s" "$value"; test -n "$value"',
            'init': '''echo "$1" >>"$FIXTURE/actions"
case "$1" in
 stop) : >"$FIXTURE/service";;
 start) cp "$FIXTURE/original-command" "$FIXTURE/service";;
 *) exit 1;;
esac''',
        }
        for name, body in scripts.items():
            path = self.root / name
            path.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
            path.chmod(0o700)
        with patch('sim.wifi_boot_service.UCI', str(self.uci)), \
                patch('sim.wifi_boot_service.INIT', str(self.root / 'init')), \
                patch('sim.wifi_boot_service.PROC', str(self.root / 'proc')):
            (self.root / 'restore.sh').write_bytes(restore_script(self.node, digest(self.saved)))

    def run_script(self, action='restore'):
        return subprocess.run(['sh', str(self.root / 'restore.sh'), action], capture_output=True,
                              env=dict(os.environ, FIXTURE=str(self.root),
                                       PATH=str(self.root) + os.pathsep + os.environ['PATH']), timeout=5)

    def test_restore_stops_only_owned_paid_service_and_reopens_original(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.uci.read_bytes(), self.saved)
        self.assertEqual((self.root / 'actions').read_text(), 'stop\nstart\n')
        self.assertFalse((self.root / 'boot-armed').exists())
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual((self.root / 'actions').read_text(), 'stop\nstart\n')

    def test_cancel_before_reboot_preserves_running_original(self):
        (self.root / 'service').write_text(self.original)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.uci.read_bytes(), self.saved)
        self.assertEqual((self.root / 'actions').read_text(), '')

    def test_durable_intent_before_uci_replace_can_be_safely_cancelled(self):
        self.uci.write_bytes(self.saved)
        (self.root / 'service').write_text(self.original)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.uci.read_bytes(), self.saved)
        self.assertEqual((self.root / 'actions').read_text(), '')

    def test_stop_leaves_account_and_boot_selection_for_collection(self):
        self.assertEqual(self.run_script('stop').returncode, 0)
        self.assertEqual(self.uci.read_bytes(), self.selected)
        self.assertTrue((self.root / 'boot-armed').exists())
        self.assertEqual((self.root / 'actions').read_text(), 'stop\n')
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual((self.root / 'actions').read_text(), 'stop\nstart\n')

    def test_changed_configuration_pending_edits_service_or_backup_refuse_mutation(self):
        for name in ('uci-config', 'pending', 'service', 'boot-uci'):
            path = self.root / name
            saved = path.read_bytes()
            path.write_bytes(b'unrelated owner\n')
            before = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script().returncode, 0)
                self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}, before)
            path.write_bytes(saved)

    def test_deleted_service_registration_does_not_prove_process_exit(self):
        (self.root / 'proc/42/cmdline').write_bytes(b'/usr/sbin/fips-relay\0run\0/etc/test/paid.json\0')
        sleeper = self.root / 'sleep'
        sleeper.write_text('#!/bin/sh\nexit 99\n')
        sleeper.chmod(0o700)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual((self.root / 'service').read_text(), '')
        self.assertEqual(self.uci.read_bytes(), self.selected)
        self.assertTrue((self.root / 'boot-armed').exists())
        self.assertEqual((self.root / 'actions').read_text(), 'stop\n')

    def test_acknowledged_stop_can_retain_registration_until_process_exit(self):
        (self.root / 'init').write_text('''#!/bin/sh
echo "$1" >>"$FIXTURE/actions"
case "$1" in
 stop) touch "$FIXTURE/deleting";;
 start) cp "$FIXTURE/original-command" "$FIXTURE/service";;
esac
''')
        (self.root / 'ubus').write_text('''#!/bin/sh
cat "$FIXTURE/service"
if [ -f "$FIXTURE/deleting" ]; then
  : >"$FIXTURE/service"
  rm "$FIXTURE/deleting"
fi
''')
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.uci.read_bytes(), self.saved)
        self.assertEqual((self.root / 'actions').read_text(), 'stop\nstart\n')


class AutomaticBootTests(unittest.TestCase):
    def setUp(self):
        self.run = object.__new__(BootRestartRun)
        self.node = Mock(npub='middle', temporary='/tmp/owned', original_binary='/usr/sbin/fips-relay')
        self.node.config, self.node.state = '/etc/test/config.json', '/etc/test/state'
        self.run.nodes = {'n02': self.node}
        self.run.evidence = {'restart': {'account_identity': 'same', 'before': {'npub': 'middle'}}}
        self.run.boot_journal, self.run.boot_loss = journal(), {'a': 3000, 'b': 4000}
        self.run.args = Mock(binary=Mock(read_bytes=Mock(return_value=b'observation executable')))
        self.run.save, self.run.monitor_nodes = Mock(), Mock()
        self.node.remote.return_value = b'same'
        self.run.middle_sample = Mock(return_value={'npub': 'middle'})
        self.events = []
        self.run.recovered_boot = Mock(side_effect=lambda: self.events.append('observed') or {'instance': {'pid': 42}})
        self.node.stage_runtime.side_effect = lambda data: self.events.append('staged')

    def test_observe_before_ram_staging_and_never_start_or_initialize(self):
        self.run.resume_middle()
        self.run.resume_middle()
        self.assertEqual(self.events, ['observed', 'staged'])
        self.node.start.assert_not_called()
        self.node.prepare.assert_not_called()
        self.assertEqual(self.node.process_binary, '/usr/sbin/fips-relay')
        self.assertEqual(self.run.expected_lost, self.run.boot_loss)
        self.assertEqual(self.run.evidence['restart']['pre_reset_journal'], journal())

    def test_partial_observation_staging_is_not_replayed(self):
        self.node.stage_runtime.side_effect = RuntimeError('partial stage')
        with self.assertRaisesRegex(RuntimeError, 'partial stage'):
            self.run.resume_middle()
        with self.assertRaisesRegex(RuntimeError, 'already attempted'):
            self.run.resume_middle()
        self.node.stage_runtime.assert_called_once()
        self.node.start.assert_not_called()

    def test_changed_paid_identity_is_rejected_before_staging(self):
        self.node.remote.return_value = b'changed'
        with self.assertRaisesRegex(RuntimeError, 'paid identity'):
            self.run.resume_middle()
        self.node.stage_runtime.assert_not_called()


if __name__ == '__main__':
    unittest.main()
