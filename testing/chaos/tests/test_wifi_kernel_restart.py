"""Kernel reset ownership, changed-boot proof and reuse of the original accounts."""

import copy
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import Mock, patch

from sim.wifi_kernel_restart import BOOT_ID, KernelRestartRun, reboot_profile
from sim.wifi_remote import Router
from tests import test_wifi_restart as crash
from tests.test_wifi_restart_load import journal


OLD = '11111111-2222-3333-4444-555555555555'
NEW = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


class KernelRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.run = object.__new__(KernelRestartRun)
        self.node = Mock(npub='middle', guard_ready=True, created=True)
        self.node.config, self.node.state = '/etc/test/config.json', '/etc/test/state'
        self.run.nodes = {'n02': self.node}
        self.run.monitor, self.run.monitor_nodes, self.run.save = Mock(), Mock(), Mock()
        self.run.args = Mock(binary=Mock(read_bytes=Mock(return_value=b'binary')))
        self.run.original = {'n02': {'hashes': 'saved', 'identity': 'original', 'connected_peers': []}}
        self.node.baseline.return_value = copy.deepcopy(self.run.original['n02'])
        self.node.remote.return_value = OLD.encode()
        self.run.evidence = {'restart': {'old_boot_id': OLD, 'before': {'npub': 'middle'},
                                         'account_identity': 'saved identity'}}
        self.run.state_json = Mock(return_value=journal())
        self.run.middle_sample = Mock(return_value={'npub': 'middle', 'host_process': {'host': 'n02'}})

    def test_unchanged_or_unreadable_boot_cannot_restage_or_start(self):
        self.assertIsNone(self.run.recovered_boot())
        self.node.remote.side_effect = RuntimeError('connection lost')
        self.assertIsNone(self.run.recovered_boot())
        self.node.stage_runtime.assert_not_called()
        self.node.start.assert_not_called()
        self.assertTrue(self.node.guard_ready)
        self.node.baseline.assert_not_called()

    def test_new_boot_requires_unchanged_original_state(self):
        self.node.remote.return_value = NEW.encode()
        self.assertEqual(self.run.recovered_boot(), self.run.original['n02'])
        self.assertFalse(self.node.guard_ready)
        self.node.baseline.return_value['hashes'] = 'changed'
        with self.assertRaisesRegex(RuntimeError, 'original router'):
            self.run.recovered_boot()

    def test_resume_reuses_persisted_window_without_initializing_or_repeating_start(self):
        self.run.recovered_boot = Mock(return_value=self.run.original['n02'])
        self.node.remote.return_value = b'saved identity'
        self.run.resume_middle()
        self.assertEqual(self.run.expected_lost, {'a': 3000, 'b': 4000})
        self.run.resume_middle()
        self.node.stage_runtime.assert_called_once_with(b'binary')
        self.node.start.assert_called_once()
        self.node.prepare.assert_not_called()
        self.run.state_json.assert_called_once_with('n02', 'seller/ledger.json')

    def test_partial_staging_remains_owned_and_is_never_replayed(self):
        self.run.recovered_boot = Mock(return_value=self.run.original['n02'])
        self.node.remote.return_value = b'saved identity'
        self.node.stage_runtime.side_effect = RuntimeError('partial transfer')
        with self.assertRaisesRegex(RuntimeError, 'partial transfer'):
            self.run.resume_middle()
        with self.assertRaisesRegex(RuntimeError, 'already attempted'):
            self.run.resume_middle()
        self.node.stage_runtime.assert_called_once()
        self.node.start.assert_not_called()

    def test_saved_candidate_identity_is_required_before_any_runtime_write(self):
        self.run.recovered_boot = Mock(return_value=self.run.original['n02'])
        self.node.remote.return_value = b'different identity'
        with self.assertRaisesRegex(RuntimeError, 'candidate identity'):
            self.run.resume_middle()
        self.node.stage_runtime.assert_not_called()

    def test_monitor_rotation_retains_failures_and_keeps_other_routers_observed(self):
        old = self.run.monitor
        old.samples, old.errors = [{'ok': True}], []
        remaining = {'n01': Mock(), 'n03': Mock()}
        with patch('sim.wifi_kernel_restart.ManagementMonitor') as monitor:
            KernelRestartRun.monitor_nodes(self.run, remaining)
        old.close.assert_called_once()
        old.check.assert_called_once()
        monitor.assert_called_once_with(remaining)
        self.assertIs(self.run.monitor.samples, old.samples)
        self.run.monitor.start.assert_called_once()


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('flock'),
                     'kernel ownership checks need Linux procfs and flock')
class KernelShellTests(unittest.TestCase):
    setUp = crash.CrashShellTests.setUp
    tearDown = crash.CrashShellTests.tearDown
    local = crash.CrashShellTests.local
    start_guard = crash.CrashShellTests.start_guard
    wait_file = crash.CrashShellTests.wait_file
    launch = crash.CrashShellTests.launch
    observed = crash.CrashShellTests.observed

    def test_reset_requires_exact_candidate_and_boot_and_dispatches_once(self):
        child = self.launch(self.node)
        observed = self.observed(self.node, child)
        fake_trigger, fake_boot = self.root / 'trigger', self.root / 'boot'
        fake_trigger.touch()
        fake_boot.write_text(OLD)
        guarded = self.node.guarded

        def isolated(command, **kwargs):
            # Never execute a real kernel reset in the Linux fixture.
            self.assertEqual(command.count('/proc/sysrq-trigger'), 2)
            command = command.replace('/proc/sysrq-trigger', str(fake_trigger)).replace(BOOT_ID, str(fake_boot))
            return guarded(command, **kwargs)

        with patch.object(self.node, 'guarded', side_effect=isolated) as dispatch:
            for modified, boot in ((observed, NEW),
                                   ({**observed, 'host_process': {**observed['host_process'], 'start_ticks': 1}}, OLD)):
                receipt = reboot_profile(self.node, modified, boot)
                self.assertTrue(receipt['boot_change_required'])
                self.assertEqual(fake_trigger.read_bytes(), b'')
                self.assertIsNone(child.poll())
            receipt = reboot_profile(self.node, observed, OLD)
            self.assertEqual(fake_trigger.read_bytes(), b'b')
            self.assertEqual(dispatch.call_count, 3)
            self.assertTrue(receipt['boot_change_required'])
        with patch.object(self.node, 'guarded', side_effect=RuntimeError('reply lost')) as dispatch:
            reboot_profile(self.node, observed, OLD)
            dispatch.assert_called_once()

    def test_ram_staging_never_changes_existing_accounts(self):
        # Exercise the actual staging writer against an independent fresh path.
        self.node.temporary = str(self.root / 'new-runtime')
        self.node.binary = self.node.temporary + '/fips-relay'
        saved = {p: p.read_bytes() for p in Path(self.node.parent).rglob('*') if p.is_file()}
        Router.stage_runtime(self.node, b'candidate executable')
        self.assertEqual({p: p.read_bytes() for p in saved}, saved)
        self.assertEqual(Path(self.node.binary).read_bytes(), b'candidate executable')
        self.node.cleanup()


if __name__ == '__main__':
    unittest.main()
