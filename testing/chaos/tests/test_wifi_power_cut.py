"""Manual power evidence cannot substitute a timeout or software restart for a cut."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_power_cut import PowerCutFundingRun, confirmed_cycle
from tests.test_wifi_kernel_restart import OLD, NEW


class PowerCutTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.run = object.__new__(PowerCutFundingRun)
        self.run.root = Path(self.directory.name)
        self.node = Mock(host='router', config='/etc/test/config.json', state='/etc/test/state')
        self.run.nodes = {'n01': self.node, 'n03': Mock(mac='other-mac')}
        self.run.monitor, self.run.monitor_nodes, self.run.save = Mock(), Mock(), Mock()
        self.run.args = SimpleNamespace(binary=Mock(read_bytes=Mock(return_value=b'candidate')))
        self.run.samples = {'n01': {'sample': 'original'}}
        self.run.original = {'n01': {'hashes': 'original'}}
        self.state = {'run': 'fresh-run', 'node': 'n01', 'old_boot_id': OLD,
                      'account_identity': 'identity config'}
        self.receipt = {**{key: self.state[key] for key in ('run', 'node', 'old_boot_id')},
                        'power_disconnected': True}

    def acknowledge(self):
        (self.run.root / 'power-cut-confirmation.json').write_text(json.dumps(self.receipt))

    def test_all_three_independent_observations_required(self):
        for evidence in ({}, {'unreachable_at': 1}, {'new_boot_id': NEW},
                         {'unreachable_at': 1, 'new_boot_id': OLD}):
            with self.subTest(evidence=evidence):
                self.assertFalse(confirmed_cycle({**self.state, **evidence}, self.receipt))
        self.state.update(unreachable_at=1, new_boot_id=NEW)
        self.assertTrue(confirmed_cycle(self.state, self.receipt))
        for changed in ({'run': 'previous'}, {'node': 'n02'}, {'old_boot_id': NEW},
                        {'power_disconnected': False}, {'power_disconnected': 1}, {'extra': True}):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                confirmed_cycle(self.state, {**self.receipt, **changed})

    def test_wait_observes_outage_and_new_boot_before_accepting_operator_receipt(self):
        self.acknowledge()
        with patch('sim.wifi_power_cut.boot_id', side_effect=[RuntimeError('offline'), NEW]), \
                patch('sim.wifi_power_cut.time.sleep'):
            self.run.wait_for_power_cycle(self.state)
        self.assertEqual(self.state['operator_confirmation'], self.receipt)
        self.assertEqual(self.state['new_boot_id'], NEW)
        self.assertFalse(self.node.guard_ready)
        self.node.stage_runtime.assert_not_called()
        self.node.start.assert_not_called()

    def test_cut_between_boot_sample_and_heartbeat_is_observed(self):
        self.acknowledge()
        self.node.management_check.side_effect = RuntimeError('power disappeared')
        with patch('sim.wifi_power_cut.boot_id', side_effect=[OLD, RuntimeError('offline'), NEW]), \
                patch('sim.wifi_power_cut.time.sleep'):
            self.run.wait_for_power_cycle(self.state)
        self.assertEqual(self.state['new_boot_id'], NEW)
        self.assertIn('unreachable_at', self.state)

    def test_live_guard_failure_cannot_be_accepted_as_power_loss(self):
        self.acknowledge()
        self.node.management_check.side_effect = RuntimeError('changed guard')
        with patch('sim.wifi_power_cut.boot_id', return_value=OLD), \
                self.assertRaisesRegex(RuntimeError, 'live candidate guard'):
            self.run.wait_for_power_cycle(self.state)
        self.node.stage_runtime.assert_not_called()

    def test_missing_attestation_times_out_without_restage(self):
        with patch('sim.wifi_power_cut.boot_id', return_value=NEW), \
                patch('sim.wifi_power_cut.time.monotonic', side_effect=[0, 1, 241]), \
                patch('sim.wifi_power_cut.time.sleep'), \
                self.assertRaisesRegex(RuntimeError, 'deadline'):
            self.run.wait_for_power_cycle(self.state)
        self.assertNotIn('operator_confirmation', self.state)
        self.node.stage_runtime.assert_not_called()

    def prepared(self):
        self.state.update(new_boot_id=NEW, unreachable_at=1, operator_confirmation=self.receipt)
        self.node.remote.return_value = self.state['account_identity'].encode()
        self.node.baseline.return_value = copy.deepcopy(self.run.original['n01'])

    def test_restaging_reuses_account_and_restores_shortcut_filter(self):
        self.prepared()
        with patch('sim.wifi_power_cut.boot_id', return_value=NEW), \
                patch('sim.wifi_power_cut.baseline_restored', return_value=True):
            self.run.restage_after_power_cut(self.state)
            with self.assertRaisesRegex(RuntimeError, 'already attempted'):
                self.run.restage_after_power_cut(self.state)
        self.node.stage_runtime.assert_called_once_with(b'candidate')
        self.node.install_filter.assert_called_once_with('other-mac')
        self.node.prepare.assert_not_called()
        self.node.start.assert_not_called()
        self.assertTrue(self.state['restaged'])

    def test_changed_identity_and_partial_stage_never_reinitialize_or_repeat(self):
        self.prepared()
        with patch('sim.wifi_power_cut.boot_id', return_value=NEW), \
                patch('sim.wifi_power_cut.baseline_restored', return_value=True):
            self.node.remote.return_value = b'wrong identity'
            with self.assertRaisesRegex(RuntimeError, 'candidate identity'):
                self.run.restage_after_power_cut(self.state)
            self.node.stage_runtime.assert_not_called()
            self.node.remote.return_value = b'identity config'
            self.node.stage_runtime.side_effect = RuntimeError('partial upload')
            with self.assertRaisesRegex(RuntimeError, 'partial upload'):
                self.run.restage_after_power_cut(self.state)
            with self.assertRaisesRegex(RuntimeError, 'already attempted'):
                self.run.restage_after_power_cut(self.state)
        self.node.stage_runtime.assert_called_once()
        self.node.prepare.assert_not_called()

    def test_reboot_epoch_does_not_compare_ticks_from_different_boots(self):
        self.prepared()
        self.state['restaged'] = True
        self.run.evidence = {'manual_power_cut': self.state}
        old, new = {'start_ticks': 10000}, {'start_ticks': 10}
        with patch('sim.wifi_power_cut.boot_id', return_value=NEW):
            self.assertTrue(self.run.restarted_epoch('n01', old, new))
            self.assertFalse(self.run.restarted_epoch('n03', old, new))


if __name__ == '__main__':
    unittest.main()
