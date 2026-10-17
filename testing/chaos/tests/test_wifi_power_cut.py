"""Manual power evidence cannot substitute a timeout or software restart for a cut."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_power_cut import PowerCutFundingRun, PowerCutSettlementRun, confirmed_cycle
from sim.wifi_settlement import SettlementRun
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

    def provider_cut(self):
        previous = self.run
        self.run = object.__new__(PowerCutSettlementRun)
        self.run.__dict__.update(previous.__dict__)
        self.run.nodes['n02'] = self.node
        self.run.nodes['n01'] = Mock(host='other', config='/other/config', state='/other/state')
        self.run.nodes['n01'].remote.return_value = b'identity config'
        for name in ('n01', 'n02'):
            self.run.nodes[name].output = self.run.root
            self.run.nodes[name].temporary = '/tmp/test'
        self.run.samples['n02'] = {'sample': 'provider'}
        self.run.original['n02'] = self.run.original['n01']
        self.state['node'] = 'n02'
        self.receipt['node'] = 'n02'

    def test_provider_restage_keeps_both_forwarding_neighbors(self):
        self.provider_cut()
        self.prepared()
        with patch('sim.wifi_power_cut.boot_id', return_value=NEW), \
                patch('sim.wifi_power_cut.baseline_restored', return_value=True):
            self.run.restage_after_power_cut(self.state)
        self.node.stage_runtime.assert_called_once_with(b'candidate')
        self.node.install_filter.assert_called_once_with(None)
        self.run.nodes['n01'].stage_runtime.assert_not_called()

    def test_cut_request_and_pause_select_the_same_provider(self):
        self.provider_cut()
        self.run.run = 'fresh-run'
        self.run.evidence = {}
        self.run.crash_attempts = []
        self.run.phase = Mock()
        self.node.remote.return_value = b'original'
        self.run.wait_for_power_cycle = Mock()
        self.run.restage_after_power_cut = Mock()
        with patch('sim.wifi_power_cut.boot_id', return_value=OLD), \
                patch('sim.wifi_power_cut.pause_profile') as pause, \
                patch('sim.wifi_account_recovery.RouterAccountRecovery.interrupt_participants') as interrupt:
            self.run.interrupt_participants()
        pause.assert_called_once_with(self.node, self.run.samples['n02'])
        interrupt.assert_called_once_with(exclude={'n02'})
        request = json.loads((self.run.root / 'power-cut-request.json').read_bytes())
        self.assertEqual(request['node'], 'n02')
        self.assertEqual(request['boundary'], 'original settlement committed at mint, reply withheld')
        self.assertEqual(self.run.crash_attempts, ['n02'])
        self.assertEqual(set(self.run.monitor_nodes.call_args.args[0]), {'n01', 'n03'})

    def test_settlement_waits_for_operator_but_status_keeps_its_deadline(self):
        self.provider_cut()
        with patch('sim.paid_wifi.PaidWifiRun.ctl', return_value='reply') as control:
            self.assertEqual(self.run.ctl('n01', 'settle'), 'reply')
            control.assert_called_once_with('n01', 'settle', operation_timeout=330)
            control.reset_mock()
            self.run.ctl('n02', 'status', operation_timeout=5)
            control.assert_called_once_with('n02', 'status', operation_timeout=5)

    def reverse_channel(self):
        self.provider_cut()
        self.run.evidence = {}
        self.run.reverse_pending = {'funding': {'original': {'funded': {'terms': {
            'expires_unix': 2000, 'refund_after_unix': 3000,
        }}}}}
        self.run.state_json = Mock(return_value=self.run.reverse_pending)

    def test_physical_settlement_extends_both_channel_and_expiry_wait(self):
        for cls, lifetime, wait in ((SettlementRun, 180, 150),
                                    (PowerCutSettlementRun, 1440, 750)):
            with self.subTest(cls=cls.__name__), patch('sim.paid_wifi.PaidWifiRun.profile_config',
                                                      return_value={'terms': {'controller': {}}}):
                run = object.__new__(cls)
                self.assertEqual(run.profile_config('n01')['terms']['controller']['channel_lifetime_secs'],
                                 lifetime)
                self.assertEqual(run.expiry_wait_seconds, wait)

    def test_reverse_expiry_margin_is_checked_before_arming_not_refund_deadline(self):
        self.reverse_channel()
        with patch('sim.committed_settlement.CommittedSettlement.interrupt_settlement') as arm:
            self.node.remote.return_value = b'1401\n'
            with self.assertRaisesRegex(RuntimeError, 'reverse channel expires too soon'):
                self.run.interrupt_settlement({})
            arm.assert_not_called()
            self.assertEqual(self.run.evidence['reverse_expiry_margins']['before_arm']['remaining_seconds'], 599)
            self.node.remote.return_value = b'1400\n'
            self.run.interrupt_settlement({})
            arm.assert_called_once_with({})
            self.node.remote.assert_called_with(['date', '+%s'])

    def test_provider_restart_rechecks_its_clock_and_preserves_rejected_account(self):
        self.reverse_channel()
        with patch('sim.wifi_settlement.SettlementRun.launch') as launch:
            self.node.remote.return_value = b'1821\n'
            with self.assertRaisesRegex(RuntimeError, 'reverse channel expires too soon'):
                self.run.launch('n02')
            launch.assert_not_called()
            self.node.prepare.assert_not_called()
            self.node.remote.return_value = b'1820\n'
            self.run.launch('n02')
            launch.assert_called_once_with('n02')
            observation = self.run.evidence['reverse_expiry_margins']['before_provider_restart']
            self.assertEqual(observation['provider_unix'], 1820)
            self.assertEqual(observation['remaining_seconds'], 180)

    def test_rejected_postboot_margin_does_not_restart_participants_during_cleanup(self):
        for clock in (b'1821\n', b'invalid', RuntimeError('unreachable')):
            with self.subTest(clock=clock):
                self.reverse_channel()
                self.node.remote.side_effect = clock if isinstance(clock, Exception) else None
                self.node.remote.return_value = clock
                with self.assertRaises((RuntimeError, ValueError)):
                    self.run.launch('n02')
                with patch('sim.wifi_account_recovery.RouterAccountRecovery.restore_controls') as restore, \
                        self.assertRaisesRegex(RuntimeError, 'preserving original accounts and mint'):
                    self.run.restore_controls()
                restore.assert_not_called()
                for node in self.run.nodes.values():
                    node.start.assert_not_called()

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
