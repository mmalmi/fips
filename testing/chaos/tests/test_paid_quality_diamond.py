"""Loss attribution excludes peer replacement and always restores before collection."""

import copy
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.paid_quality_diamond import QualityDiamondRun, impaired_carrier
from sim.wifi_frame_loss import FrameLoss
from test_paid_diamond_lifecycle import runner
from test_wifi_diamond import topology
from test_wifi_diamond_selection import DESTINATION, PROVIDER, observation


class QualityTests(unittest.TestCase):
    def test_inflight_feedback_is_saved_without_replaying_an_uncertain_send(self):
        for lost_reply in (False, True):
            sampled = Event()
            run = object.__new__(QualityDiamondRun)
            run.sampling_loss = True
            run.nodes = {'n01': SimpleNamespace(node_addr=PROVIDER),
                         'n03': SimpleNamespace(node_addr=DESTINATION)}
            run.evidence = {'quality_switch': {'samples': []}}
            run.fault = Mock()
            run.fault.observe.return_value = {'enabled': True}
            run.save = sampled.set
            value = observation()
            value['quality']['quality']['loss_rate'] = 0.5
            def send(*_args):
                self.assertTrue(sampled.wait(2))
                if lost_reply:
                    raise RuntimeError('send reply lost')
                return {'finite': 'sent'}
            with patch('sim.paid_diamond.PaidDiamondRun.send_batch', side_effect=send) as sender, \
                    patch('sim.paid_diamond.PaidDiamondRun.observe', return_value=value):
                if lost_reply:
                    with self.assertRaisesRegex(RuntimeError, 'send reply lost'):
                        run.send_batch({}, 4)
                else:
                    self.assertEqual(run.send_batch({}, 4), {'finite': 'sent'})
                sender.assert_called_once_with({}, 4)
            self.assertTrue(run.evidence['quality_switch']['samples'][0]['impaired_carrier'])

    def test_loss_requires_the_same_full_carrier_and_fresh_native_feedback(self):
        value = observation()
        value['quality']['quality']['loss_rate'] = 0.5
        self.assertTrue(impaired_carrier(value, DESTINATION, PROVIDER))
        edits = (
            lambda r: r['after']['purchases'][0]['contract'].update(id='replacement'),
            lambda r: r['quality']['quality'].update(next_hop=[2] * 16),
            lambda r: r['quality']['quality'].update(has_recent_delivery_feedback=False),
            lambda r: r['quality']['quality'].update(delivery_feedback_timed_out=True),
            lambda r: r['quality']['quality'].update(loss_rate=0.25),
            lambda r: r['quality']['quality'].update(loss_rate=float('nan')),
        )
        for edit in edits:
            changed = copy.deepcopy(value)
            edit(changed)
            self.assertFalse(impaired_carrier(changed, DESTINATION, PROVIDER))

    def test_native_connection_or_epoch_changes_cannot_pass_as_quality_selection(self):
        run = object.__new__(QualityDiamondRun)
        states, _, _ = topology()
        run.topology, run.peer_anchor = Mock(return_value=states), None
        peers = {name: [{'npub': p['npub'], 'transport_type': p['transport'],
                         'connectivity': 'connected', 'link_id': i + 1, 'authenticated_at_ms': 10}
                        for i, p in enumerate(state['peers'])] for name, state in states.items()}
        run.accounts = SimpleNamespace(nodes={name: SimpleNamespace(native=Mock(return_value={
            'status': 'ok', 'data': {'peers': rows}})) for name, rows in peers.items()})
        run.peer_anchor = run.peer_snapshot()
        for key, value in (('link_id', 100), ('authenticated_at_ms', 11),
                           ('connectivity', 'disconnected'), ('transport_type', 'udp')):
            peer = peers['n03'][0]
            original, peer[key] = peer[key], value
            with self.subTest(field=key), self.assertRaises(RuntimeError):
                run.peer_snapshot()
            peer[key] = original
        self.assertEqual(run.peer_snapshot(), run.peer_anchor)

    def test_success_and_uncertain_fault_restore_before_recovery_or_collection(self):
        for failure in (None, 'enable', 'drive', 'feedback'):
            with self.subTest(failure=failure), patch('sim.paid_diamond.signal.alarm'):
                run = runner()
                run.__class__ = QualityDiamondRun
                run.peer_snapshot = Mock(return_value={'original': 'epochs'})
                run.evidence['quality_switch'] = {'samples': [{'impaired_carrier': failure != 'feedback'}]}
                run.nodes['n01'].mac = '02:00:00:00:00:01'
                run.nodes['n03'].install_filter = Mock()
                events = []
                run.collect = Mock(side_effect=lambda: events.append('collect'))
                fault = Mock()
                fault.enable.return_value = {'enabled': True, 'jump_handle': 9,
                                             'dropped_packets': 0, 'dropped_bytes': 0}
                fault.observe.return_value = {**fault.enable.return_value,
                                              'dropped_packets': 10, 'dropped_bytes': 1000}
                fault.clear.side_effect = lambda: events.append('clear')
                if failure == 'enable':
                    fault.enable.side_effect = RuntimeError('installation reply lost')
                def drive(provider, baseline, phase):
                    events.append(phase)
                    if phase == 'loss_failover' and failure == 'drive':
                        raise RuntimeError('no working alternative')
                run.drive_route.side_effect = drive
                with patch('sim.paid_quality_diamond.FrameLoss', return_value=fault) as constructor:
                    if failure:
                        with self.assertRaises(RuntimeError):
                            run.exercise()
                    else:
                        run.exercise()
                        self.assertTrue(run.evidence['paid_switching_accepted'])
                        self.assertLess(events.index('clear'), events.index('recovered_cheaper_provider'))
                    constructor.assert_called_once_with(run.nodes['n03'], run.nodes['n01'].mac, every=2)
                self.assertLess(events.index('clear'), events.index('collect'))
                fault.enable.assert_called_once_with()
                fault.clear.assert_called_once_with()
                self.assertEqual(sum(c.args[1] == 'watch' for c in run.ctl.call_args_list), 1)
                for node in run.nodes.values():
                    node.mesh_down.assert_not_called()
                    node.mesh_up.assert_not_called()

    def test_frame_loss_period_is_bounded_and_used_by_the_owned_rule(self):
        node = SimpleNamespace(table='owned', table_owner='owner')
        for every in (2, 20):
            fault = FrameLoss(node, '02:00:00:00:00:01', every=every)
            fault.observe = Mock(side_effect=[{'enabled': False}, {'enabled': True}])
            fault.owned = Mock()
            fault.enable()
            self.assertIn(f'numgen inc mod {every} 0 counter drop', fault.owned.call_args.args[1].decode())
        for invalid in (True, 1, 1001, 2.5, '2'):
            with self.subTest(period=invalid), self.assertRaises(ValueError):
                FrameLoss(node, '02:00:00:00:00:01', every=invalid)


if __name__ == '__main__':
    unittest.main()
