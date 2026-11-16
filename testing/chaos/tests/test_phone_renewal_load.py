"""Successor creation alone cannot qualify sustained paid transit."""

import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.phone_renewal_load import MIN_CHANNELS, PhoneRenewalLoadRun, validate_successors


def fixture(counts=MIN_CHANNELS):
    row = {'before_processes': {'phone': 1}, 'after_processes': {'phone': 1},
           'samples': [], 'original': {}}
    before, after, purchases = {}, {}, {}
    for name, count in counts.items():
        purchases[name] = []
        before[name] = {'controller': {'local': name, 'policy': {'max_wallet_spend_sat': 64},
                                      'funding': {}, 'buyer_settlements': {}},
                        'buyer': {'local': name, 'total_budget_sat': 64}}
        after[name] = copy.deepcopy(before[name])
        for i in range(count):
            channel = {'id': name + '-' + str(i), 'capacity_sat': 32}
            purchase = {'channel': channel, 'provider': 'provider-' + name,
                        'contract': {'destination': 'destination', 'next_hop': 'hop',
                                     'price': 1, 'max_units': 128, 'billing': 'forwarding_data',
                                     'expires_unix': 300 * (i + 1)}}
            purchases[name].append(purchase)
            after[name]['controller']['funding'][channel['id']] = {'funded': {'terms': channel}}
            if i < count - 1:
                report = {'channel_id': channel['id'], 'value_after_stage1_sat': 32,
                          'paid_sat': 2, 'refunded_sat': 30, 'receiver_fee_reserve_sat': 0, 'fee_sat': 0}
                after[name]['controller']['buyer_settlements'][channel['id']] = {
                    'refunded': True, 'channel': channel, 'report': report, 'wallet_refund_sat': 30}
        first = purchases[name][0]
        row['original'][name] = first
        before[name]['controller']['funding'][first['channel']['id']] = {'funded': {'terms': first['channel']}}
    for stage in range(max(counts.values())):
        for tick in range(2):
            sample = {'stream_id': 'window', 'states': {}}
            for name, count in counts.items():
                purchase = purchases[name][min(stage, count - 1)]
                sample['states'][name] = {
                    'purchases': [purchase], 'remaining_budget_sat': 64 - stage - tick,
                    'funding_budget': {'pending_reserved_sat': 0, 'locked_sat': 32,
                                      'wallet_debited_sat': 32, 'wallet_refunded_sat': 0, 'exposure_sat': 32},
                    'payment_progress': {purchase['channel']['id']: {'acknowledged_msat': 1000 + tick}},
                    'stream_probe': {'finished': False, 'shape': {'stream_id': 'window'},
                                     'received_bytes': stage * 100 + tick}}
            row['samples'].append(sample)
    return row, before, after


class PhoneRenewalLoadTests(unittest.TestCase):
    def test_successors_need_live_bidirectional_delivery_payment_and_retained_authority(self):
        row, before, after = fixture()
        self.assertEqual(validate_successors(row, before, after), MIN_CHANNELS)
        counts = dict(MIN_CHANNELS, n02=2)
        self.assertEqual(validate_successors(*fixture(counts)), counts)
        for counts in (dict(MIN_CHANNELS, phone=2), dict(MIN_CHANNELS, n02=5)):
            with self.assertRaises(RuntimeError):
                validate_successors(*fixture(counts))
        mutations = {
            'no payment': lambda r, b, a: [s['states']['phone']['payment_progress'].update(
                {p['channel']['id']: {'acknowledged_msat': 0} for p in s['states']['phone']['purchases']})
                for s in r['samples']],
            'one way only': lambda r, b, a: [s['states']['n03']['stream_probe'].update(received_bytes=0)
                                          for s in r['samples']],
            'stale stream': lambda r, b, a: [s['states']['n01']['stream_probe']['shape'].update(stream_id='stale')
                                           for s in r['samples']],
            'post traffic': lambda r, b, a: [s['states']['n01']['stream_probe'].update(finished=True)
                                           for s in r['samples']],
            'raised budget': lambda r, b, a: a['phone']['buyer'].update(total_budget_sat=128),
            'extra funding': lambda r, b, a: a['phone']['controller']['funding'].update(extra={'funded': None}),
            'unresolved refund': lambda r, b, a: a['phone']['controller']['buyer_settlements']['phone-0'].update(refunded=False),
            'capital overrun': lambda r, b, a: r['samples'][1]['states']['phone']['funding_budget'].update(locked_sat=65),
            'restart': lambda r, b, a: r['after_processes'].update(phone=2),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                values = fixture()
                mutate(*values)
                with self.assertRaises(RuntimeError):
                    validate_successors(*values)

    def test_byte_counters_are_compared_within_the_same_stream(self):
        row, before, after = fixture()
        # A successor can span the end of one stream and the start of another.
        for sample in row['samples'][-2:]:
            sample['stream_id'] = 'second'
            for state in sample['states'].values():
                state['stream_probe']['shape']['stream_id'] = 'second'
                state['stream_probe']['received_bytes'] -= 200
        validate_successors(row, before, after)

    def test_workload_rejects_mixed_faults_before_touching_devices(self):
        for flag in ('screen_off', 'sustained_transit', 'forced_idle', 'phone_outage',
                     'phone_restart', 'impaired_transit', 'compare_transit_rates'):
            with self.subTest(flag=flag), patch('sim.phone_renewal_load.PhoneTransitRun.__init__') as base:
                with self.assertRaises(RuntimeError):
                    PhoneRenewalLoadRun(SimpleNamespace(**{flag: True}))
                base.assert_not_called()

    def test_two_paced_windows_precede_one_pause_and_final_validation(self):
        run = PhoneRenewalLoadRun.__new__(PhoneRenewalLoadRun)
        run.nodes = dict.fromkeys(('n01', 'n02', 'n03'))
        run.phone = Mock()
        row = {'samples': [], 'windows': []}
        run.evidence = {'renewable_transit': row, 'windows': []}
        run.journals = Mock(return_value={})
        run.topology = Mock(return_value={name: {'purchases': [{}]} for name in MIN_CHANNELS})
        run.save, run.phase, run.ctl = Mock(), Mock(), Mock()
        run.once = lambda label, call: call()
        events = []
        run.restore_foreground = lambda: events.append('foreground')
        def window(mode):
            events.append(mode)
            self.assertEqual(run.stream_shape(mode, False), (9 * 1024**2, 300, 32 * 1024, 300))
            self.assertEqual(run.active_stream, mode)
            run.evidence['windows'].append({'results': {n: {'completed_us': 288_000_000} for n in ('n01', 'n03')}})
        run.ctl.side_effect = lambda name, kind: events.append((name, kind))
        with patch('sim.phone_renewal_load.PhoneTransitRun.stream', side_effect=window), \
                patch('sim.phone_renewal_load.processes', return_value={}), \
                patch('sim.phone_renewal_load.control') as phone, \
                patch('sim.phone_renewal_load.validate_successors', return_value=MIN_CHANNELS) as validate:
            run.stream('background')
            self.assertEqual(events[:2], ['background-renewal-1', 'background-renewal-2'])
            self.assertEqual(events[2:], ['foreground', *[(n, 'pause_renewals') for n in run.nodes]])
            phone.assert_called_once_with(run.phone, 'pause_renewals')
            validate.assert_called_once()
            self.assertTrue(row['passed'])
            self.assertEqual(run.settlement_channel_counts, MIN_CHANNELS)
            self.assertIsNone(run.active_stream)


if __name__ == '__main__':
    unittest.main()
