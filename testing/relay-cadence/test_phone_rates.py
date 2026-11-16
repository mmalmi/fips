"""Analyze real counter formats and refuse unmatched or incomplete comparisons."""

import copy
import hashlib
import unittest

from phone_rates import BYTES, NODES, RATES, analyze
from test_analyze import snapshot
from validation import CURRENT_OPERATIONS


def state(name, tick):
    value = snapshot(0, tick, tick)
    value['npub'] = name
    value['measurements']['version'] = 3
    operations = value['measurements']['operations']
    operations['payment_exchange'] = copy.deepcopy(operations['payment_sign'])
    value['measurements']['operations'] = {k: operations[k] for k in CURRENT_OPERATIONS}
    for peer in value['peers']:
        peer.update(received_bytes=tick * 1000, sent_packets=tick, received_packets=tick)
    value['payment_progress'] = {name: next(iter(value['payment_progress'].values()))}
    value['funding_budget'] = {'wallet_debited_sat': 32}
    value['purchases'] = [{'channel': name, 'price': 1}]
    return value


def report():
    digest = hashlib.sha256(bytes(i % 251 for i in range(BYTES))).hexdigest()
    windows = []
    for index, (mode, rate) in enumerate(RATES.items()):
        before = {n: state(n, 10 + index * 3) for n in NODES}
        after = {n: state(n, 12 + index * 3) for n in NODES}
        shapes = {n: {'peer': 'n03' if n == 'n01' else 'n01', 'stream_id': '0' * 32,
                      'bytes': BYTES, 'duration_secs': 300, 'bytes_per_second': rate * 1024}
                  for n in ('n01', 'n03')}
        streams = {n: {'shape': shape, 'ready': True, 'connected': True, 'finished': True,
                       'stopped_reason': None, 'completed_us': BYTES * 1_000_000 // (rate * 1024),
                       'elapsed_us': 300_000_000, 'accepted_bytes': BYTES,
                       'received_bytes': BYTES, 'acknowledged_bytes': BYTES, 'received_sha256': digest}
                   for n, shape in shapes.items()}
        resources = {'process': {'pid': 1, 'start_ticks': 10}, 'memory_kib': {'VmRSS': 100}}
        windows.append({'mode': mode, 'passed': True, 'unpaid': False, 'errors': {},
                        'results': streams, 'shapes': shapes, 'before': resources, 'after': resources,
                        'samples': [{'line_verified': True, 'foreground_service': True, 'wakefulness': 'Awake'}],
                        'payment_before': before.pop('phone'), 'routers_before': before,
                        'payment_after': after.pop('phone'), 'routers_after': after, 'cpu_seconds': 0.1})
    return {'passed': True, 'compare_transit_rates_requested': True, 'impaired_transit_requested': False,
            'test_identities': {n: n for n in NODES if n != 'phone'}, 'phone_npub': 'phone', 'windows': windows}


class PhoneRatesTests(unittest.TestCase):
    def test_equal_payloads_use_actual_completion_and_exclusive_payment_cpu(self):
        result = analyze(report())
        slow, fast = result['comparison'].values()
        self.assertEqual(slow['completion_seconds']['n01'], 128)
        self.assertEqual(fast['completion_seconds']['n01'], 16)
        self.assertEqual(fast['completion_kib_per_second_per_direction']['n01'], 256)
        for row in (slow, fast):
            self.assertEqual(set(row['nodes']), set(NODES))
            for node in row['nodes'].values():
                self.assertAlmostEqual(node['payment_cpu_ms_per_payload_mib'], 0.001)
                self.assertAlmostEqual(node['process_cpu_ms_per_payload_mib'], 0.025)

    def test_loss_changed_budget_terms_epochs_and_interwindow_resets_are_rejected(self):
        baseline = report()
        edits = (
            lambda r: r['windows'].reverse(),
            lambda r: r['windows'][1]['results']['n01'].update(received_bytes=BYTES - 1),
            lambda r: r['windows'][1]['routers_after']['n01']['funding_budget'].update(wallet_debited_sat=64),
            lambda r: r['windows'][1]['routers_after']['n01']['purchases'][0].update(price=2),
            lambda r: r['windows'][1]['routers_after']['n01']['peers'][0].update(link_id=100),
            lambda r: r['windows'][1]['payment_before']['measurements'].update(process_cpu_ns=0),
            lambda r: r['windows'][1]['payment_after']['payment_progress']['phone'].update(acknowledged_msat=0),
        )
        for edit in edits:
            changed = copy.deepcopy(baseline)
            edit(changed)
            with self.assertRaises((RuntimeError, ValueError)):
                analyze(changed)


if __name__ == '__main__':
    unittest.main()
