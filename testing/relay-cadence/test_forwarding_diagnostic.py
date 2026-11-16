"""Native drop totals and endpoint probe loss have different packet scopes."""
from copy import deepcopy
import unittest

from forwarding_diagnostic import classify
from native_counters import BACKGROUND, DEFERRED, GROUPS, WAIT_DROPS
from test_analyze import complete_report, probe
from test_service_carrier import carrier


def report():
    source = complete_report()
    rows = [{'diagnostic': 'native-forwarding-drops', 'comparison_complete': False,
             'max_delay_ms': 500, 'repeats': 2}]
    for trial in (0, 1):
        rows.append({'trial': trial, 'max_delay_ms': 500, 'warmup': [probe(1, trial)]})
        for row in source[1 + trial * 5:6 + trial * 5]:
            row['max_delay_ms'] = 500
            if 'data' in row:
                data = row['data']
                for boundary in ('before_guard', 'before', 'after', 'after_guard'):
                    for node in data[boundary]:
                        node['measurements']['admission_denials'] = {
                            'credit_limit': 0, 'durable_window': 0}
                        for state in node['payment_progress'].values():
                            state.update(pending=None, last_failure_stage=None)
                        for peer in node['peers']:
                            peer.update(received_bytes=peer['sent_bytes'],
                                        sent_packets=peer['sent_bytes'] // 1000,
                                        received_packets=peer['sent_bytes'] // 1000)
                        for service in node['control_traffic']:
                            tick = service['counters']['requests_started']
                            value = carrier(tick)
                            value['discarded_outputs'] = 0
                            service['service_carrier'] = (
                                value if service['service_port'] == 44743 else None)
                data['forwarding'] = {
                    boundary: [{'process_id': node['measurements']['process_id'],
                                'counters': dict.fromkeys(
                                    GROUPS['forwarding'] | BACKGROUND | DEFERRED | WAIT_DROPS, 0)}
                               for node in data[boundary]]
                    for boundary in ('before', 'after')}
            rows.append(row)
    return rows


def lose(data, count):
    received = data['probes'][0]['receiver']
    delivered = received['expected_packets'] - count
    received.update(unique_packets=delivered, unique_bytes=delivered * 1000,
                    missing_packets=count)
    received['latency'].update(samples=delivered, sum_us=delivered * 80,
                              bucket_counts=[delivered] + [0] * 13)


def drop(data, packets, byte_count):
    counters = data['forwarding']['after'][1]['counters']
    for kind in ('denied', 'wait_full'):
        counters[f'drop_policy_{kind}_packets'] += packets
        counters[f'drop_policy_{kind}_bytes'] += byte_count


class ForwardingDiagnosticTests(unittest.TestCase):
    def test_clean_diagnostic_is_not_a_complete_cadence_matrix(self):
        raw = report()
        before = deepcopy(raw)
        result = classify(raw)
        self.assertTrue(result['clean_link_accepted'])
        self.assertFalse(result['comparison_complete'])
        self.assertEqual(raw, before)

    def test_probe_loss_does_not_identify_which_native_packets_were_dropped(self):
        for packets, byte_count in ((0, 0), (3, 3219), (4, 3290)):
            with self.subTest(native_packets=packets):
                raw = report()
                lose(raw[5]['data'], 3)
                drop(raw[5]['data'], packets, byte_count)
                before = deepcopy(raw)
                result = classify(raw)
                high = result['workloads'][3]
                self.assertTrue(result['sequence_may_continue'])
                self.assertFalse(result['clean_link_accepted'])
                self.assertEqual(high['missing_packets'], 3)
                self.assertEqual(high['queue_full_packets'], packets)
                self.assertEqual(high['queue_full_bytes'], byte_count)
                self.assertIsNone(high['probe_loss_from_queue_full'])
                self.assertEqual(raw, before)

    def test_delivered_probes_do_not_hide_dropped_control_traffic(self):
        raw = report()
        drop(raw[5]['data'], 1, 71)
        result = classify(raw)
        self.assertFalse(result['clean_link_accepted'])
        high = result['workloads'][3]
        self.assertEqual(high['missing_packets'], 0)
        self.assertEqual(high['classification'], 'native-queue-congestion')

    def test_usage_deficits_remain_visible_without_excusing_signed_liability(self):
        raw = report()
        data = raw[5]['data']
        lose(data, 3)
        for boundary in ('after', 'after_guard'):
            state = next(iter(data[boundary][0]['payment_progress'].values()))
            state['evidence_msat'] = state['acknowledged_msat'] + 1
        before = deepcopy(raw)
        result = classify(raw)
        deficits = result['workloads'][3]['evidence_deficits']
        self.assertEqual([d['boundary'] for d in deficits], ['after', 'after_guard'])
        self.assertTrue(all(d['state']['evidence_msat'] ==
                            d['state']['acknowledged_msat'] + 1 for d in deficits))
        self.assertFalse(result['clean_link_accepted'])
        self.assertEqual(raw, before)
        next(iter(data['after'][0]['payment_progress'].values()))['authorized_sat'] += 1
        with self.assertRaisesRegex(ValueError, 'unacknowledged signed liability'):
            classify(raw)

    def test_other_failures_still_reject_the_diagnostic(self):
        cases = {
            'duplicate': lambda d: d['probes'][0]['receiver'].update(duplicate_packets=1),
            'partial send': lambda d: d['probes'][0]['sender'].update(submitted_packets=31999),
            'unfinished payment': lambda d: next(iter(d['after'][0]['payment_progress'].values()))
                .update(in_flight=True),
            'unacknowledged liability': lambda d: next(iter(d['after'][0]['payment_progress'].values()))
                .update(authorized_sat=1000000),
            'controller error': lambda d: d['after'][0].update(last_error='failed'),
            'native send error': lambda d: d['forwarding']['after'][0]['counters']
                .update(drop_send_error_packets=1),
            'counter reset': lambda d: d['forwarding']['before'][0]['counters']
                .update(forwarded_packets=1),
            'inconsistent native cause': lambda d: d['forwarding']['after'][0]['counters']
                .update(drop_policy_wait_full_packets=1),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                raw = report()
                lose(raw[5]['data'], 3)
                drop(raw[5]['data'], 3, 3219)
                mutate(raw[5]['data'])
                with self.assertRaises(ValueError):
                    classify(raw)
        for kind in ('low-rate loss', 'low-rate drop', 'settlement'):
            raw = report()
            if kind == 'low-rate loss':
                lose(raw[4]['data'], 1)
            elif kind == 'low-rate drop':
                drop(raw[4]['data'], 1, 71)
            else:
                raw[6]['collected_sat'] -= 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                classify(raw)


if __name__ == '__main__':
    unittest.main()
