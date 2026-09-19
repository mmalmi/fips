"""Carrier attribution retains TCP tails and rejects ambiguous or absent evidence."""
import copy
import unittest

from analyze import analyze_rows, diagnose_rows, markdown
from test_analyze import complete_report, workload
from test_hardware import hardware_report, nodes


TRANSPORTS = ('udp', 'ethernet', 'tcp', 'tor', 'websocket', 'webrtc', 'ble', 'sim', 'other')


def carrier(tick):
    return {'service_port': 44743, 'ambiguous_port_datagrams': 0, 'discarded_outputs': tick,
            'transports': [{'transport': transport,
                            'submitted_packets': tick if transport == 'ethernet' else 0,
                            'fips_payload_bytes': tick * 200 if transport == 'ethernet' else 0,
                            'ethernet_framing_bytes': tick * 3 if transport == 'ethernet' else 0}
                           for transport in TRANSPORTS]}


def report(rows=None):
    rows = hardware_report() if rows is None else rows
    rows[0]['payment_service_carrier'] = True
    for index, row in enumerate(r for r in rows if 'data' in r):
        for offset, boundary in enumerate(('before_guard', 'before', 'after', 'after_guard')):
            for node in row['data'][boundary]:
                for service in node['control_traffic']:
                    service['service_carrier'] = (carrier(100 + index % 4 * 4 + offset)
                                                 if service['service_port'] == 44743 else None)
    return rows


def measurement(data, boundary='after', node=0):
    return next(s['service_carrier'] for s in data[boundary][node]['control_traffic']
                if s['service_port'] == 44743)


class ServiceCarrierTests(unittest.TestCase):
    def reject(self, mutate):
        rows = report()
        mutate(rows)
        for analyzer in (analyze_rows, diagnose_rows):
            with self.assertRaises((ValueError, KeyError, TypeError)):
                analyzer(rows)

    def test_window_and_guard_costs_remain_separate_without_mutating_evidence(self):
        rows = report()
        original = copy.deepcopy(rows)
        metadata, trials, grouped = analyze_rows(rows)
        steady = next(r for r in trials if r['workload'] == 'steady')
        measured = steady['payment_service_carrier']
        self.assertEqual(measured['total']['fips_payload_bytes'], 600)
        self.assertEqual(measured['total']['ethernet_framing_bytes'], 9)
        self.assertEqual(measured['total']['submitted_packets'], 3)
        self.assertEqual(measured['total']['discarded_outputs'], 3)
        self.assertEqual(measured['bytes_per_delivered_byte'], 609 / 3200000)
        self.assertIsNone(measured['physical_wire_bytes'])
        self.assertEqual(set(measured['outside_workload']), {
            'previous_after_guard_to_before_guard', 'before_guard_to_before', 'after_to_after_guard'})
        self.assertEqual(measured['nodes']['n01']['transports']['ethernet']['fips_payload_bytes'], 200)
        for gap in measured['outside_workload'].values():
            self.assertEqual(gap['total']['fips_payload_bytes'], 600)
        idle = next(r for r in trials if r['workload'] == 'idle')
        self.assertEqual(idle['payment_record_bytes'], 0)
        self.assertEqual(idle['payment_service_carrier']['total']['fips_payload_bytes'], 600)
        self.assertIsNone(idle['payment_service_carrier']['bytes_per_delivered_byte'])
        self.assertIn('Local payment-service carrier', markdown(metadata, grouped))
        self.assertEqual(rows, original)

    def test_old_uninstrumented_reports_are_explicitly_unavailable(self):
        rows = hardware_report()
        _, trials, _ = analyze_rows(rows)
        self.assertTrue(all(r['payment_service_carrier'] is None for r in trials))
        for node in nodes(rows):
            for service in node['control_traffic']:
                service['service_carrier'] = None
        _, trials, _ = analyze_rows(rows)
        self.assertTrue(all(r['payment_service_carrier'] is None for r in trials))

    def test_hardware_known_sends_require_both_ethernet_packets_and_bytes(self):
        for field in ('submitted_packets', 'fips_payload_bytes'):
            rows = report()
            for node in nodes(rows):
                service = next(s for s in node['control_traffic'] if s['service_port'] == 44743)
                self.assertGreater(service['counters']['stream_bytes_sent'], 0)
                service['service_carrier']['transports'][1][field] = 0
            original = copy.deepcopy(rows)
            for analyzer in (analyze_rows, diagnose_rows):
                with self.subTest(field=field, analyzer=analyzer.__name__), \
                        self.assertRaisesRegex(ValueError, 'missing Ethernet carrier activity'):
                    analyzer(rows)
            self.assertEqual(rows, original)

    def test_other_nodes_or_carriers_cannot_hide_one_missing_hardware_node(self):
        for host in ('n01', 'n02', 'n03'):
            rows = report()
            for node in nodes(rows):
                if node['host_process']['host'] != host:
                    continue
                service = next(s for s in node['control_traffic'] if s['service_port'] == 44743)
                value = service['service_carrier']
                value['transports'][0].update(submitted_packets=10, fips_payload_bytes=2000)
                value['transports'][1].update(submitted_packets=0, fips_payload_bytes=0,
                                              ethernet_framing_bytes=0)
            for analyzer in (analyze_rows, diagnose_rows):
                with self.subTest(host=host, analyzer=analyzer.__name__), \
                        self.assertRaisesRegex(ValueError, 'missing Ethernet carrier activity'):
                    analyzer(rows)

    def test_hardware_idle_needs_no_new_carrier_submissions(self):
        rows = report()
        idle = workload(rows, 'idle')
        for boundary in ('before_guard', 'before', 'after', 'after_guard'):
            for node in idle[boundary]:
                service = next(s for s in node['control_traffic'] if s['service_port'] == 44743)
                service['service_carrier'] = carrier(100)
        original = copy.deepcopy(rows)
        _, trials, _ = analyze_rows(rows)
        measured = trials[0]['payment_service_carrier']
        self.assertEqual(trials[0]['payment_record_bytes'], 0)
        self.assertEqual(measured['total']['submitted_packets'], 0)
        self.assertEqual(measured['total']['fips_payload_bytes'], 0)
        self.assertIsNone(measured['bytes_per_delivered_byte'])
        self.assertEqual(rows, original)

    def test_node_without_application_sends_needs_no_ethernet_activity(self):
        rows = report()
        for node in nodes(rows):
            if node['host_process']['host'] == 'n02':
                service = next(s for s in node['control_traffic'] if s['service_port'] == 44743)
                service['counters']['stream_bytes_sent'] = 0
                service['service_carrier'] = carrier(0)
        original = copy.deepcopy(rows)
        _, trials, _ = analyze_rows(rows)
        for result in trials:
            measured = result['payment_service_carrier']['nodes']['n02']
            self.assertTrue(all(t['submitted_packets'] == 0 for t in measured['transports'].values()))
        self.assertEqual(rows, original)

    def test_schema_two_keeps_non_ethernet_carrier_accounting(self):
        rows = report(complete_report())
        for node in nodes(rows):
            service = next(s for s in node['control_traffic'] if s['service_port'] == 44743)
            value = service['service_carrier']
            for name in ('submitted_packets', 'fips_payload_bytes'):
                value['transports'][0][name] = value['transports'][1][name]
                value['transports'][1][name] = 0
            value['transports'][1]['ethernet_framing_bytes'] = 0
        original = copy.deepcopy(rows)
        _, trials, _ = analyze_rows(rows)
        self.assertGreater(trials[0]['payment_service_carrier']['total']['fips_payload_bytes'], 0)
        self.assertEqual(rows, original)

    def test_presence_matches_explicit_metadata(self):
        for value in (False, None, 1, 'true'):
            with self.subTest(value=value):
                self.reject(lambda r: r[0].__setitem__('payment_service_carrier', value))
        self.reject(lambda r: next(s for s in workload(r)['after_guard'][2]['control_traffic']
                                  if s['service_port'] == 44743).pop('service_carrier'))
        self.reject(lambda r: next(s for s in workload(r)['after'][0]['control_traffic']
                                  if s['service_port'] == 44743).__setitem__('service_carrier', None))

    def test_ambiguous_identity_shape_and_saturated_counters_are_rejected(self):
        for field, value in (('service_port', 44742), ('service_port', True),
                             ('ambiguous_port_datagrams', 1), ('discarded_outputs', 2**64 - 1),
                             ('discarded_outputs', -1), ('discarded_outputs', True)):
            with self.subTest(field=field, value=value):
                self.reject(lambda r: measurement(workload(r)).__setitem__(field, value))
        self.reject(lambda r: measurement(workload(r))['transports'].pop())
        self.reject(lambda r: measurement(workload(r))['transports'].append(
            measurement(workload(r))['transports'][0].copy()))
        self.reject(lambda r: measurement(workload(r))['transports'][0]
                    .__setitem__('transport', 'invented'))
        for value in (-1, True, None, '1', 2**64 - 1, 2**64):
            with self.subTest(value=value):
                self.reject(lambda r: measurement(workload(r))['transports'][1]
                            .__setitem__('fips_payload_bytes', value))

    def test_resets_are_rejected_at_every_boundary(self):
        for boundary in ('before_guard', 'before', 'after', 'after_guard'):
            with self.subTest(boundary=boundary):
                self.reject(lambda r: measurement(workload(r), boundary)['transports'][1]
                            .__setitem__('fips_payload_bytes', 0))
        self.reject(lambda r: measurement(workload(r, 'bursty'), 'before_guard')
                    .__setitem__('discarded_outputs', 0))

    def test_ethernet_prefix_is_not_added_to_other_transports(self):
        rows = report()
        for node in nodes(rows):
            value = next(s['service_carrier'] for s in node['control_traffic']
                         if s['service_port'] == 44743)
            tick = value['discarded_outputs']
            value['transports'][0].update(submitted_packets=tick * 2, fips_payload_bytes=tick * 700)
        _, trials, _ = analyze_rows(rows)
        measured = trials[0]['payment_service_carrier']
        self.assertEqual(measured['total']['submitted_packets'], 9)
        self.assertEqual(measured['total']['fips_payload_bytes'], 2700)
        self.assertEqual(measured['total']['ethernet_framing_bytes'], 9)
        self.reject(lambda r: measurement(workload(r))['transports'][0]
                    .__setitem__('ethernet_framing_bytes', 3))

    def test_transport_snapshot_order_is_not_identity(self):
        rows = report()
        measurement(workload(rows))['transports'].reverse()
        _, trials, _ = analyze_rows(rows)
        self.assertEqual(trials[2]['payment_service_carrier']['total']['fips_payload_bytes'], 600)

    def test_carrier_diagnostics_cannot_hide_payload_loss(self):
        rows = report()
        receiver = workload(rows, 'high_rate')['probes'][0]['receiver']
        receiver.update(unique_packets=7999, unique_bytes=7999000, missing_packets=1)
        with self.assertRaises(ValueError):
            analyze_rows(rows)
        diagnostic = diagnose_rows(rows)
        self.assertIs(diagnostic['accepted'], False)
