"""Counter-based window attribution over the existing complete cadence fixture."""
import copy
import unittest

from service_carrier import TRANSPORTS
from test_analyze import complete_report
from test_wire_capture import capture, event, udp
from wire_capture import read_pcap, read_traces
from wire_intervals import analyze_wire


def fixture():
    rows = complete_report()
    rows[0]['payment_service_carrier'] = True
    final = {}
    for row in rows:
        if 'data' not in row:
            continue
        for boundary in ('before_guard', 'before', 'after', 'after_guard'):
            for node in row['data'][boundary]:
                pid = node['measurements']['process_id'] + row['trial'] * 1000
                node['measurements']['process_id'] = pid
                service = next(s for s in node['control_traffic'] if s['service_port'] == 44743)
                count = service['counters']['stream_bytes_sent'] // 100
                count += row['data']['workload'] == 'high_rate' or (
                    row['data']['workload'] == 'steady' and boundary != 'before_guard')
                service['service_carrier'] = {'service_port': 44743, 'ambiguous_port_datagrams': 0,
                    'discarded_outputs': 0, 'transports': [dict(transport=t,
                        submitted_packets=count if t == 'udp' else 0,
                        fips_payload_bytes=count * 100 if t == 'udp' else 0,
                        ethernet_framing_bytes=0) for t in sorted(TRANSPORTS)]}
                final[pid] = count
    frames, traces = [], []
    for pid, count in final.items():
        for number in range(1, count + 2):
            payload = f'{pid}-{number}'.encode().ljust(100, b'x')
            frames.append(udp(payload))
            traces.append(event(payload, number).replace('process_id=123 ', f'process_id={pid} '))
    payload = b'application service ciphertext'.ljust(100, b'x')
    frames.append(udp(payload))
    traces.append(event(payload, 1, counter_id=2).replace('process_id=123 ', 'process_id=100 ')
                  .replace('service_port=44743 ', 'service_port=44740 '))
    return rows, frames, traces


class WireIntervalTests(unittest.TestCase):
    def test_all_windows_keep_setup_and_shutdown_outside_measured_cost(self):
        rows, frames, traces = fixture()
        original = copy.deepcopy(rows)
        result = analyze_wire(rows, read_pcap(capture(frames)), read_traces(traces))
        self.assertEqual(len(result['windows']), 32)
        for window in result['windows']:
            packets = 0 if window['workload'] == 'idle' else 5
            self.assertEqual(window['wire'].get('packets', 0), packets)
            self.assertEqual(window['wire'].get('captured_link_bytes', 0), packets * 142)
        self.assertEqual(result['capture']['unattributed']['packets'], 41)
        self.assertEqual(sum(i.get('packets', 0) for i in result['intervals'] if i['workload'] == 'setup'), 400)
        self.assertEqual(sum(i.get('packets', 0) for i in result['intervals']
                             if i['interval'] == 'before_guard_to_before'), 40)
        self.assertEqual(rows, original)

    def test_missing_measured_trace_cannot_hide_in_shutdown_traffic(self):
        rows, frames, traces = fixture()
        traces = [line for line in traces if not ('process_id=100 ' in line and 'packet_number=11 ' in line)]
        with self.assertRaisesRegex(ValueError, 'ordinal'):
            analyze_wire(rows, read_pcap(capture(frames)), read_traces(traces))

    def test_delivery_failure_still_rejects_wire_results(self):
        rows, frames, traces = fixture()
        probe = next(r['data']['probes'][0]['receiver'] for r in rows if r.get('data', {}).get('workload') == 'steady')
        probe['missing_packets'] = 1
        with self.assertRaises(ValueError):
            analyze_wire(rows, read_pcap(capture(frames)), read_traces(traces))
