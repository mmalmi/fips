import hashlib
import io
import struct
import unittest

from wire_capture import match_packets, read_pcap, read_traces
from service_carrier import TRANSPORTS


def udp(payload):
    body = b'\0\1\0\2' + struct.pack('!H', 8 + len(payload)) + b'\0\0' + payload
    ip = b'\x45\0' + struct.pack('!H', 20 + len(body)) + b'\0\0\0\0\x40\x11\0\0' + b'\x7f\0\0\1' * 2
    return b'\0' * 12 + b'\x08\0' + ip + body


def capture(frames, *, original=None):
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for frame in frames:
        data += struct.pack('<IIII', 1, 2, len(frame), original or len(frame)) + frame
    return io.BytesIO(data)


def event(payload, number, transport='udp', counter_id=1):
    return ('TRACE fips_core::service_wire: FIPS service packet submitted '
            f'process_id=123 counter_id={counter_id} service_port=44743 packet_number={number} transport="{transport}" '
            f'payload_bytes={len(payload)} fingerprint={hashlib.sha256(payload).hexdigest()}\n')


def counters(payloads, transport='udp'):
    values = {name: dict(transport=name, submitted_packets=0, fips_payload_bytes=0, ethernet_framing_bytes=0)
              for name in TRANSPORTS}
    values[transport].update(submitted_packets=len(payloads), fips_payload_bytes=sum(map(len, payloads)),
                             ethernet_framing_bytes=3 * len(payloads) if transport == 'ethernet' else 0)
    return [{'process_id': 123, 'service_port': 44743, 'ambiguous_port_datagrams': 0,
             'discarded_outputs': 0, 'transports': list(values.values())}]


class WireCaptureTests(unittest.TestCase):
    def test_udp_retries_and_unattributed_traffic_are_retained(self):
        payload = b'opaque cipher bytes'
        frames = [udp(payload), udp(payload), udp(b'shared traffic')]
        result = match_packets(read_pcap(capture(frames)), read_traces([event(payload, 1), event(payload, 2)]),
                               counters([payload, payload]))
        self.assertEqual(result['attributed']['packets'], 2)
        self.assertEqual(result['attributed']['fips_payload_bytes'], 2 * len(payload))
        self.assertEqual(result['attributed']['ip_bytes'], 2 * (28 + len(payload)))
        self.assertEqual(result['attributed']['captured_link_bytes'], 2 * len(frames[0]))
        self.assertEqual(result['unattributed'], {'packets': 1, 'captured_link_bytes': len(frames[2])})
        self.assertIsNone(result['physical_wire_bytes'])

    def test_ethernet_prefix_and_padding_are_captured_without_hashing_padding(self):
        payload = b'cipher'
        frame = b'\0' * 12 + b'\x88\xb5' + b'\0' + len(payload).to_bytes(2, 'little') + payload + b'\0' * 40
        result = match_packets(read_pcap(capture([frame])), read_traces([event(payload, 1, 'ethernet')]),
                               counters([payload], 'ethernet'))
        self.assertEqual(result['attributed']['captured_link_bytes'], len(frame))
        self.assertEqual(result['attributed']['fips_payload_bytes'], len(payload))

    def test_partial_capture_and_missing_or_duplicate_submissions_fail(self):
        payload = b'cipher'
        with self.assertRaisesRegex(ValueError, 'truncated'):
            list(read_pcap(capture([udp(payload)], original=len(udp(payload)) + 1)))
        with self.assertRaisesRegex(ValueError, 'independent capture'):
            match_packets(read_pcap(capture([udp(payload)])), read_traces([event(payload, 1), event(payload, 2)]),
                          counters([payload, payload]))
        for events in ([event(payload, 1), event(payload, 1)], [event(payload, 2)]):
            with self.assertRaisesRegex(ValueError, 'ordinal'):
                list(read_traces(events))

    def test_invalid_record_lengths_and_trace_fields_are_rejected(self):
        malformed = bytearray(udp(b'cipher'))
        malformed[38:40] = b'\0\0'
        with self.assertRaisesRegex(ValueError, 'UDP length'):
            list(read_pcap(capture([malformed])))
        with self.assertRaisesRegex(ValueError, 'changed'):
            list(read_traces([event(b'cipher', 1).replace('process_id=123 ', '')]))
        with self.assertRaisesRegex(ValueError, 'changed'):
            list(read_traces([event(b'cipher', 1) + 'process_id=123']))

    def test_multiple_local_instances_keep_independent_ordinals(self):
        payload = b'cipher'
        traces = [event(payload, 1).replace('TRACE ', 'TRACE parent{peer=red}: '), event(payload, 1, counter_id=2)]
        result = match_packets(read_pcap(capture([udp(payload)] * 2)), read_traces(traces),
                               counters([payload, payload]))
        self.assertEqual(result['attributed']['packets'], 2)

    def test_unlogged_submissions_fail_final_counter_reconciliation(self):
        payload = b'cipher'
        with self.assertRaisesRegex(ValueError, 'final carrier counters'):
            match_packets(read_pcap(capture([udp(payload)])), read_traces([]), counters([payload]))
        with self.assertRaisesRegex(ValueError, 'final carrier counters'):
            match_packets(read_pcap(capture([udp(payload)])), read_traces([event(payload, 1)]), counters([]))


if __name__ == '__main__':
    unittest.main()
