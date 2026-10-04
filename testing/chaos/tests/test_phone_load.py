"""Reject incomplete diagnostics and false healthy/payment acceptance."""

import copy
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.phone_diagnostics import decode_record
from sim.paid_phone_load import BYTES, PACKETS, SECONDS, validate_window


def fixture():
    shape = {'stream_id': 'ab' * 16, 'packet_count': PACKETS, 'payload_bytes': BYTES}
    sender = {'stream_id': shape['stream_id'], 'requested_packets': PACKETS,
              'submitted_packets': PACKETS, 'submitted_bytes': PACKETS * BYTES,
              'stopped_reason': None, 'elapsed_us': SECONDS * 1_000_000}
    def receiver(source, count):
        return {'stream_id': shape['stream_id'], 'source': source, 'expected_packets': PACKETS,
                'payload_bytes': BYTES, 'unique_packets': count, 'unique_bytes': count * BYTES,
                'missing_packets': PACKETS - count, 'duplicate_packets': 0,
                'invalid_packets': 0, 'latency': None}
    def sample(at, paid):
        return {'ended_at': at, 'receivers': {name: receiver(name, paid * 100)
                 for name in ('phone', 'n03')},
                'financial': {name: {'authorized': paid, 'signed': {name: paid},
                                    'credited': {name: paid * 1000}}
                              for name in ('phone', 'n01', 'n02', 'n03')}}
    state = {'process': {'pid': 1, 'start_ticks': 100}, 'cpu_ticks': 1, 'ticks_per_second': 100}
    return {'impaired': False, 'before': state, 'after': copy.deepcopy(state),
            'streams': {name: {'shape': copy.deepcopy(shape), 'sender': copy.deepcopy(sender),
                       'receiver': receiver(name, PACKETS), 'started_at': 0}
                        for name in ('phone', 'n03')},
            'samples': [sample(10, 1), sample(80, 4)]}


class PhoneLoadTests(unittest.TestCase):
    def test_framed_reply_requires_one_complete_record(self):
        payload = json.dumps({'ok': {'probe': 'observed'}}).encode()
        wire = struct.pack('!I', len(payload)) + payload
        self.assertEqual(decode_record(wire), {'probe': 'observed'})
        for invalid in (wire[:-1], wire + b'\0', b'', struct.pack('!I', 2) + b'{}'):
            with self.subTest(size=len(invalid)), self.assertRaises(RuntimeError):
                decode_record(invalid)

    def test_window_requires_delivery_and_live_provider_payment(self):
        row = fixture()
        identities = {'phone': 'phone', 'n03': 'n03'}
        validate_window(row, identities)
        bad = copy.deepcopy(row)
        bad['streams']['phone']['receiver'].update(
            unique_packets=PACKETS - 1, unique_bytes=(PACKETS - 1) * BYTES, missing_packets=1)
        with self.assertRaises(RuntimeError):
            validate_window(bad, identities)
        for mutation in ('credit', 'late'):
            bad = copy.deepcopy(row)
            if mutation == 'credit':
                bad['samples'][-1]['financial']['n02']['credited']['n02'] = 1000
            else:
                bad['samples'][-1]['ended_at'] = SECONDS + 1
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                validate_window(bad, identities)
        bad = copy.deepcopy(row)
        bad['impaired'] = True
        with self.assertRaises(RuntimeError):
            validate_window(bad, identities)


if __name__ == '__main__':
    unittest.main()
