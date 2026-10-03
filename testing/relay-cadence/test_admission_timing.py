"""Reject partial timing evidence and distinguish quiet observations from zero cost."""

import tempfile
import unittest
from pathlib import Path

from admission_timing import distribution, read_log

CLOCK = '   0.001000000s TRACE fips_admission: Process clock anchor event="clock" epoch_unix_us=1000000 uncertainty_us=4\n'
PUBLISH = '   0.002000000s TRACE fips_admission: Forwarding allowance publication event="published" persist_us=150 increased=true\n'
ADMIT = '   0.003000000s TRACE fips_admission: Queued forwarding admission event="readmitted" wait_us=2000 bytes=1000\n'


class AdmissionTimingTests(unittest.TestCase):
    def parse(self, body, omitted=0, original=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'node.log'
            body = body.encode()
            length = len(body) if original is None else original
            path.write_bytes(f'# original_bytes={length} omitted_prefix_bytes={omitted}\n'.encode() + body)
            return read_log(path)

    def test_monotonic_events_retain_durations_despite_writer_reordering(self):
        anchor, events = self.parse(CLOCK + ADMIT + PUBLISH)
        self.assertEqual(anchor['uncertainty_us'], 4)
        self.assertEqual([e['event'] for e in events], ['clock', 'published', 'readmitted'])
        self.assertEqual(events[1]['persist_us'], 150)
        self.assertIs(events[1]['increased'], True)
        self.assertEqual(events[2]['wait_us'], 2000)

    def test_partial_and_malformed_traces_are_rejected(self):
        cases = [
            (CLOCK + ADMIT, {'omitted': 1}),
            (CLOCK + ADMIT, {'original': 1}),
            (ADMIT, {}),
            (CLOCK + CLOCK + ADMIT, {}),
            (CLOCK + ADMIT.replace('0.003000000s', '2026-10-03T12:00:00Z'), {}),
            (CLOCK + ADMIT.replace('wait_us=2000', 'wait_us=-1'), {}),
            (CLOCK + PUBLISH.replace('increased=true', 'increased=1'), {}),
            (CLOCK + ADMIT.replace('bytes=1000', 'bytes=1000 bytes=1000'), {}),
        ]
        for body, arguments in cases:
            with self.subTest(body=body, arguments=arguments), self.assertRaises(ValueError):
                self.parse(body, **arguments)

    def test_empty_observations_are_unavailable(self):
        self.assertEqual(distribution([])['mean_us'], None)
        self.assertEqual(distribution([2, 1, 3]),
                         {'samples': 3, 'mean_us': 2, 'max_us': 3, 'p50_us': 2, 'p95_us': 3})


if __name__ == '__main__':
    unittest.main()
