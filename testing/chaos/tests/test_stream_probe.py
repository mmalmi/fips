"""A failed observer must not discard or replay completed endpoint requests."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.stream_probe import duplex


class StreamProbeTests(unittest.TestCase):
    def test_observer_failure_retains_both_completed_requests_without_replay(self):
        with tempfile.TemporaryDirectory() as root:
            release = threading.Event()
            run = Mock(root=Path(root), nodes={name: Mock(npub=name) for name in ('n01', 'n03')})
            def control(name, _kind, **_kwargs):
                self.assertTrue(release.wait(2))
                return {'probe': {'endpoint': name}}
            run.ctl.side_effect = control
            def failed_observation():
                release.set()
                raise RuntimeError('lost observation')
            record = {}
            with self.assertRaisesRegex(RuntimeError, 'lost observation'):
                duplex(run, record, label='failed', count=1024, duration=4,
                       rate=1024, observe=failed_observation)
            self.assertEqual(record['results'], {name: {'endpoint': name} for name in run.nodes})
            self.assertEqual(record['errors'], {})
            self.assertEqual(run.ctl.call_count, 2)
            for name in run.nodes:
                saved = json.loads((run.root / 'stream-failed' / (name+'-result.json')).read_text())
                self.assertEqual(saved['probe'], record['results'][name])
            with self.assertRaises(FileExistsError):
                duplex(run, {}, label='failed', count=1024, duration=4, rate=1024, observe=Mock())
            self.assertEqual(run.ctl.call_count, 2)


if __name__ == '__main__':
    unittest.main()
