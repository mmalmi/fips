"""A failed observer must not discard or replay completed endpoint requests."""
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.stream_probe import duplex
from sim.paid_phone_transit import PhoneTransitRun


class StreamProbeTests(unittest.TestCase):
    def test_rate_comparison_rejects_mixed_faults_before_preparing_devices(self):
        for flag in ('screen_off', 'forced_idle', 'phone_outage', 'phone_renewal', 'impaired_transit'):
            args = SimpleNamespace(transit=True, open_mesh=False, sustained_transit=False,
                                   compare_transit_rates=True, **{flag: True})
            with self.subTest(flag=flag), patch('sim.paid_phone_transit.PaidPhoneRun.__init__') as base:
                with self.assertRaises(RuntimeError):
                    PhoneTransitRun(args)
                base.assert_not_called()

    def test_sustained_transit_requires_five_minutes_only_in_the_paid_background_window(self):
        cases = [(True, False, 'background', False, 300, 9 * 1024**2, 300, 32),
                 (True, False, 'background', False, 299, 9 * 1024**2, 300, 32),
                 (True, False, 'foreground', False, 16, 512 * 1024, 30, 32),
                 (False, False, 'background', False, 16, 512 * 1024, 30, 32),
                 (True, False, 'background', True, 4, 1024, 4, 32),
                 (False, True, 'background', False, 300, 4 * 1024**2, 300, 32),
                 (False, True, 'background-high-rate', False, 300, 4 * 1024**2, 300, 256)]
        for sustained, compare, mode, unpaid, elapsed, count, duration, rate in cases:
            with self.subTest(sustained=sustained, compare=compare, mode=mode, unpaid=unpaid, elapsed=elapsed):
                run = PhoneTransitRun.__new__(PhoneTransitRun)
                run.args = SimpleNamespace(sustained_transit=sustained, compare_transit_rates=compare)
                run.nodes = dict.fromkeys(('n01', 'n02', 'n03'))
                run.ctl = Mock(return_value={'measurements': 'retained'})
                run.phone = Mock()
                run.phone.shell.return_value = b'USB-powered test'
                run.evidence = {'windows': []}
                run.save, run.phase = Mock(), Mock()
                def dispatch(_run, row, **_kwargs):
                    row.update(results={'n01': {'elapsed_us': elapsed * 1_000_000}},
                               shapes={'n01': {}})
                before = dict(process={'pid': 1, 'start_ticks': 1}, cpu_ticks=0, ticks_per_second=100)
                after = dict(before, cpu_ticks=10)
                with patch('sim.paid_phone_transit.duplex', side_effect=dispatch) as send, \
                        patch('sim.paid_phone_transit.resources', side_effect=[before, after]), \
                        patch('sim.paid_phone_transit.control', return_value={}), \
                        patch('sim.paid_phone_transit.validate_stream'):
                    if sustained and mode == 'background' and not unpaid and elapsed < 300:
                        with self.assertRaisesRegex(RuntimeError, 'five-minute'):
                            run.stream(mode, unpaid=unpaid)
                    else:
                        run.stream(mode, unpaid=unpaid)
                        self.assertTrue(run.evidence['windows'][0]['passed'])
                    self.assertEqual(send.call_args.kwargs['count'], count)
                    self.assertEqual(send.call_args.kwargs['duration'], duration)
                    self.assertEqual(send.call_args.kwargs['rate'], rate * 1024)
                    if compare:
                        row = run.evidence['windows'][0]
                        self.assertEqual(set(row['routers_before']), set(run.nodes))
                        self.assertEqual(row['routers_after'], row['routers_before'])

    def test_unpaid_deadline_requires_fresh_finished_zero_delivery_evidence(self):
        for received in (0, 1):
            with self.subTest(received=received), tempfile.TemporaryDirectory() as root:
                run = Mock(root=Path(root), nodes={name: Mock(npub=name) for name in ('n01', 'n03')})
                reports = {}
                def control(name, kind, **fields):
                    if kind == 'stream_probe':
                        reports[name] = dict(shape=fields['probe'], ready=True, finished=True,
                            completed_us=None, received_bytes=received, acknowledged_bytes=0,
                            received_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                            stopped_reason='stream probe deadline reached before exact delivery and ACK')
                        raise RuntimeError('CLI returned nonzero')
                    self.assertEqual(kind, 'status')
                    return {'stream_probe': reports[name]}
                run.ctl.side_effect = control
                record = {}
                if received:
                    with self.assertRaises(RuntimeError):
                        duplex(run, record, label='denied', count=1024, duration=4,
                               rate=1024, observe=lambda: {}, expect_denial=True)
                else:
                    duplex(run, record, label='denied', count=1024, duration=4,
                           rate=1024, observe=lambda: {}, expect_denial=True)
                    self.assertEqual(record['results'], reports)
                self.assertEqual(run.ctl.call_count, 4)
                for name in run.nodes:
                    saved = json.loads((run.root / 'stream-denied' / (name+'-result.json')).read_text())
                    self.assertEqual(saved['probe'], reports[name])

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
