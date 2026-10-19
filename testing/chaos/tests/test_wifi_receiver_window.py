"""Keep progress timing independent of bounded original-custody observation."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
import json
import subprocess
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_receiver_window import measure, progress
from sim import wifi_receiver_custody as custody


def point(at, value):
    return dict(elapsed_us=at, delivered=value,
                payments=[{'authorized_sat': value}] * 2, credits=[value * 1000] * 2,
                counter_reads=[dict(started_us=at, finished_us=at) for _ in range(5)])


class ReceiverTimingTests(unittest.TestCase):
    def test_missing_timing_cannot_requalify_an_old_result(self):
        samples = [point(500_000, 1), point(1_000_000, 2)]
        samples[0].pop('counter_reads')
        result = progress(point(0, 0), samples, [])
        self.assertFalse(result['within_limit'])
        self.assertFalse(result['timing_resolution_sufficient'])

    def test_mixed_read_intervals_are_not_one_batch_timestamp(self):
        first, second = point(1_500_000, 1), point(1_990_000, 2)
        ends = [250_000, 500_000, 1_500_000, 600_000, 700_000]
        first['counter_reads'] = [dict(started_us=end - 50_000, finished_us=end) for end in ends]
        ends = [1_850_000, 1_900_000, 1_900_000, 1_950_000, 1_990_000]
        second['counter_reads'] = [dict(started_us=1_550_000, finished_us=end) for end in ends]
        result = progress(point(0, 0), [first, second], [])
        self.assertEqual(result['max_observed_gap_us'], ends)
        self.assertTrue(result['within_limit'])
        self.assertTrue(result['timing_resolution_sufficient'])

    def test_real_two_second_stall_fails_and_ambiguous_timing_is_unqualified(self):
        stalled = [point(500_000, 1), point(1_000_000, 1), point(2_600_000, 1), point(2_800_000, 2)]
        result = progress(point(0, 0), stalled, [])
        self.assertFalse(result['within_limit'])
        self.assertEqual(result['timing_verdict'], ['failed'] * 5)
        self.assertTrue(all(gap > 2_000_000 for gap in result['minimum_gap_us']))
        ambiguous = [point(500_000, 1), point(2_000_000, 1), point(2_300_000, 2)]
        result = progress(point(0, 0), ambiguous, [])
        self.assertFalse(result['within_limit'])
        self.assertFalse(result['timing_resolution_sufficient'])
        self.assertEqual(result['timing_verdict'], ['unqualified'] * 5)

    def test_only_checked_pending_custody_brackets_prove_overlap(self):
        samples = [point(500_000, 1), point(1_000_000, 2), point(1_500_000, 3)]
        custody = [dict(started_us=0, elapsed_us=100_000, cleanup_pending=True),
                   dict(started_us=1_200_000, elapsed_us=1_300_000, cleanup_pending=True),
                   dict(started_us=1_600_000, elapsed_us=1_700_000, cleanup_pending=False)]
        self.assertTrue(progress(point(0, 0), samples, custody)['progress_between_unfinished_cleanup_samples'])
        self.assertFalse(progress(point(0, 0), samples, custody[:1])['progress_between_unfinished_cleanup_samples'])
        missing = dict(custody[1], complete=False, missing_reads=['proofs'])
        self.assertFalse(progress(point(0, 0), samples, [custody[0], missing])
                         ['progress_between_unfinished_cleanup_samples'])

    def test_cached_counters_are_not_recounted_as_fresh_observations(self):
        first, partial, last = point(500_000, 1), point(750_000, 1), point(1_000_000, 2)
        first['counter_reads'] = [dict(started_us=450_000, finished_us=500_000) for _ in range(5)]
        partial['counter_reads'] = [dict(read) for read in first['counter_reads']]
        partial['counter_reads'][0] = dict(started_us=700_000, finished_us=750_000)
        partial['delivered'] = 2
        result = progress(point(0, 0), [first, partial, last])
        self.assertTrue(result['within_limit'])
        self.assertEqual(result['observed_counter_reads'], [3, 2, 2, 2, 2])


class ReceiverObserverTests(unittest.TestCase):
    @staticmethod
    def fixture():
        run = SimpleNamespace(transit='transit', guard='guard', incoming='incoming',
                              nodes={'n02': SimpleNamespace(state='state')},
                              originals={'guard', 'spendable'}, guard_inputs={'guard'},
                              unspent={'spendable'}, intents={'guard': {'original': True}},
                              check_forwards=Mock())
        run.ctl = Mock(return_value={'payment_progress': {'transit': {'authorized_sat': 1},
                                                         'guard': {'authorized_sat': 1}}})
        run.credit = Mock(return_value=1000)
        run.journal = Mock(return_value={'funding': {'guard': {'original': True}},
                                        'seller_settlements': {'incoming': {}}})
        run.nodes['n02'].remote = Mock(side_effect=lambda *_, **__: json.dumps(run.journal()).encode())
        return run

    def test_one_slow_progress_reader_does_not_hold_back_other_readers(self):
        from sim.wifi_receiver_observer import ReceiverObserver
        run, entered, release = self.fixture(), threading.Event(), threading.Event()
        relay_calls = []

        def status(name, *_args, **_kwargs):
            if name == 'n02':
                relay_calls.append(1)
                if len(relay_calls) == 2:
                    entered.set()
                    if not release.wait(3):
                        raise RuntimeError('test did not release its owned progress read')
            return {'payment_progress': {'transit': {'authorized_sat': 1},
                                         'guard': {'authorized_sat': 1}}}

        run.ctl.side_effect = status
        with patch('sim.wifi_receiver_observer.probes.receive', return_value={'unique_packets': 1}), \
                ReceiverObserver(run, {}, time.monotonic()) as observer, \
                ThreadPoolExecutor(max_workers=1) as caller:
            baseline = observer.progress()
            future = caller.submit(observer.progress)
            try:
                self.assertTrue(entered.wait(1))
                try:
                    future.result(timeout=.25)
                except TimeoutError:
                    self.fail('one slow counter blocked unrelated progress readers')
                seen, deadline = [], time.monotonic() + 1
                while len(seen) < 3 and time.monotonic() < deadline:
                    sample = observer.progress()
                    if sample is not None and 3 in sample['updated_counters']:
                        seen.append(sample)
                    time.sleep(.001)
                self.assertEqual(len(seen), 3)
                self.assertEqual(len(relay_calls), 2)
                self.assertTrue(all(sample['counter_reads'][2] == baseline['counter_reads'][2]
                                    for sample in seen))
                self.assertGreater(seen[-1]['counter_reads'][3]['started_us'],
                                   seen[0]['counter_reads'][3]['finished_us'])
            finally:
                release.set()
                future.result(timeout=2)

    def test_unavailable_custody_is_explicit_and_cannot_mask_changed_identity(self):
        from sim.wifi_receiver_observer import ReceiverObserver
        run = self.fixture()
        with patch('sim.wifi_receiver_observer.custody.live', side_effect=custody.ReadUnavailable('unavailable')), \
                ReceiverObserver(run, {}, time.monotonic()) as observer:
            observer.start_custody()
            deadline, checked = time.monotonic() + 2, None
            while checked is None and time.monotonic() < deadline:
                checked = observer.poll_custody()
                time.sleep(.001)
            self.assertFalse(checked['complete'])
            self.assertEqual(checked['missing_reads'], ['proofs'])
            self.assertNotIn('cleanup_pending', checked)
            self.assertFalse(observer.start_custody(), 'custody polling interval was bypassed')
            run.journal.return_value['funding'] = {}
            observer.last_custody_started = -1
            observer.start_custody()
            with self.assertRaisesRegex(RuntimeError, 'original active guard funding'):
                while time.monotonic() < deadline:
                    observer.poll_custody()
                    time.sleep(.001)

    def test_slow_custody_never_retimes_or_blocks_progress_or_starts_overlapping_reads(self):
        from sim.wifi_receiver_observer import ReceiverObserver
        entered, release = threading.Event(), threading.Event()
        proof_calls = []

        def proofs(*_):
            proof_calls.append(1)
            entered.set()
            if not release.wait(3):
                raise RuntimeError('test did not release its owned observation')
            return {'guard': 'SPENT', 'spendable': 'UNSPENT'}

        run = self.fixture()
        with patch('sim.wifi_receiver_observer.custody.live', side_effect=proofs), \
                patch('sim.wifi_receiver_observer.probes.receive', return_value={'unique_packets': 1}), \
                ReceiverObserver(run, {}, time.monotonic()) as observer:
            try:
                observer.start_custody()
                self.assertTrue(entered.wait(1))
                first = observer.progress()
                second, deadline = None, time.monotonic() + 1
                while second is None and time.monotonic() < deadline:
                    second = observer.progress()
                    time.sleep(.001)
                self.assertIsNone(observer.poll_custody())
                self.assertIsNone(observer.poll_custody())
                self.assertFalse(observer.start_custody())
                self.assertEqual(len(proof_calls), 1)
                self.assertGreater(second['elapsed_us'], first['elapsed_us'])
                self.assertEqual(len(first['counter_reads']), 5)
                release.set()
                deadline = time.monotonic() + 2
                checked = None
                while checked is None and time.monotonic() < deadline:
                    checked = observer.poll_custody()
                    time.sleep(.001)
                self.assertIsNotNone(checked)
                self.assertLess(second['elapsed_us'], checked['elapsed_us'])
                self.assertTrue(checked['cleanup_pending'])
                self.assertEqual(checked['remaining_originals'], 2)
            finally:
                release.set()

    def test_changed_original_custody_still_refuses(self):
        from sim.wifi_receiver_observer import ReceiverObserver
        run = self.fixture()
        with patch('sim.wifi_receiver_observer.custody.live', return_value={'guard': 'UNSPENT'}), \
                ReceiverObserver(run, {}, time.monotonic()) as observer:
            observer.start_custody()
            deadline = time.monotonic() + 2
            with self.assertRaisesRegex(RuntimeError, 'exact guard or spendable original'):
                while time.monotonic() < deadline:
                    observer.poll_custody()
                    time.sleep(.001)


class ReceiverMeasurementTests(unittest.TestCase):
    def run_window(self, final_refusal=False, final_late=False, final_missing=False, missing_once=False):
        clock = SimpleNamespace(elapsed=0)
        run = SimpleNamespace(evidence={'receiver_history': {}}, save=Mock(),
                              transit='transit', guard='guard', held_nodes=['n02'],
                              nodes={'n02': SimpleNamespace(held=Mock(return_value=True))},
                              release_holds=Mock())
        held = [dict(payment_progress={channel: {'authorized_sat': 0}})
                for channel in ('transit', 'guard')]
        shape = dict(stream_id='original', packet_count=84, payload_bytes=1000)
        sender = dict(stream_id='original', requested_packets=84, submitted_packets=84,
                      submitted_bytes=84000, stopped_reason=None)
        future = Mock()
        future.done.return_value, future.result.return_value = False, sender
        pool = Mock()
        pool.__enter__ = Mock(return_value=pool)
        pool.__exit__ = Mock(return_value=False)
        pool.submit.return_value = future

        class Observer:
            def __init__(self, *_):
                self.round, self.progress_calls, self.start, self.pending = 0, 0, 0, False

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def start_custody(self):
                if self.pending:
                    return False
                self.pending = True
                self.round += 1
                self.start = int(clock.elapsed * 1_000_000)
                return True

            def progress(self):
                self.progress_calls += 1
                clock.elapsed += .2
                count = [0, 1, 40, 84, 84][self.progress_calls - 1]
                sample = point(int(clock.elapsed * 1_000_000), count)
                if self.progress_calls == 4:
                    # Buyer snapshots predate the newly observed final packet.
                    for reading in sample['counter_reads'][1:3]:
                        reading['started_us'] -= 100_000
                        reading['finished_us'] -= 100_000
                sample['payments'] = [dict(authorized_sat=count, evidence_msat=count * 1000,
                                           in_flight=count != 84, acknowledged_msat=count * 1000)] * 2
                return sample

            def poll_custody(self):
                if not self.pending:
                    return None
                self.pending = False
                if self.round == 5 and final_refusal:
                    raise RuntimeError('final original custody changed')
                if self.round == 5 and final_late:
                    clock.elapsed = 35.1
                if self.round >= 5 and final_missing and (self.round == 5 or not missing_once):
                    clock.elapsed += .5
                    return dict(started_us=self.start, elapsed_us=int(clock.elapsed * 1_000_000),
                                complete=False, missing_reads=['proofs'])
                return dict(started_us=self.start, elapsed_us=int(clock.elapsed * 1_000_000),
                            complete=True, cleanup_pending=self.round == 1)

        instance = Observer()

        def sleep(seconds):
            clock.elapsed += seconds

        with patch('sim.wifi_receiver_window.time.monotonic', side_effect=lambda: 100 + clock.elapsed), \
                patch('sim.wifi_receiver_window.time.sleep', side_effect=sleep), \
                patch('sim.wifi_receiver_window.ReceiverObserver', return_value=instance), \
                patch('sim.wifi_receiver_window.ThreadPoolExecutor', return_value=pool), \
                patch('sim.wifi_receiver_window.probes.arm', return_value=shape), \
                patch('sim.wifi_receiver_window.probes.receive', return_value={'unique_packets': 84}):
            result = measure(run, held, [0, 0])
        run.release_holds.assert_called_once_with(['n02'])
        pool.submit.assert_called_once()
        return result, instance

    def test_terminal_payment_waits_for_fresh_checked_complete_custody(self):
        row, observer = self.run_window()
        self.assertEqual(observer.progress_calls, 5)
        self.assertEqual(len(row['samples']), 4)
        self.assertEqual(len(row['custody_samples']), 5)
        self.assertLess(row['cleanup_finished_us'], row['terminal_progress_us'])
        self.assertGreater(row['terminal_progress_us'], row['traffic_finished_us'])
        self.assertGreaterEqual(row['custody_samples'][-1]['started_us'], row['terminal_progress_us'])
        self.assertFalse(row['custody_samples'][-1]['cleanup_pending'])
        self.assertTrue(row['passed'])

    def test_terminal_custody_failure_is_not_skipped_after_payments_finish(self):
        with self.assertRaisesRegex(RuntimeError, 'final original custody changed'):
            self.run_window(final_refusal=True)

    def test_late_final_custody_cannot_pass_the_original_35_second_deadline(self):
        with self.assertRaisesRegex(RuntimeError, 'inside35 seconds'):
            self.run_window(final_late=True)

    def test_missing_final_custody_requires_a_later_fresh_complete_observation(self):
        row, _ = self.run_window(final_missing=True, missing_once=True)
        self.assertTrue(row['passed'])
        self.assertFalse(row['custody_samples'][-2]['complete'])
        self.assertTrue(row['custody_samples'][-1]['complete'])
        self.assertGreaterEqual(row['custody_samples'][-1]['started_us'], row['terminal_progress_us'])

    def test_missing_custody_through_the_deadline_cannot_qualify(self):
        with self.assertRaisesRegex(RuntimeError, 'inside35 seconds'):
            self.run_window(final_missing=True)


class CustodyAvailabilityTests(unittest.TestCase):
    def test_only_remote_unavailability_is_typed_not_invalid_data(self):
        profile = SimpleNamespace(temporary='private', state='state', remote=Mock())
        for error in (RuntimeError('private remote failure'), subprocess.TimeoutExpired('read', 3)):
            profile.remote.side_effect = error
            with self.assertRaises(custody.ReadUnavailable):
                custody.live(profile, {'original'})
        profile.remote.side_effect = None
        profile.remote.return_value = b'invalid-json'
        with self.assertRaises(json.JSONDecodeError):
            custody.live(profile, {'original'})
        profile.remote.return_value = b'{"states":[]}'
        with self.assertRaisesRegex(RuntimeError, 'changed original identity count'):
            custody.live(profile, {'original'})


if __name__ == '__main__':
    unittest.main()
