"""Keep progress timing independent of bounded original-custody observation."""

import json
from queue import Full
import subprocess
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_receiver_window import exposure, measure, progress, reconciled
from sim import wifi_receiver_custody as custody
from sim import wifi_probes as probes


def point(at, value):
    return dict(elapsed_us=at, delivered=value,
                payments=[{'authorized_sat': value, 'signed_sat': value}] * 2, credits=[value * 1000] * 2,
                counter_reads=[dict(started_us=at, finished_us=at) for _ in range(5)])


class ReceiverTimingTests(unittest.TestCase):
    @staticmethod
    def priced_state(cost, evidence):
        return dict(payment_progress={'original': dict(evidence_msat=evidence)},
                    purchases=[dict(channel=dict(id='original', capacity_sat=32),
                                    contract=dict(price=dict(msat=cost, per_bytes=1000)))])

    def test_discrete_244msat_packets_cannot_meet_the_admitted_cadence(self):
        # Five discrete packets may be needed after rounding a prior claim up.
        # 5/3 seconds plus the unchanged 500ms scheduler target exceeds 2s.
        with self.assertRaisesRegex(RuntimeError, 'cadence'):
            exposure([self.priced_state(244, 0)], [self.priced_state(244, 244)],
                     [self.priced_state(244, 244)], ['original'], 84)

    def test_actual_250msat_payload_keeps_its_four_packet_bound(self):
        row = exposure([self.priced_state(250, 0)], [self.priced_state(250, 250)],
                       [self.priced_state(250, 250)], ['original'], 84)
        self.assertEqual(row['hops'][0]['maximum_quantization_us'], 1_333_334)
        self.assertEqual(row['hops'][0]['minimum_payload_msat'], 250)

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

    def test_delivery_finishes_at_last_expected_packet_while_payments_continue(self):
        samples = [point(at, index) for index, at in enumerate(range(500_000, 3_000_001, 500_000), 1)]
        for sample in samples:
            sample['delivered'] = min(sample['delivered'], 2)
        legacy = progress(point(0, 0), samples)
        result = progress(point(0, 0), samples, expected_packets=2)
        self.assertTrue(result['within_limit'])
        self.assertFalse(legacy['within_limit'])
        self.assertEqual(result['delivery_complete_us'], 1_000_000)
        self.assertEqual(result['observed_counter_reads'][0], 2)
        self.assertEqual(result['observation_us'], legacy['observation_us'])
        self.assertEqual(result['max_observed_gap_us'][1:], legacy['max_observed_gap_us'][1:])

    def test_delivery_completion_preserves_initial_final_and_payment_stall_checks(self):
        cases = [
            ('initial', [point(2_100_000, 0), point(2_200_000, 1), point(2_300_000, 2)], 0),
            ('final', [point(500_000, 1), point(2_600_000, 1), point(2_800_000, 2)], 0),
            ('payment', [point(500_000, 1), point(1_000_000, 2), point(3_100_000, 2)], 1),
        ]
        for name, samples, index in cases:
            with self.subTest(name=name):
                result = progress(point(0, 0), samples, expected_packets=2)
                self.assertFalse(result['within_limit'])
                self.assertEqual(result['timing_verdict'][index], 'failed')

    def test_delivery_completion_requires_the_exact_fresh_stream(self):
        for values in ((1, 1), (1, 3), (1, 2, 1)):
            with self.subTest(values=values):
                samples = [point(index * 500_000, value) for index, value in enumerate(values, 1)]
                with self.assertRaises(RuntimeError):
                    progress(point(0, 0), samples, expected_packets=2)
        with self.assertRaises(RuntimeError):
            progress(point(0, 1), [point(500_000, 2), point(1_000_000, 2)], expected_packets=2)

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

    def test_signature_progress_and_terminal_acknowledgment_are_distinct(self):
        sample = point(1_000_000, 2)
        states = {name: dict(started_us=1_000_000, finished_us=1_000_001,
                            value=dict(authorized_sat=2, evidence_msat=2000,
                                       acknowledged_msat=2000, in_flight=False, pending=None))
                  for name in ('source', 'n02')}
        self.assertTrue(reconciled(sample, states, 1_000_000))
        for field, wrong in (('acknowledged_msat', 1999), ('in_flight', True), ('authorized_sat', 3),
                             ('pending', {'amount': 1})):
            changed = json.loads(json.dumps(states))
            changed['n02']['value'][field] = wrong
            self.assertFalse(reconciled(sample, changed, 1_000_000))
        self.assertFalse(reconciled(sample, states, 1_000_001))
        sample['payments'] = [dict(authorized_sat=2, signed_sat=1)] * 2
        self.assertFalse(reconciled(sample, states, 1_000_000))
        samples = [point(500_000, 1), point(1_000_000, 2)]
        for current in samples:
            current['payments'] = [dict(authorized_sat=current['delivered'], signed_sat=0)] * 2
        self.assertTrue(progress(point(0, 0), samples)['all_counters_advanced'])
        self.assertFalse(progress(point(0, 0), samples, payment_field='signed_sat')['all_counters_advanced'])


class ReceiverObserverTests(unittest.TestCase):
    def setUp(self):
        class Numeric:
            def __init__(self, run):
                self.run = run

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def payment(self, name, channel):
                row = self.run.ctl(name, 'status')['payment_progress'][channel]
                return dict(authorized_sat=row['authorized_sat'], signed_sat=row['authorized_sat'])

            def credit(self, name, channel):
                return self.run.credit(name, channel)

        patcher = patch('sim.wifi_receiver_observer.NumericReaders', Numeric)
        patcher.start()
        self.addCleanup(patcher.stop)

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
                ReceiverObserver(run, {}, time.monotonic()) as observer:
            baseline = observer.baseline()
            observer.start()
            try:
                self.assertTrue(entered.wait(1))
                seen, deadline = [], time.monotonic() + 1
                while len(seen) < 3 and time.monotonic() < deadline:
                    seen.extend(sample for sample in observer.progress() if 3 in sample['updated_counters'])
                    time.sleep(.001)
                self.assertEqual(len(seen), 3)
                self.assertEqual(len(relay_calls), 2)
                self.assertTrue(all(sample['counter_reads'][2] == baseline['counter_reads'][2]
                                    for sample in seen))
                self.assertGreater(seen[-1]['counter_reads'][3]['started_us'],
                                   seen[0]['counter_reads'][3]['finished_us'])
            finally:
                release.set()

    def test_readers_continue_and_retain_every_read_while_main_thread_is_busy(self):
        from sim.wifi_receiver_observer import ReceiverObserver
        run, reads = self.fixture(), []

        def credit(name, _channel):
            if name == 'n02':
                reads.append(len(reads) // 2)
                return reads[-1]
            return 1000

        run.credit.side_effect = credit
        with patch('sim.wifi_receiver_observer.probes.receive', return_value={'unique_packets': 1}), \
                patch('sim.wifi_receiver_observer.POLL_SECONDS', .01), \
                ReceiverObserver(run, {}, time.monotonic()) as observer:
            baseline = observer.baseline()
            observer.start()
            time.sleep(.1)  # The release operation can occupy this caller.
            samples = observer.stop_and_drain()
            actual = [sample['credits'][0] for sample in samples if 3 in sample['updated_counters']]
            self.assertGreaterEqual(len(actual), 3)
            self.assertEqual([baseline['credits'][0], *actual], reads)
            self.assertEqual([sample['elapsed_us'] for sample in samples],
                             sorted(set(sample['elapsed_us'] for sample in samples)))
            self.assertTrue(all(future.done() for future in observer.progress_pending.values()))

    def test_terminal_trace_reuses_the_same_bounded_scheduler_reads(self):
        from sim.wifi_receiver_observer import ReceiverObserver
        records = {name: {'payment_progress': {'authorized_sat': amount}, 'trace': {'pending': 0}}
                   for name, amount in (('source', 2), ('n02', 1))}
        with patch('sim.wifi_receiver_observer.authorization_trace.read_channel',
                   side_effect=lambda _run, name, *_args, **_kwargs: records[name]) as read, \
                ReceiverObserver(self.fixture(), {}, time.monotonic()) as observer:
            result, deadline = None, time.monotonic() + 2
            while result is None and time.monotonic() < deadline:
                result = observer.payment_status()
                time.sleep(.001)
            self.assertIsNotNone(result)
            self.assertEqual(read.call_count, 2)
            for name in records:
                self.assertIs(observer.authorization_status[name], records[name])
                self.assertIs(result[name]['value'], records[name]['payment_progress'])
                self.assertLessEqual(result[name]['started_us'], result[name]['finished_us'])
            self.assertTrue(all(call.kwargs == {'timeout': 3} for call in read.call_args_list))

    def test_overflow_and_reader_error_refuse_without_leaving_workers(self):
        from sim.wifi_receiver_observer import ReceiverObserver
        for fail in (False, True):
            run = self.fixture()
            with self.subTest(reader_error=fail), \
                    patch('sim.wifi_receiver_observer.probes.receive', return_value={'unique_packets': 1}), \
                    patch('sim.wifi_receiver_observer.MAX_PROGRESS_READS', 2 if not fail else 2048), \
                    self.assertRaises(RuntimeError if fail else Full):
                with ReceiverObserver(run, {}, time.monotonic()) as observer:
                    observer.baseline()
                    if fail:
                        run.credit.side_effect = RuntimeError('owned numeric read failed')
                    observer.start()
                    time.sleep(.05)
                    retained = observer.stop_and_drain()
                    self.assertTrue(retained, 'fresh samples were lost before the reader failure')
                    with self.assertRaises(RuntimeError if fail else Full):
                        observer.stop_and_drain()
            self.assertTrue(all(future.done() for future in observer.progress_pending.values()))

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
                first = observer.baseline()
                observer.start()
                later, deadline = [], time.monotonic() + 1
                while not later and time.monotonic() < deadline:
                    later = observer.progress()
                    time.sleep(.001)
                second = later[-1]
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
    def run_window(self, final_refusal=False, final_late=False, final_missing=False, missing_once=False,
                   held_override=None, save_observations=None, observation_delay=0):
        clock = SimpleNamespace(elapsed=0)
        run = SimpleNamespace(evidence={'receiver_history': {}}, save=Mock(),
                              transit='transit', guard='guard', held_nodes=['n02'],
                              check_forwards=Mock(), monitor=SimpleNamespace(check=Mock()),
                              nodes={'n02': SimpleNamespace(held=Mock(return_value=True))},
                              release_holds=Mock())
        def saved():
            if save_observations is not None:
                save_observations.append((clock.elapsed, json.loads(json.dumps(run.evidence))))
        run.save.side_effect = saved
        held = [dict(payment_progress={channel: dict(authorized_sat=0, evidence_msat=0,
                                                    in_flight=False, acknowledged_msat=0)})
                for channel in ('transit', 'guard')]
        if held_override:
            held[0]['payment_progress']['transit'].update(held_override)
        shape = dict(stream_id='original', packet_count=84, payload_bytes=1000)
        sender = dict(stream_id='original', requested_packets=84, submitted_packets=84,
                      submitted_bytes=84000, stopped_reason=None)
        future = Mock()
        future.done.return_value, future.result.return_value = False, sender
        pool = Mock()
        pool.__enter__ = Mock(return_value=pool)
        pool.__exit__ = Mock(return_value=False)
        trace_future = Mock()
        trace_future.result.return_value = {}
        pool.submit.side_effect = [trace_future, future]

        class Observer:
            def __init__(self, *_):
                self.round, self.progress_calls, self.custody_started, self.pending = 0, 0, 0, False

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def start_custody(self):
                if self.pending:
                    return False
                self.pending = True
                self.round += 1
                self.custody_started = int(clock.elapsed * 1_000_000)
                return True

            def baseline(self):
                return self.observe()

            def start(self):
                pass

            def progress(self):
                return [self.observe()]

            def stop_and_drain(self):
                return []

            def payment_status(self):
                current = self.last_sample
                self.authorization_status = {name: dict(channel_id=channel, payment_progress=payment,
                    npub=name, host_process=dict(pid=42, start_ticks=100), process_id=42,
                    trace=dict(pending=0)) for name, channel, payment in
                    zip(('source', 'n02'), ('transit', 'guard'), current['payments'])}
                return {name: dict(started_us=current['elapsed_us'], finished_us=current['elapsed_us'],
                                   value=payment) for name, payment in zip(('source', 'n02'), current['payments'])}

            def observe(self):
                self.progress_calls += 1
                clock.elapsed += .2
                count = [0, 1, 40, 84, 84][self.progress_calls - 1]
                sample = point(int(clock.elapsed * 1_000_000), count)
                if self.progress_calls == 4:
                    # Buyer snapshots predate the newly observed final packet.
                    for reading in sample['counter_reads'][1:3]:
                        reading['started_us'] -= 100_000
                        reading['finished_us'] -= 100_000
                sample['payments'] = [dict(authorized_sat=count, signed_sat=count, evidence_msat=count * 1000,
                                           in_flight=count != 84, acknowledged_msat=count * 1000, pending=None)] * 2
                self.last_sample = sample
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
                    return dict(started_us=self.custody_started, elapsed_us=int(clock.elapsed * 1_000_000),
                                complete=False, missing_reads=['proofs'])
                return dict(started_us=self.custody_started, elapsed_us=int(clock.elapsed * 1_000_000),
                            complete=True, cleanup_pending=self.round == 1)

        instance = Observer()

        def sleep(seconds):
            clock.elapsed += seconds
            if run.release_holds.called:
                clock.elapsed += observation_delay

        with patch('sim.wifi_receiver_window.time.monotonic', side_effect=lambda: 100 + clock.elapsed), \
                patch('sim.wifi_receiver_window.time.sleep', side_effect=sleep), \
                patch('sim.wifi_receiver_window.ReceiverObserver', return_value=instance), \
                patch('sim.wifi_receiver_window.ThreadPoolExecutor', return_value=pool), \
                patch('sim.wifi_receiver_window.authorization_trace.capture', return_value={}), \
                patch('sim.wifi_receiver_window.authorization_trace.checked'), \
                patch('sim.wifi_receiver_window.authorization_trace.qualify', side_effect=lambda polled, _: polled), \
                patch('sim.wifi_receiver_window.probes.arm', return_value=shape), \
                patch('sim.wifi_receiver_window.probes.receive', return_value={'unique_packets': 84}):
            result = measure(run, held, [0, 0])
        run.release_holds.assert_called_once_with(['n02'])
        self.assertEqual(pool.submit.call_count, 2)
        self.assertIs(pool.submit.call_args_list[-1].args[0], probes.send)
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

    def test_diagnostics_are_throttled_and_terminal_analysis_is_saved(self):
        saved = []
        row, _ = self.run_window(save_observations=saved, observation_delay=.8)
        before_terminal = [at for at, _ in saved if at * 1_000_000 < row['terminal_progress_us']]
        self.assertEqual(len(before_terminal), 3)
        self.assertEqual(before_terminal[0], 0)
        self.assertTrue(all(later - earlier >= 1 for earlier, later in zip(before_terminal, before_terminal[1:])))
        self.assertLess(row['released_us'], 2_000_000)
        self.assertGreaterEqual(row['custody_samples'][-1]['started_us'], row['terminal_progress_us'])
        self.assertEqual(saved[-1][1]['receiver_history']['live'], row)
        self.assertEqual(row['progress_poll_delay_us'], 25_000)

    def test_finally_preserves_every_sample_and_sender_on_custody_failure(self):
        saved = []
        with self.assertRaisesRegex(RuntimeError, 'final original custody changed'):
            self.run_window(final_refusal=True, save_observations=saved)
        final = saved[-1][1]['receiver_history']['live']
        self.assertEqual(len(final['samples']), 4)
        self.assertEqual(final['sender']['submitted_packets'], 84)
        self.assertFalse(final['passed'])

    def test_baseline_must_match_the_acknowledged_pre_stream_payment(self):
        for wrong in (dict(in_flight=True), dict(acknowledged_msat=None),
                      dict(authorized_sat=1, acknowledged_msat=1000)):
            with self.subTest(held=wrong), self.assertRaisesRegex(RuntimeError, 'baseline changed'):
                self.run_window(held_override=wrong)

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
