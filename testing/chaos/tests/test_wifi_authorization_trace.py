"""Event timing must retain uncertainty, complete custody and process identity."""

import copy
import unittest

from sim import wifi_authorization_trace as trace
from sim.wifi_authorization_trace import channel_progress, qualify


def event(sequence, old, new, start, finish, channel='original'):
    return dict(sequence=sequence, channel_id=channel, old_sat=old, new_sat=new,
                started_ns=start, finished_ns=finish)


def snapshot(sequence, at, balance, events):
    return dict(channel_id='original', npub='original-node', process_id=42,
                host_process=dict(host='n02', pid=42, start_ticks=100), started_us=0, finished_us=1,
                payment_progress=dict(authorized_sat=balance, evidence_msat=balance * 1000,
                                      in_flight=False, pending=None, acknowledged_msat=balance * 1000),
                trace=dict(version=1, clock='CLOCK_MONOTONIC', capacity=1024, measured_at_ns=at,
                           completed_sequence=sequence, overwritten=0, missing_intervals=0,
                           clock_failures=0, aborted=0, pending=0, sequence_exhausted=False,
                           lock_poisoned=False, events=events))


def fixture():
    prior = event(10, 0, 1, 900_000_000, 910_000_000)
    first = snapshot(10, 1_000_000_000, 1, [prior])
    last = snapshot(13, 4_900_000_000, 3, [prior,
        event(11, 1, 2, 2_800_000_000, 2_810_000_000),
        event(12, 9, 10, 3_000_000_000, 3_010_000_000, 'other'),
        event(13, 2, 3, 4_700_000_000, 4_710_000_000)])
    return first, last


class AuthorizationTraceTests(unittest.TestCase):
    def test_each_channel_keeps_its_first_unchanged_quiescent_terminal(self):
        before, first = fixture()
        selected = trace.terminal_records({}, {'n02': first})
        late = copy.deepcopy(first)
        late['trace']['measured_at_ns'] = 6_800_000_001
        selected = trace.terminal_records(selected, {'source': late, 'n02': late})
        self.assertIs(selected['n02'], first)
        self.assertIs(selected['source'], late)
        self.assertEqual(channel_progress(before, selected['n02'], 'original', 1, 3)['timing_verdict'], 'passed')
        self.assertEqual(channel_progress(before, late, 'original', 1, 3)['timing_verdict'], 'failed')

    def test_changed_accounted_work_replaces_an_earlier_terminal(self):
        _, first = fixture()
        selected = trace.terminal_records({}, {'n02': first})
        newer = copy.deepcopy(first)
        newer['payment_progress'].update(authorized_sat=4, acknowledged_msat=4000, evidence_msat=4000)
        newer['trace'].update(completed_sequence=14, measured_at_ns=6_200_000_000)
        newer['trace']['events'].append(event(14, 3, 4, 5_800_000_000, 5_810_000_000))
        self.assertIs(trace.terminal_records(selected, {'n02': newer})['n02'], newer)

    def test_unfinished_trace_cannot_reuse_a_quiescent_terminal(self):
        _, first = fixture()
        selected = trace.terminal_records({}, {'n02': first})
        busy = copy.deepcopy(first)
        busy['trace']['pending'] = 1
        self.assertEqual(trace.terminal_records(selected, {'n02': busy}), {})
        restarted = copy.deepcopy(first)
        restarted['host_process']['start_ticks'] += 1
        with self.assertRaisesRegex(RuntimeError, 'process epoch changed'):
            trace.terminal_records(selected, {'n02': restarted})

    def test_complete_commit_intervals_include_both_quiescent_boundaries(self):
        before, after = fixture()
        result = channel_progress(before, after, 'original', 1, 3)
        self.assertEqual(result['timing_verdict'], 'passed')
        self.assertEqual(result['maximum_gap_ns'], 1_910_000_000)
        self.assertEqual(result['minimum_gap_ns'], 1_890_000_000)
        self.assertEqual(result['commits'], 2)
        after['trace']['measured_at_ns'] = 6_800_000_001
        self.assertEqual(channel_progress(before, after, 'original', 1, 3)['timing_verdict'], 'failed')

    def test_crossing_intervals_remain_unqualified_and_proved_stalls_fail(self):
        before, after = fixture()
        after['trace']['events'][-1].update(started_ns=4_790_000_000, finished_ns=4_810_000_001)
        result = channel_progress(before, after, 'original', 1, 3)
        self.assertEqual(result['timing_verdict'], 'unqualified')
        self.assertLess(result['minimum_gap_ns'], 2_000_000_000)
        self.assertGreater(result['maximum_gap_ns'], 2_000_000_000)
        after['trace']['events'][-1]['started_ns'] = 4_810_000_001
        self.assertEqual(channel_progress(before, after, 'original', 1, 3)['timing_verdict'], 'failed')

    def test_missing_coverage_and_changed_original_authority_are_refused(self):
        changes = [
            lambda row: row['trace'].update(pending=1),
            lambda row: row['trace'].update(missing_intervals=1),
            lambda row: row['trace'].update(clock_failures=1),
            lambda row: row['trace'].update(aborted=1),
            lambda row: row['trace'].update(sequence_exhausted=True),
            lambda row: row['trace'].update(lock_poisoned=True),
            lambda row: row['trace'].update(measured_at_ns=None),
            lambda row: row['trace']['events'].pop(2),
            lambda row: row['trace']['events'][-1].update(old_sat=1),
            lambda row: row['trace']['events'][-1].update(finished_ns=5_000_000_000),
            lambda row: row['host_process'].update(start_ticks=101),
            lambda row: row['payment_progress'].update(acknowledged_msat=2999),
            lambda row: row['payment_progress'].update(pending=3000),
        ]
        for change in changes:
            before, after = fixture()
            change(after)
            with self.subTest(change=changes.index(change)), self.assertRaises(RuntimeError):
                channel_progress(before, after, 'original', 1, 3)

    def test_poll_uncertainty_is_retained_beside_direct_timing_and_cannot_hide_credit_failure(self):
        before, after = fixture()
        before.update(started_us=10, finished_us=20)
        after.update(started_us=4_000_001, finished_us=4_100_000)
        row = dict(payment_channels=['original'] * 2, stream_started_us=30, traffic_finished_us=3_900_000,
                   terminal_progress_us=4_200_000,
                   baseline=dict(payments=[dict(authorized_sat=1)] * 2),
                   samples=[dict(payments=[dict(authorized_sat=3)] * 2,
                                 counter_reads=[dict(finished_us=4_000_000)] * 5)],
                   authorization_commit_observation=dict(baseline=dict(source=before, n02=before),
                                                         terminal=dict(source=after, n02=after)),
                   terminal_payment_status={name: dict(value=copy.deepcopy(after['payment_progress']))
                                            for name in ('source', 'n02')})
        polled = dict(timing_verdict=['passed', 'unqualified', 'unqualified', 'failed', 'passed'],
                      max_observed_gap_us=[1_900_000, 2_100_000, 2_100_000, 2_200_000, 1_900_000],
                      minimum_gap_us=[1_800_000, 1_900_000, 1_900_000, 2_100_000, 1_800_000],
                      within_limit=False)
        original = copy.deepcopy(polled)
        result = qualify(polled, row)
        self.assertEqual(polled, original)
        self.assertEqual(result['timing_verdict'], ['passed', 'passed', 'passed', 'failed', 'passed'])
        self.assertFalse(result['within_limit'])
        self.assertEqual(result['max_observed_gap_us'][1:3], [1_910_000] * 2)
        row['samples'][-1]['counter_reads'][-1]['finished_us'] = 4_150_000
        self.assertEqual(qualify(polled, row)['timing_verdict'], result['timing_verdict'])
        row['terminal_payment_status']['n02']['value']['evidence_msat'] = 3001
        with self.assertRaisesRegex(RuntimeError, 'final reconciled payment'):
            qualify(polled, row)
        row['terminal_payment_status']['n02']['value']['evidence_msat'] = 3000
        row['stream_started_us'] = 19
        with self.assertRaisesRegex(RuntimeError, 'bracket'):
            qualify(polled, row)


if __name__ == '__main__':
    unittest.main()
