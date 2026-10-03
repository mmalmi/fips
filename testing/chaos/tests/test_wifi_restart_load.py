"""Restart/load acceptance rejects lost financial evidence and still closes known funds."""

import copy
import json
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_frame_loss import FrameLoss
from sim.wifi_restart_load import PACKETS, RestartLoadRun, recovered_exposure, retained_finances, validate_stream
from sim.wifi_restart_traffic import active_restart_stream, validate_overlap
from tests.test_paid_settlement import finances
from tests.test_wifi_priority import reports


def accounts():
    values = finances()
    for name, state in values.items():
        state.update(signed_after=dict(state['signed']), buyer_units={}, seller_units={}, seller_channels={})
        if name != 'n02':
            channel = 'channel-' + name
            state['buyer_units'][channel] = 1000
            provider = values['n02']
            provider['credited'][channel] = state['signed'][channel] * 1000
    for name in ('n01', 'n03'):
        key = 'channel-' + name
        values['n02']['seller_units'][key] = 1000
        values['n02']['seller_channels'][key] = {
            'paid_msat': values['n02']['credited'][key], 'reserved_msat': 1000,
            'submitted_msat': 1000, 'lost_msat': 0,
        }
    return values


def journal():
    return {'version': 2, 'window_msat': 4000, 'ceilings': {'a': 7000, 'b': 8000},
            'ledger': {'channels': [
                {'active': True, 'terms': {'id': name, 'capacity_sat': 32, 'grace_msat': 8000},
                 'usage': {'reserved_msat': 4000, 'lost_msat': 0, 'paid_msat': 4000}}
                for name in ('a', 'b')]}}


class RestartLoadTests(unittest.TestCase):
    def test_active_restart_rejects_stale_delivery_or_a_late_control_response(self):
        shape, _, report = reports(PACKETS, 1000)
        def partial(count):
            return {**report, 'unique_packets': count, 'unique_bytes': count * 1000,
                    'missing_packets': PACKETS - count}
        evidence = {'before_crash': partial(10), 'recovery_before': partial(12),
                    'recovery_after': partial(13), 'dispatch_started': 100,
                    'crash_started': 101, 'restarted_at': 103,
                    'recovery_sampled_at': 104, 'recovery_observed_at': 105}
        validate_overlap(evidence, shape, 'paid-source', 200)
        for edit in (
            lambda e: e.update(recovery_after=partial(12)),
            lambda e: e.update(recovery_after=partial(PACKETS)),
            lambda e: e.update(recovery_observed_at=120),
            lambda e: e.update(restarted_at=106),
            lambda e: e['recovery_after'].update(stream_id='foreign'),
        ):
            changed = copy.deepcopy(evidence); edit(changed)
            with self.assertRaises(RuntimeError):
                validate_overlap(changed, shape, 'paid-source', 200)

    def test_uncertain_crash_drains_one_sender_before_returning_to_cleanup(self):
        shape, sender, receiver = reports(PACKETS, 1000)
        receiver.update(unique_packets=1, unique_bytes=1000, missing_packets=PACKETS - 1)
        released, finished = threading.Event(), threading.Event()
        run = SimpleNamespace(nodes={'n01': SimpleNamespace(npub='paid-source')},
                              middle_sample=Mock(return_value={}), evidence={}, save=Mock())
        def send(*_args):
            if not released.wait(5):
                raise RuntimeError('test sender was never released')
            finished.set()
            return sender
        def crash(**_kwargs):
            released.set()
            raise RuntimeError('crash reply lost')
        run.restart_middle = crash
        with patch('sim.wifi_restart_traffic.probes.arm', return_value=shape), \
             patch('sim.wifi_restart_traffic.probes.receive', return_value=receiver), \
             patch('sim.wifi_restart_traffic.time.sleep'), \
             patch('sim.wifi_restart_traffic.probes.send', side_effect=send) as sending:
            with self.assertRaisesRegex(RuntimeError, 'crash reply lost'):
                active_restart_stream(run, 3, PACKETS, 200)
        self.assertTrue(finished.is_set())
        self.assertEqual(run.evidence['active_restart']['sender'], sender)
        self.assertEqual(run.evidence['active_restart']['receiver'], receiver)
        sending.assert_called_once()

    def test_loss_needs_counted_drops_and_healthy_streams_still_require_full_delivery(self):
        _, sender, receiver = reports(PACKETS, 1000)
        row = {'sender': sender, 'receiver': receiver, 'seconds': 20}
        validate_stream(row, 'paid-source')
        row['frame_loss'] = {
            'before': {'enabled': True, 'jump_handle': 9, 'dropped_packets': 0, 'dropped_bytes': 0},
            'after': {'enabled': True, 'jump_handle': 9, 'dropped_packets': 200, 'dropped_bytes': 220000},
        }
        receiver.update(unique_packets=3800, unique_bytes=3800000, missing_packets=200)
        validate_stream(row, 'paid-source')
        for edit in (
            lambda r: r.pop('frame_loss'),
            lambda r: r.update(frame_loss={}),
            lambda r: r['frame_loss']['after'].update(dropped_packets=199),
            lambda r: r['frame_loss']['after'].update(enabled=False),
            lambda r: r['frame_loss']['after'].update(jump_handle=10),
            lambda r: r['receiver'].update(unique_packets=3500, unique_bytes=3500000, missing_packets=500),
            lambda r: r['receiver'].update(unique_packets=4000, unique_bytes=4000000, missing_packets=0),
            lambda r: r['receiver'].update(duplicate_packets=1),
        ):
            changed = copy.deepcopy(row); edit(changed)
            with self.assertRaises(RuntimeError):
                validate_stream(changed, 'paid-source')

    def test_uncertain_loss_installation_is_cleared_without_replaying_or_touching_foreign_rules(self):
        node = SimpleNamespace(table='fips_test', table_owner='test-owner', temporary='/tmp/owned')
        loss = FrameLoss(node, '02:00:00:00:00:02')
        active, calls = False, []

        def guarded(command, data=None):
            nonlocal active
            calls.append((command, data))
            self.assertIn('test -f /tmp/owned/table-created', command)
            self.assertIn('= "test-owner"', command)
            if data:
                if b'create chain' in data:
                    active = True
                    raise RuntimeError('reply lost after installation')
                active = False
                return b''
            rows = [{'chain': {'name': 'ingress'}},
                    {'rule': {'chain': 'ingress', 'handle': 7, 'expr': [{'drop': None}]}}]
            if active:
                rows += [{'chain': {'name': 'frame_loss'}},
                         {'rule': {'chain': 'ingress', 'handle': 9, 'comment': loss.comment}},
                         {'rule': {'chain': 'frame_loss', 'expr': [
                             {'counter': {'packets': 3, 'bytes': 3000}}, {'drop': None}]}}]
            return json.dumps({'nftables': rows}).encode()

        node.guarded = guarded
        with self.assertRaisesRegex(RuntimeError, 'reply lost'):
            loss.enable()
        observed = loss.clear()
        self.assertEqual(observed['before']['dropped_packets'], 3)
        self.assertFalse(observed['after']['enabled'])
        writes = [data.decode() for _, data in calls if data]
        self.assertEqual(len(writes), 2)
        self.assertIn('ether type 0x88b5 ether saddr 02:00:00:00:00:02 jump frame_loss', writes[0])
        self.assertIn('numgen inc mod 20 0 counter drop', writes[0])
        self.assertEqual(writes[1], 'delete rule netdev fips_test ingress handle 9\n'
                         'flush chain netdev fips_test frame_loss\n'
                         'delete chain netdev fips_test frame_loss\n')
        with self.assertRaisesRegex(ValueError, 'exact adjacent'):
            FrameLoss(node, '02:00:00:00:00:02; reboot')

    def test_failed_impaired_stream_clears_both_filters_before_collecting_funds(self):
        run = object.__new__(RestartLoadRun)
        run.nodes = {n: SimpleNamespace(npub=n, mac='02:00:00:00:00:02')
                     for n in ('n01', 'n02', 'n03')}
        run.form_line, run.ctl, run.finances = Mock(), Mock(), Mock(return_value=accounts())
        run.warmup, run.save, run.phase = Mock(), Mock(), Mock()
        run.frame_loss, run.loss_filters, run.evidence = True, {}, {'streams': []}
        run.middle_sample = Mock(return_value={'host_process': {'host': 'n02', 'pid': 2, 'start_ticks': 10}})
        run.checkpoint = Mock(return_value=accounts())
        events = []
        run.restore_middle = lambda: events.append('restore')
        run.collect = lambda: events.append('collect')
        faults = [Mock(), Mock()]
        for name, fault in zip(('n01', 'n03'), faults):
            fault.clear.side_effect = lambda name=name: events.append('clear-' + name)

        def stream(_count, _rate, *, source, destination):
            if len(run.evidence['streams']) == 2:
                raise RuntimeError('impaired stream failed')
            _, sender, receiver = reports(PACKETS, 1000)
            receiver['source'] = source
            return {'sender': sender, 'receiver': receiver}

        run.stream = stream
        with patch('sim.wifi_restart_load.FrameLoss', side_effect=faults), \
                patch('sim.wifi_restart_load.time.monotonic', side_effect=range(0, 1000, 20)), \
                patch('sim.wifi_restart_load.signal.alarm'), \
                self.assertRaisesRegex(RuntimeError, 'impaired stream failed'):
            run.exercise()
        self.assertEqual(events, ['clear-n01', 'clear-n03', 'restore', 'collect'])
        for fault in faults:
            fault.enable.assert_called_once()

    def test_one_failed_filter_clear_does_not_skip_the_other_receiver(self):
        run = object.__new__(RestartLoadRun)
        first = Mock(clear=Mock(side_effect=RuntimeError('uncertain removal')))
        second = Mock(clear=Mock(return_value={'after': {'enabled': False}}))
        run.loss_filters, run.phase = {'n01': first, 'n03': second}, Mock()
        with self.assertRaisesRegex(RuntimeError, 'removal incomplete: n01'):
            run.clear_loss()
        second.clear.assert_called_once()
        outcomes = run.phase.call_args.kwargs['filters']
        self.assertEqual(outcomes['n01'], {'error': 'RuntimeError'})
        self.assertFalse(outcomes['n03']['after']['enabled'])

    def test_recovery_requires_the_exact_stopped_durable_window(self):
        self.assertEqual(recovered_exposure(journal()), {'a': 3000, 'b': 4000})
        for key, value in (('window_msat', 8000), ('ceilings', {'a': 3999, 'b': 8000}),
                           ('ceilings', {'a': 8001, 'b': 8000}),
                           ('ceilings', {'a': 7000, 'b': 8000, 'foreign': 1})):
            changed = journal(); changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                recovered_exposure(changed)

    def test_recovery_cannot_reset_funding_or_turn_unbilled_exposure_into_usage(self):
        old = accounts(); current = copy.deepcopy(old)
        lost = {'channel-n01': 3000, 'channel-n03': 4000}
        for key, value in lost.items():
            current['n02']['seller_channels'][key].update(lost_msat=value, reserved_msat=1000 + value)
        self.assertEqual(retained_finances(old, current, lost), current)
        for edit in (
            lambda r: r['n02']['seller_channels']['channel-n01'].update(lost_msat=2999),
            lambda r: r['n02']['seller_channels']['channel-n01'].update(submitted_msat=3001),
            lambda r: r['n02']['seller_channels'].pop('channel-n01'),
            lambda r: r['n01']['funding'].update({'fund-n01': ('channel-n01', 'new-operation')}),
            lambda r: r['n01']['buyer_units'].update({'channel-n01': 999}),
            lambda r: r['n02']['credited'].update({'channel-n01': 999999}),
        ):
            changed = copy.deepcopy(current); edit(changed)
            with self.assertRaises(RuntimeError):
                retained_finances(old, changed, lost)

    def test_a_failed_workload_still_restores_control_and_collects_original_funds(self):
        run = object.__new__(RestartLoadRun)
        run.nodes = {n: SimpleNamespace(npub=n) for n in ('n01', 'n02', 'n03')}
        run.form_line, run.ctl, run.finances = Mock(), Mock(), Mock(return_value=accounts())
        run.warmup = Mock(side_effect=RuntimeError('delivery failed'))
        run.loss_filters = {}
        run.restore_middle, run.collect = Mock(), Mock()
        with patch('sim.wifi_restart_load.signal.alarm') as alarm, self.assertRaisesRegex(RuntimeError, 'delivery failed'):
            run.exercise()
        alarm.assert_called_once_with(0)
        run.restore_middle.assert_called_once()
        run.collect.assert_called_once()
        self.assertEqual(run.ctl.call_count, 2)


if __name__ == '__main__':
    unittest.main()
