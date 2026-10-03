"""Restart/load acceptance rejects lost financial evidence and still closes known funds."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_restart_load import RestartLoadRun, recovered_exposure, retained_finances
from tests.test_paid_settlement import finances


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
        run.restore_middle, run.collect = Mock(), Mock()
        with patch('sim.wifi_restart_load.signal.alarm') as alarm, self.assertRaisesRegex(RuntimeError, 'delivery failed'):
            run.exercise()
        alarm.assert_called_once_with(0)
        run.restore_middle.assert_called_once()
        run.collect.assert_called_once()
        self.assertEqual(run.ctl.call_count, 2)


if __name__ == '__main__':
    unittest.main()
