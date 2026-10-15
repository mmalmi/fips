"""Reject false retirement overlap and preserve the ordinary settlement boundary."""

import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_retirement_live import (CAPACITY, LiveRetirementRun, deadlines,
                                     maintenance_idle, overlap, refund_count)


class FragmentedRetirementTests(unittest.TestCase):
    def test_overlap_requires_payment_credit_and_delivery_inside_one_plan(self):
        before = dict(plan='same', authorized_sat=1, credited_msat=1000, delivered=4)
        after = dict(plan='same', authorized_sat=2, credited_msat=2000, delivered=8)
        self.assertTrue(overlap([before, after]))
        for change in (dict(plan=None), dict(plan='replacement'), dict(authorized_sat=1),
                       dict(credited_msat=1000), dict(delivered=4)):
            with self.subTest(change=change):
                self.assertFalse(overlap([before, {**after, **change}]))
        self.assertFalse(overlap([before]))
        signed = {**before, 'authorized_sat': 2}
        self.assertTrue(overlap([before, signed, after]))
        self.assertFalse(overlap([before, {**signed, 'plan': None}, after]))
        self.assertFalse(overlap([before, {**signed, 'plan': 'other'}, after]))

    def test_device_deadline_bounds_preserve_hold_and_active_preparation_windows(self):
        intents = {'first': {'refund_after_unix': 1200}, 'last': {'refund_after_unix': 1290}}
        self.assertEqual(deadlines(intents, 1099), (1200, 1290))
        for now, last in ((1100, 1290), (1099, 1291)):
            with self.subTest(now=now, last=last), self.assertRaises(RuntimeError):
                deadlines({**intents, 'last': {'refund_after_unix': last}}, now)

    def test_release_rejects_uncredited_or_changed_held_payment_before_sending(self):
        for baseline in ({'authorized_sat': 2, 'credited_msat': 1000},
                         {'authorized_sat': 3, 'credited_msat': 3000}):
            run = object.__new__(LiveRetirementRun)
            run.active, run.held_nodes, run.evidence = 'active', ['n01'], {'fragmented': {}}
            run.caught_up = Mock(return_value={'payment_progress': {'active': {'authorized_sat': 2}}})
            run.release_holds, run.sample = Mock(), Mock(return_value=baseline)
            with self.subTest(baseline=baseline), \
                    patch('sim.wifi_retirement_live.probes.arm', return_value={}), \
                    patch('sim.wifi_retirement_live.probes.send') as send:
                with self.assertRaisesRegex(RuntimeError, 'post-release baseline'):
                    run.traffic('released', 1, 1, release=True)
                run.release_holds.assert_called_once_with(['n01'])
                send.assert_not_called()

    def test_refund_count_requires_exact_original_one_sat_coins(self):
        client = {'settled_refunds': {str(i): {'proofs_json': json.dumps([{'amount': 1}] * CAPACITY)}
                                      for i in range(15)}}
        channels = set(client['settled_refunds'])
        self.assertEqual(refund_count(client, channels), 480)
        for coins in ([{'amount': 2}] * 16, [{'amount': 1}] * 31,
                      [{'amount': 0}] + [{'amount': 1}] * 31):
            changed = copy.deepcopy(client)
            changed['settled_refunds']['0']['proofs_json'] = json.dumps(coins)
            with self.subTest(coins=coins[:1]), self.assertRaises(RuntimeError):
                refund_count(changed, channels)
        with self.assertRaises(RuntimeError):
            refund_count(client, channels - {'0'})

    def test_each_maintenance_fence_blocks_final_settlement(self):
        self.assertTrue(maintenance_idle({'history': {}}))
        for history in ({'pending': {'x': 1}}, {'channels': {'pending': {'x': 1}}},
                        {'seller': {'pending': {'x': 1}}}):
            self.assertFalse(maintenance_idle({'history': history}))
        run = object.__new__(LiveRetirementRun)
        run.held_nodes, run.retirement_started = ['n01'], True
        run.release_holds, run.old_retired, run.ctl = Mock(), Mock(), Mock()
        with patch('sim.wifi_retirement_live.eventually', side_effect=RuntimeError('still pending')):
            with self.assertRaisesRegex(RuntimeError, 'still pending'):
                run.close()
        run.release_holds.assert_called_once_with(['n01'])
        run.ctl.assert_not_called()

    def test_opt_in_profile_uses_ordinary_forwarding_and_owned_mint_pacing(self):
        run = object.__new__(LiveRetirementRun)
        base = {'terms': {'controller': {}}, 'return_allowance': False}
        mint = SimpleNamespace(settings={'max_issued_sat': 384})
        with patch('sim.wifi_retirement.RetirementRun.profile_config', return_value=base), \
                patch('sim.wifi_retirement.RetirementRun.create_mint', return_value=mint):
            config = run.profile_config(None)
            self.assertEqual(config['terms']['billing'], 'forwarding_data')
            self.assertEqual(config['terms']['controller']['channel_lifetime_secs'], 900)
            self.assertEqual(config['terms']['controller']['max_wallet_spend_sat'], 128)
            self.assertEqual(config['terms']['wallet_capacity_bytes'], 64 * 1024 * 1024)
            self.assertEqual(config['funding_request_budget'], {'burst': 128, 'requests_per_minute': 60_000})
            self.assertFalse(config['return_allowance'])
            self.assertIs(run.create_mint(SimpleNamespace(mint_host='configured')), mint)
            self.assertEqual(mint.settings, {'max_issued_sat': 384, 'fragmented_channel_keyset': True})
        with patch('sim.wifi_retirement.RetirementRun.create_mint') as create:
            with self.assertRaisesRegex(RuntimeError, 'requires --mint-host'):
                run.create_mint(SimpleNamespace(mint_host=None))
            create.assert_not_called()


if __name__ == '__main__':
    unittest.main()
