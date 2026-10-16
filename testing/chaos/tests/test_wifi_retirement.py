"""Reject false retirement overlap and preserve the ordinary settlement boundary."""

import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_retirement_renewal import RenewalRetirementRun, unchanged_pending
from sim.wifi_retirement_live import (ACTIVE_LEAD, CAPACITY, HOLD_LEAD, HOLD_SECONDS,
                                     LIFETIME, MAX_SPREAD, RELEASE_MARGIN, RELEASE_WINDOW,
                                     RUN_WINDOW, LiveRetirementRun, deadlines,
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
        last = 1200 + MAX_SPREAD
        intents = {'first': {'refund_after_unix': 1200}, 'last': {'refund_after_unix': last}}
        self.assertEqual(deadlines(intents, 1099), (1200, last))
        for now, last in ((1100, last), (1099, last + 1)):
            with self.subTest(now=now, last=last), self.assertRaises(RuntimeError):
                deadlines({**intents, 'last': {'refund_after_unix': last}}, now)
        # Production service admission lasts half the immutable funding lifetime.
        self.assertGreaterEqual(LIFETIME // 2 - ACTIVE_LEAD,
                                MAX_SPREAD + RELEASE_WINDOW + RELEASE_MARGIN)
        self.assertGreaterEqual(HOLD_SECONDS, MAX_SPREAD + HOLD_LEAD + 1 + 45 + 38 + 8)
        self.assertLessEqual(HOLD_SECONDS, 420)
        self.assertGreaterEqual(RUN_WINDOW, LIFETIME + MAX_SPREAD + RELEASE_WINDOW + 540)

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
        run.nodes = {'n01': object()}
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
            self.assertEqual(config['terms']['controller']['channel_lifetime_secs'], LIFETIME)
            self.assertEqual(config['terms']['quote_lifetime_secs'], LIFETIME // 2)
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


class RenewalRetirementTests(unittest.TestCase):
    @staticmethod
    def pending_state():
        return dict(local=[1], epoch=7, policy={'max_wallet_spend_sat': 128},
                    funding={'original': {'funded': {'terms': {'id': 'active', 'capacity_sat': 32}}}},
                    next_funding=17, renewals={}, renewals_paused=False,
                    buyer_settlements={},
                    history={'channels': {'pending': {'after': {'through': 15}}}})

    def test_due_retirement_preserves_exact_funding_and_renewal_authority(self):
        original = self.pending_state()
        unchanged_pending(original, copy.deepcopy(original))
        for key, value in (('local', [2]), ('epoch', 8), ('policy', {}),
                           ('funding', {}), ('next_funding', 18),
                           ('renewals', {'active': {}}), ('renewals_paused', True),
                           ('history', {'channels': {'pending': None}})):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                unchanged_pending(original, {**original, key: value})
        with self.assertRaises(RuntimeError):
            unchanged_pending({**original, 'history': {}}, {**original, 'history': {}})

    def test_renewal_profile_only_enables_original_buyer_without_raising_limits(self):
        run = object.__new__(RenewalRetirementRun)
        run.nodes = {name: object() for name in ('n01', 'n02', 'n03')}
        base = {'terms': {'controller': {'renewal': None, 'max_locked_sat': 64,
                'max_wallet_spend_sat': 128, 'channel_capacity_sat': 32}}}
        with patch.object(LiveRetirementRun, 'profile_config', side_effect=lambda node: copy.deepcopy(base)):
            for name, node in run.nodes.items():
                profile = run.profile_config(node)
                expected = copy.deepcopy(base)
                if name == 'n01':
                    expected['terms']['controller']['renewal'] = {'at_capacity_percent': 5,
                                                                  'before_expiry_secs': 1}
                self.assertEqual(profile, expected)

    def test_due_samples_reject_changed_plan_and_keep_existing_payment_checks(self):
        run = object.__new__(RenewalRetirementRun)
        run.renewal_before = self.pending_state()
        run.active = 'active'
        run.due_required = True
        run.journal = Mock(return_value=copy.deepcopy(run.renewal_before))
        state = dict(purchases=[{'channel': {'id': 'active', 'capacity_sat': 32}}],
                     remaining_budget_sat=254, payment_progress={'active': {'authorized_sat': 2}})
        run.ctl = Mock(return_value=state)
        row = dict(plan='same', authorized_sat=2, credited_msat=2000, delivered=3)
        with patch.object(LiveRetirementRun, 'sample', return_value=row) as sample:
            observed = run.sample({}, True)
            self.assertEqual({key: observed[key] for key in row}, row)
            self.assertEqual(observed['predecessor']['before'], observed['predecessor']['after'])
            self.assertEqual(observed['predecessor']['before']['selected_channel'], 'active')
            sample.assert_called_once_with({}, True)
            with self.assertRaisesRegex(RuntimeError, 'not due'):
                sample.return_value = {**row, 'authorized_sat': 1}
                run.sample({}, True)
            sample.return_value = row
            run.journal.side_effect = [copy.deepcopy(run.renewal_before),
                                      {**run.renewal_before, 'next_funding': 18}]
            with self.assertRaisesRegex(RuntimeError, 'renewal authority'):
                run.sample({}, True)
            run.journal.side_effect = None
            for changed in ({**state, 'purchases': []}, {**state, 'remaining_budget_sat': 256},
                            {**state, 'purchases': [{'channel': {'id': 'other', 'capacity_sat': 32}}]}):
                run.ctl.return_value = changed
                with self.subTest(state=changed), self.assertRaisesRegex(RuntimeError, 'selected predecessor'):
                    run.sample({}, True)
            run.ctl.return_value = state
            run.journal.return_value['buyer_settlements']['active'] = {'refunded': False}
            with self.assertRaisesRegex(RuntimeError, 'selected predecessor'):
                run.sample({}, True)

    def test_successor_rejects_duplicate_or_replaced_funding_and_changed_lifetime_totals(self):
        run = object.__new__(RenewalRetirementRun)
        run.active, run.predecessor_paid, run.released_unix = 'active', 4, 999
        run.renewal_before = self.pending_state()
        original = run.renewal_before['funding']['original']
        original.update(provider='provider', receiver_pubkey_hex='receiver', grace_msat=8000)
        terms = original['funded']['terms']
        intent = dict(id='successor-funding', provider='provider', receiver_pubkey_hex='receiver',
                      grace_msat=8000, capacity_sat=32, max_wallet_debit_sat=32,
                      created_unix=1000, expires_unix=1660, refund_after_unix=2320, funded=None)
        current = copy.deepcopy(run.renewal_before)
        current['history']['channels']['pending'] = None
        current['next_funding'] = 18
        current['funding'][intent['id']] = intent
        renewal = {'preopening': {'funding_id': intent['id']}, 'completed': False}
        current['renewals']['active'] = renewal
        run.successor_authority = None
        run.journal = Mock(return_value=current)
        self.assertIsNone(run.successor())
        self.assertEqual(run.successor_authority['id'], intent['id'])
        report = dict(channel_id='active', value_after_stage1_sat=32, paid_sat=4,
                      receiver_fee_reserve_sat=0, refunded_sat=28, fee_sat=0)
        current['buyer_settlements']['active'] = dict(refunded=True, channel=terms,
                                                     report=report, wallet_refund_sat=28)
        successor = {'channel': {'id': 'successor', 'capacity_sat': 32}}
        intent['funded'] = {'terms': successor['channel']}
        renewal['completed'] = True
        state = dict(purchases=[successor], remaining_budget_sat=252,
                     funding_budget=dict(wallet_debited_sat=544, wallet_refunded_sat=508,
                                         locked_sat=32, exposure_sat=36, pending_reserved_sat=0))
        run.ctl = Mock(return_value=state)
        self.assertEqual(run.successor(), (successor, report, current))
        # Each mutation retains the other genuine successor/refund evidence.
        for field, value in (('next_funding', 19), ('policy', {}),
                             ('funding', {**current['funding'], 'duplicate': copy.deepcopy(intent)})):
            run.journal.return_value = {**current, field: value}
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                run.successor()
        changed = copy.deepcopy(current)
        changed['funding'][intent['id']].update(created_unix=1001, expires_unix=1661,
                                               refund_after_unix=2321)
        run.journal.return_value = changed
        with self.assertRaisesRegex(RuntimeError, 'reservation was replaced'):
            run.successor()
        run.journal.return_value = current
        for field, value in (('wallet_debited_sat', 576), ('wallet_refunded_sat', 512),
                             ('pending_reserved_sat', 32), ('exposure_sat', 32)):
            run.ctl.return_value = {**state, 'funding_budget': {**state['funding_budget'], field: value}}
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'spending totals'):
                run.successor()

    def test_cleanup_pauses_automatic_funding_after_releasing_writer(self):
        run = object.__new__(RenewalRetirementRun)
        run.renewal_resumed, run.held_nodes = True, ['n01']
        calls = []
        run.release_holds = Mock(side_effect=lambda nodes: calls.append('release'))
        run.ctl = Mock(side_effect=lambda *args, **kwargs: calls.append(args[1]))
        with patch.object(LiveRetirementRun, 'close', side_effect=lambda: calls.append('close')):
            run.close()
        self.assertEqual(calls, ['release', 'pause_renewals', 'close'])


if __name__ == '__main__':
    unittest.main()
