"""Reject false purchase acceptance and keep auxiliary wallets in collection."""

import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_retirement_live import CAPACITY, LIFETIME, LiveRetirementRun, funding_budget
from sim.wifi_retirement_purchase import PurchaseRetirementRun, completed_purchase, unchanged_purchase


def original():
    return dict(local=[1], epoch=7, policy={'max_wallet_spend_sat': 128}, next_funding=17,
                funding={'active-funding': {'funded': {'terms': {'id': 'active', 'capacity_sat': 32}}}},
                requested={}, outgoing={}, renewals={}, renewals_paused=True,
                watched_routes=[], route_changes=[], buyer_settlements={},
                history={'channels': {'pending': {'after': {'through': 15}}}})


class PurchaseRetirementTests(unittest.TestCase):
    def test_fork_rejects_shortcuts_and_wrong_transport_bindings(self):
        run = object.__new__(PurchaseRetirementRun)
        run.nodes = {name: SimpleNamespace(npub=name) for name in ('n01', 'n02', 'n03')}
        run.extra = {name: SimpleNamespace(npub=name) for name in ('provider', 'destination')}
        run.listeners = dict(n01='192.168.1.1:10', provider='192.168.1.2:20', destination='192.168.1.3:30')
        edges = {'n01': [('n02', 'ethernet'), ('provider', 'udp')],
                 'n02': [('n01', 'ethernet'), ('n03', 'ethernet')], 'n03': [('n02', 'ethernet')],
                 'provider': [('n01', 'udp'), ('destination', 'udp')], 'destination': [('provider', 'udp')]}
        states = {name: dict(npub=name, peers=[dict(npub=other, transport=transport, connected=True,
                  address=run.listeners.get(other)) for other, transport in peers]) for name, peers in edges.items()}
        run.ctl = Mock(side_effect=lambda name, command: states[name])
        self.assertEqual(run.fork_ready(), states)
        states['n01']['peers'].append(dict(npub='destination', transport='udp', connected=True))
        self.assertIsNone(run.fork_ready())
        states['n01']['peers'].pop()
        states['provider']['peers'][0]['address'] = '192.168.1.99:10'
        with self.assertRaisesRegex(RuntimeError, 'listener changed'):
            run.fork_ready()

    def test_rejected_purchase_preserves_funding_routes_and_exact_pending_plan(self):
        before = original()
        unchanged_purchase(before, copy.deepcopy(before))
        for field, value in (('funding', {}), ('next_funding', 18), ('requested', {'new': {}}),
                             ('outgoing', {'new': {}}), ('renewals', {'new': {}}),
                             ('watched_routes', ['new']), ('route_changes', ['new']),
                             ('policy', {}), ('history', {'channels': {'pending': None}})):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                unchanged_purchase(before, {**before, field: value})
        before['history']['channels']['pending'] = None
        with self.assertRaises(RuntimeError):
            unchanged_purchase(before, before)

    def test_completed_purchase_needs_one_distinct_provider_and_exact_budget(self):
        before = original()
        current = copy.deepcopy(before)
        current['history']['channels']['pending'] = None
        current['next_funding'] = 18
        provider = '02' * 16
        terms = {'id': 'new', 'capacity_sat': 32}
        intent = dict(id='new-funding', capacity_sat=32, max_wallet_debit_sat=32, created_unix=1000,
                      expires_unix=1000 + LIFETIME // 2, refund_after_unix=1000 + LIFETIME,
                      provider=[2] * 16, funded={'terms': terms})
        current['funding']['new-funding'] = intent
        state = dict(funding_budget=funding_budget(CAPACITY), purchases=[
            {'channel': before['funding']['active-funding']['funded']['terms'], 'provider': [1] * 16},
            {'channel': terms, 'provider': [2] * 16}])
        self.assertEqual(completed_purchase(before, current, state, 'active', provider, 1000)[0], 'new-funding')
        mutations = [
            lambda c, s: c.update(next_funding=19),
            lambda c, s: c['funding'].update(duplicate=copy.deepcopy(intent)),
            lambda c, s: c['funding']['active-funding'].update(replaced=True),
            lambda c, s: c.update(policy={}),
            lambda c, s: c['buyer_settlements'].update(active={}),
            lambda c, s: c['history']['channels'].update(pending={'after': {'through': 15}}),
            lambda c, s: c['funding']['new-funding'].update(created_unix=999),
            lambda c, s: c['funding']['new-funding'].update(max_wallet_debit_sat=64),
            lambda c, s: s['purchases'][0].update(provider=[2] * 16),
            lambda c, s: s['funding_budget'].update(wallet_debited_sat=576),
        ]
        for index, mutate in enumerate(mutations):
            c, s = copy.deepcopy(current), copy.deepcopy(state)
            mutate(c, s)
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                completed_purchase(before, c, s, 'active', provider, 1000)

    def test_refusal_requires_fresh_exact_error_and_unchanged_spending(self):
        with tempfile.TemporaryDirectory() as directory:
            run = object.__new__(PurchaseRetirementRun)
            run.nodes = {'n01': SimpleNamespace(output=Path(directory), held=Mock(return_value=True))}
            run.extra = {'destination': SimpleNamespace(npub='new-destination')}
            run.active, run.purchase_before = 'active', original()
            run.journal = Mock(side_effect=lambda: copy.deepcopy(run.purchase_before))
            run.save = Mock()
            run.evidence = {'fragmented': {'purchase': {'rejected': []}}}
            state = dict(funding_budget=funding_budget(), purchases=[{'channel': {'id': 'active'}}],
                         remaining_budget_sat=254, payment_progress={'active': {'authorized_sat': 2}})
            def control(name, kind, **fields):
                if kind == 'buy':
                    (Path(directory) / 'last-error.txt').write_bytes(b'fips-relay: controller journal suspended\n')
                    raise RuntimeError('remote failure')
                return state
            run.ctl = Mock(side_effect=control)
            run.reject_purchase()
            self.assertEqual(len(run.evidence['fragmented']['purchase']['rejected']), 1)
            run.ctl = Mock(side_effect=RuntimeError('no new diagnostic'))
            with self.assertRaisesRegex(RuntimeError, 'expected maintenance refusal'):
                run.reject_purchase()
            run.ctl = Mock(side_effect=control)
            state['funding_budget']['pending_reserved_sat'] = 32
            with self.assertRaisesRegex(RuntimeError, 'spending'):
                run.reject_purchase()

    def test_auxiliary_profiles_start_empty_without_grants(self):
        run = object.__new__(PurchaseRetirementRun)
        run.nodes = {name: object() for name in ('n01', 'n02', 'n03')}
        run.extra = {name: Mock(state=name, npub=name) for name in ('provider', 'destination')}
        run.mint_url, run.evidence = 'http://owned-mint', {}
        for profile in run.extra.values():
            profile.control.return_value = dict(mint_url=run.mint_url, unit='sat', balance_sat=0)
        run.udp_config = Mock(return_value={'bind_addr': '192.168.1.2:0'})
        base = {'terms': {}, 'transports': {}}
        with patch.object(LiveRetirementRun, 'profile_config', side_effect=lambda node: copy.deepcopy(base)), \
                patch.object(LiveRetirementRun, 'before_launch') as fund:
            run.before_launch()
            fund.assert_called_once_with()
            for name, profile in run.extra.items():
                profile.control.assert_called_once_with('balance', action='wallet')
                self.assertEqual(profile.prepare.call_args.args[0]['state_directory'], name)
            self.assertEqual(run.initial_balances(), dict(n01=128, n02=128, n03=128, provider=0, destination=0))
            self.assertEqual(set(run.participants()), set(run.initial_balances()))
            run.extra['provider'].control.return_value['balance_sat'] = 1
            fund.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'initial funds'):
                run.before_launch()
            fund.assert_not_called()

    def test_collection_includes_both_zero_funded_profiles_and_the_actual_provider(self):
        run = object.__new__(PurchaseRetirementRun)
        run.nodes = {name: Mock() for name in ('n01', 'n02', 'n03')}
        run.extra = {name: Mock() for name in ('provider', 'destination')}
        terms = {'id': 'new', 'capacity_sat': 32}
        intent = {'funded': {'terms': terms}}
        report = dict(channel_id='new', value_after_stage1_sat=32, paid_sat=2,
                      refunded_sat=30, fee_sat=0, receiver_fee_reserve_sat=0)
        run.intents, run.reports, run.providers = {'new': intent}, {}, {'new': 'provider'}
        run.held_nodes, run.old, run.retirement_started = [], set(), False
        run.release_holds, run.phase, run.account_execute = Mock(), Mock(), Mock()
        run.evidence, run.mint_url = {'phases': []}, 'http://owned-mint'
        def journal(name='n01'):
            return dict(funding={'new-funding': intent} if name == 'n01' else {},
                        buyer_settlements={'new': {}} if name == 'n01' else {},
                        seller_settlements={'new': {'released': True, 'report': report}}
                            if name == 'provider' else {}, history={})
        run.journal = Mock(side_effect=journal)
        def control(name, kind):
            if kind == 'settle':
                return {'settlements': [report] if name == 'n01' else []}
            return dict(funding_budget=dict(wallet_debited_sat=32, wallet_refunded_sat=30,
                        locked_sat=0, pending_reserved_sat=0, exposure_sat=2), remaining_budget_sat=254)
        run.ctl = Mock(side_effect=control)
        with patch('sim.wifi_retirement_live.verified_refund', return_value=report), \
                patch('sim.wifi_retirement_live.financial_snapshot', return_value={}), \
                patch('sim.wifi_retirement_live.collect_settled_wallets') as collect:
            run.close()
        view = collect.call_args.args[0]
        self.assertEqual(set(view.nodes), {'n01', 'n02', 'n03', 'provider', 'destination'})
        fixture = collect.call_args.kwargs['fixture']
        self.assertEqual(dict(fixture.channel_providers), {'new': 'provider'})
        self.assertEqual(dict(fixture.initial_balances), run.initial_balances())


if __name__ == '__main__':
    unittest.main()
