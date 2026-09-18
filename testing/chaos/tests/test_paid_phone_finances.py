"""Synthetic source-schema fixtures; no device access or bearer proofs."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_phone_finances import validate_settled, check_mint

EDGES = [('phone', 'n01'), ('n01', 'n02'), ('n03', 'n02'), ('n02', 'n01')]


def address(name):
    return [0] * 15 + [('phone', 'n01', 'n02', 'n03').index(name) + 1]


def fixture():
    mint = {'test_only': True, 'conserved': True, 'url': 'http://test.invalid:3338',
            'issued_sat': 512, 'external_funding_sat': 512, 'total_accounted_sat': 512,
            'collected_sat': 0}
    before = {}
    for name in ('phone', 'n01', 'n02', 'n03'):
        before[name] = {
            'controller': {'local': address(name), 'policy': {'max_wallet_spend_sat': 64},
                           'history': None, 'funding': {}, 'buyer_settlements': {}, 'seller_settlements': {}},
            'buyer': {'local': address(name), 'total_budget_sat': 64, 'history': None, 'channels': {}},
            'seller': {'ledger': {'history': None, 'channels': []}},
        }
    for index, (owner, provider) in enumerate(EDGES):
        channel = 'channel-' + owner
        terms = {'id': channel, 'buyer': address(owner), 'mint_url': mint['url'],
                 'capacity_sat': 32, 'expires_unix': 2_000_000_000, 'grace_msat': 8_000}
        funded = {'terms': terms, 'opening': {'channel_id': channel, 'balance': 0},
                  'wallet_operation_id': 'operation-' + owner,
                  'wallet_cost': {'token_amount_sat': 32, 'wallet_debit_sat': 32, 'swap_fee_sat': 0}}
        before[owner]['controller']['funding']['fund-' + owner] = {
            'id': 'fund-' + owner, 'provider': address(provider), 'capacity_sat': 32,
            'max_wallet_debit_sat': 32, 'expires_unix': terms['expires_unix'],
            'grace_msat': 8_000, 'funded': funded}
        before[owner]['buyer']['channels'][channel] = {
            'terms': terms, 'provider': address(provider), 'authorized_sat': index + 1}
        before[provider]['seller']['ledger']['channels'].append({
            'terms': terms, 'usage': {'paid_msat': (index + 1)*1000}})
    after = copy.deepcopy(before)
    balances = {name: 96 for name in before}
    for index, (owner, provider) in enumerate(EDGES):
        channel = 'channel-' + owner
        paid = index + 2
        report = {'channel_id': channel, 'value_after_stage1_sat': 32, 'paid_sat': paid,
                  'receiver_fee_reserve_sat': 0, 'refunded_sat': 32-paid, 'fee_sat': 0}
        terms = after[owner]['buyer']['channels'][channel]['terms']
        payment = {'channel_id': channel, 'balance': paid}
        # Sealed paid credit may precede the final signed amount legitimately.
        usage = {'paid_msat': (paid-1)*1000}
        after[owner]['controller']['buyer_settlements'][channel] = {
            'kind': 'cooperative', 'provider': address(provider), 'channel': terms,
            'usage': usage, 'payment': payment, 'report': report,
            'released': True, 'refunded': True, 'wallet_refund_sat': 32-paid}
        after[provider]['controller']['seller_settlements'][channel] = {
            'channel': terms, 'usage': usage, 'payment': payment, 'report': report, 'released': True}
        after[owner]['buyer']['channels'][channel]['authorized_sat'] = paid
        next(row for row in after[provider]['seller']['ledger']['channels']
             if row['terms']['id'] == channel)['usage']['paid_msat'] = paid*1000
        balances[owner] += 32-paid
        balances[provider] += paid
    return after, before, balances, mint, copy.deepcopy(EDGES)


class PaidPhoneFinanceTests(unittest.TestCase):
    def test_complete_four_account_roundtrip(self):
        args = fixture()
        result = validate_settled(*args)
        self.assertEqual(result['total_wallet_sat'], 512)
        self.assertEqual(len(result['settlements']), 4)
        self.assertEqual(result['accounts']['phone']['seller_received_sat'], 0)
        self.assertEqual(result['accounts']['n01']['seller_received_sat'], 7)
        self.assertEqual(result['accounts']['n02']['seller_received_sat'], 7)
        self.assertNotIn('payment', repr(result))

    def test_normalized_ledger_and_distinct_original_budgets(self):
        args = fixture()
        for snapshots in args[:2]:
            snapshots['phone']['buyer']['total_budget_sat'] = 128
            for state in snapshots.values():
                state['seller'] = state['seller']['ledger']
        result = validate_settled(*args)
        self.assertEqual(result['accounts']['phone']['buyer_budget_sat'], 128)

    def test_actual_nodeaddr_schema_rejects_wrong_shape(self):
        for bad in ('addr-phone', [0]*15, [0]*17, [0]*15+[256], [0]*15+[-1], [0]*15+[True]):
            with self.subTest(shape=type(bad).__name__):
                args = fixture()
                args[0]['phone']['controller']['local'] = bad
                with self.assertRaises(RuntimeError):
                    validate_settled(*args)

    def test_missing_terminal_evidence(self):
        for field, value in [('released', False), ('refunded', False), ('wallet_refund_sat', None),
                             ('usage', None), ('payment', None), ('report', None), ('kind', 'expiry')]:
            with self.subTest(field=field):
                args = fixture()
                args[0]['phone']['controller']['buyer_settlements']['channel-phone'][field] = value
                with self.assertRaises(RuntimeError):
                    validate_settled(*args)

    def test_seller_release_and_matching_report_required(self):
        for field, value in [('released', False), ('report', {}), ('payment', None)]:
            with self.subTest(field=field):
                args = fixture()
                args[0]['n01']['controller']['seller_settlements']['channel-phone'][field] = value
                with self.assertRaises(RuntimeError):
                    validate_settled(*args)

    def test_original_channel_and_wallet_operation_identity(self):
        for field, value in [('wallet_operation_id', 'changed'), ('terms', {})]:
            with self.subTest(field=field):
                args = fixture()
                args[0]['phone']['controller']['funding']['fund-phone']['funded'][field] = value
                with self.assertRaises(RuntimeError):
                    validate_settled(*args)
        args = fixture()
        for snapshots in args[:2]:
            snapshots['phone']['controller']['funding']['fund-phone']['funded']['wallet_operation_id'] = 'operation-n01'
        with self.assertRaises(RuntimeError):
            validate_settled(*args)

    def test_lifetime_budget_reset_rejected(self):
        args = fixture()
        args[0]['phone']['buyer']['total_budget_sat'] += 1
        with self.assertRaises(RuntimeError):
            validate_settled(*args)

    def test_credit_missing_or_duplicate_rejected(self):
        for mode in ('credit', 'duplicate', 'missing'):
            with self.subTest(mode=mode):
                args = fixture()
                rows = args[0]['n01']['seller']['ledger']['channels']
                if mode == 'credit':
                    rows[0]['usage']['paid_msat'] -= 1
                elif mode == 'duplicate':
                    rows.append(copy.deepcopy(rows[0]))
                else:
                    rows.pop()
                with self.assertRaises(RuntimeError):
                    validate_settled(*args)

    def test_per_wallet_equation_not_only_global_total(self):
        args = fixture()
        args[2]['phone'] -= 1
        args[2]['n01'] += 1
        with self.assertRaises(RuntimeError):
            validate_settled(*args)

    def test_wrong_participant_edges_or_extra_account(self):
        for mode in ('edge', 'duplicate', 'extra'):
            with self.subTest(mode=mode):
                args = fixture()
                if mode == 'edge':
                    args[4][0] = ('phone', 'n03')
                elif mode == 'duplicate':
                    args[4][0] = args[4][1]
                else:
                    args[0]['unknown'] = copy.deepcopy(args[0]['phone'])
                with self.assertRaises(RuntimeError):
                    validate_settled(*args)

    def test_mint_all_accounting_fields_and_scope(self):
        for field, value in [('test_only', False), ('conserved', False), ('issued_sat', 511),
                             ('external_funding_sat', 511), ('total_accounted_sat', 511),
                             ('collected_sat', 1), ('url', 'http://other.invalid')]:
            with self.subTest(field=field):
                args = fixture()
                args[3][field] = value
                with self.assertRaises(RuntimeError):
                    validate_settled(*args)
        report = fixture()[3]
        report['collected_sat'] = 512
        check_mint(report, 512)

    def test_invalid_money_and_unaccounted_history(self):
        for bad in (True, -1, 1.5, '128', None):
            with self.subTest(bad=bad):
                args = fixture()
                args[2]['phone'] = bad
                with self.assertRaises(RuntimeError):
                    validate_settled(*args)
        args = fixture()
        args[0]['phone']['buyer']['history'] = {'authorized_sat': 1}
        with self.assertRaises(RuntimeError):
            validate_settled(*args)


if __name__ == '__main__':
    unittest.main()
