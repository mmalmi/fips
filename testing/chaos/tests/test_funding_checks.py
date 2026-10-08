"""Funding acceptance must reject altered authority and duplicate SDK operations."""

import copy
import unittest

from sim.funding_checks import PendingFunding


def operation(*, preparing=False, renewal=False):
    original = ({'open_requests': {'old-request': 'old-channel'}, 'funding': {'old-channel': {'saved': True}},
                 'openings': {'r:old-request': {'saved': True}}} if renewal else {})
    pending = {key: copy.deepcopy(original.get(key, {})) for key in ('open_requests', 'funding', 'openings')}
    request = {'client_request_id': 'request'}
    opening = {'request': request, 'channel_id': 'channel', 'wallet_send': {'operation_id': 'wallet-operation'}}
    if preparing:
        pending['admissions'] = {'request': {'request': request, 'funding_started': True}}
    else:
        pending['openings']['r:request'] = opening
    intent = dict(id='request', capacity_sat=32, max_wallet_debit_sat=32, grace_msat=8000,
                  expires_unix=1000, refund_after_unix=1100, funded=None)
    current = copy.deepcopy(intent)
    current['funded'] = dict(terms=dict(id='channel', buyer='buyer', mint_url='mint', capacity_sat=32,
                                      grace_msat=8000, expires_unix=1000, refund_after_unix=1100),
                            wallet_operation_id='wallet-operation',
                            wallet_cost=dict(token_amount_sat=32, wallet_debit_sat=32, swap_fee_sat=0))
    recovered = copy.deepcopy(pending)
    recovered['admissions'] = {}
    recovered['openings']['r:request'] = opening
    recovered['open_requests']['request'] = 'channel'
    recovered['funding']['channel'] = {'saved': True}
    return PendingFunding('request', intent, original, pending), current, recovered


class PendingFundingTests(unittest.TestCase):
    def test_first_and_successor_operations_recover_both_durable_stages(self):
        for preparing in (False, True):
            for renewal in (False, True):
                with self.subTest(preparing=preparing, renewal=renewal):
                    held, current, recovered = operation(preparing=preparing, renewal=renewal)
                    held.unchanged(copy.deepcopy(held.pending))
                    self.assertEqual(held.recovered(current, recovered, buyer='buyer', mint='mint'), 'channel')

    def test_pending_operation_is_bound_to_one_started_request(self):
        for change in ('not-started', 'other-request', 'extra-request', 'both-stages'):
            with self.subTest(change=change):
                held, _, _ = operation(preparing=True)
                pending = copy.deepcopy(held.pending)
                admission = pending['admissions']['request']
                if change == 'not-started':
                    admission['funding_started'] = False
                elif change == 'other-request':
                    admission['request']['client_request_id'] = 'different'
                elif change == 'extra-request':
                    pending['admissions']['extra'] = copy.deepcopy(admission)
                else:
                    pending['openings']['r:request'] = {'unexpected': True}
                with self.assertRaises(RuntimeError):
                    PendingFunding('request', held.intent, held.original, pending)

    def test_restart_cannot_drop_or_replace_pending_sdk_authority(self):
        held, _, _ = operation()
        for changed in ({}, {**held.pending, 'open_requests': {'other': 'channel'}}):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(RuntimeError, 'pending SDK operation'):
                    held.unchanged(changed)

    def test_recovery_preserves_terms_cost_and_original_wallet_operation(self):
        for change in ('intent', 'cost', 'buyer', 'mint', 'operation'):
            with self.subTest(change=change):
                held, current, recovered = operation()
                if change == 'intent':
                    current['max_wallet_debit_sat'] = 64
                elif change == 'cost':
                    current['funded']['wallet_cost']['wallet_debit_sat'] = 64
                elif change in ('buyer', 'mint'):
                    current['funded']['terms']['buyer' if change == 'buyer' else 'mint_url'] = 'other'
                else:
                    current['funded']['wallet_operation_id'] = 'replacement'
                with self.assertRaises(RuntimeError):
                    held.recovered(current, recovered, buyer='buyer', mint='mint')

    def test_recovery_cannot_duplicate_funding_or_replace_prior_sdk_history(self):
        for field in ('open_requests', 'openings', 'funding'):
            with self.subTest(field=field):
                held, current, recovered = operation(renewal=True)
                recovered[field][next(iter(held.original[field]))] = 'changed'
                with self.assertRaisesRegex(RuntimeError, 'duplicated SDK funding'):
                    held.recovered(current, recovered, buyer='buyer', mint='mint')
                held, current, recovered = operation(renewal=True)
                recovered[field]['duplicate'] = 'unexpected'
                with self.assertRaisesRegex(RuntimeError, 'duplicated SDK funding'):
                    held.recovered(current, recovered, buyer='buyer', mint='mint')


if __name__ == '__main__':
    unittest.main()
