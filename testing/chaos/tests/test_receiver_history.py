"""Bookkeeping only: original request recovery, bounded setup and custody release."""
import copy
import json
import unittest
from unittest.mock import Mock, patch

from sim.receiver_history import circulate, WALLET_BYTES, HEADROOM


class Wallet:
    def __init__(self, mint, name, balance):
        self.mint, self.name, self.balance = mint, name, balance
        self.state = '/' + name
        self.exports, self.received = {}, set()
        self.floor = 0
        self.fail_receive = None
        self.collection_pages = 0
        self.recovered = False

    def remote(self, command):
        number = int(command[1].rsplit('/', 1)[1].removesuffix('.json'))
        return json.dumps(dict(token=self.exports[number], amount_sat=1)).encode()

    def control(self, kind, *, action, **fields):
        assert action == 'wallet'
        if kind == 'balance':
            return dict(balance_sat=self.balance)
        if kind == 'export':
            self.recovered = False
            number = fields['id']
            assert number > self.floor
            if number not in self.exports:
                assert self.balance == fields['amount_sat'] or self.balance > fields['amount_sat']
                self.balance -= fields['amount_sat']
                token = f'{self.name}/{number}'
                assert token not in self.mint
                self.mint[token] = None
                self.exports[number] = token
            return dict(path=self.state + f'/exports/{number}.json')
        if kind == 'import':
            token = fields['token']
            assert self.mint[token] in (None, self.name)
            if token not in self.received:
                self.mint[token] = self.name
                self.received.add(token)
                self.balance += 1
                if self.fail_receive == len(self.received):
                    self.fail_receive = None
                    raise RuntimeError('original import committed but reply was lost')
            return dict(amount_sat=1)
        if kind == 'recover':
            assert all(self.mint[token] is not None for token in self.exports.values())
            self.recovered = True
            return dict(recovery_pass_complete=True, minted_amount=0, finalized_melts=0, warning_count=0)
        assert kind == 'acknowledge_exports'
        through = fields['through']
        for number, token in list(self.exports.items()):
            if number <= through:
                assert self.mint[token] is not None, 'cannot acknowledge an undelivered original'
                del self.exports[number]
        self.floor = through
        self.collection_pages = max(0, self.collection_pages - 1)
        return dict(requested_sat=through, cost=dict(wallet_debit_sat=through, swap_fee_sat=0))


class ReceiverHistoryTests(unittest.TestCase):
    def run_history(self, count, *, lost_reply=None, capacity_after=None, delayed_collection=0,
                    setup_seconds=3600, before_recovery=None):
        mint, evidence = {}, []
        wallets = [Wallet(mint, 'donor', 2048), Wallet(mint, 'receiver', 0)]
        wallets[1].fail_receive = lost_reply
        returned = False

        def observe():
            nonlocal returned
            receipts = len(wallets[1].received)
            if receipts and wallets[1].balance == 0 and not returned:
                returned = True
                wallets[1].collection_pages = delayed_collection
            charged = 1000 + 1000 * receipts
            if capacity_after is not None and receipts >= capacity_after:
                charged = WALLET_BYTES - HEADROOM + 1
            return dict(receipts=receipts, incomplete_operations=0, proof_rows=receipts,
                        capacity_bytes=WALLET_BYTES, charged_bytes=charged,
                        unowned_proof_rows=wallets[1].collection_pages + int(
                            receipts > 0 and wallets[1].balance == 0 and not wallets[1].recovered))

        error = None
        try:
            result = circulate(wallets, observe, lambda row: evidence.append(copy.deepcopy(row)), count,
                               setup_seconds=setup_seconds, before_recovery=before_recovery)
        except RuntimeError as failure:
            error, result = str(failure), None
        self.assertEqual([p.balance for p in wallets], [2048, 0])
        self.assertTrue(all(not p.exports for p in wallets))
        self.assertTrue(all(owner is not None for owner in mint.values()))
        self.assertIsNone(evidence[-1]['pending'])
        self.assertTrue(evidence[-1]['returned_original_value'])
        return result, error, evidence, wallets

    def test_receipts_span_acknowledgement_batches_without_new_issued_value(self):
        result, error, evidence, wallets = self.run_history(137, delayed_collection=2)
        self.assertIsNone(error)
        self.assertEqual(result['rows'], 137)
        self.assertEqual(wallets[1].floor, 137)
        self.assertEqual(len(wallets[1].received), 137)
        self.assertEqual(evidence[-1]['final']['receipts'], 137)
        self.assertEqual(evidence[-1]['collection_passes'], 2)
        self.assertTrue(evidence[-1]['native_recovery']['recovery_pass_complete'])

    def test_lost_import_reply_recovers_same_original_and_still_fails_setup(self):
        wait = Mock()
        result, error, evidence, wallets = self.run_history(10, lost_reply=3, before_recovery=wait)
        wait.assert_called_once_with()
        self.assertIsNone(result)
        self.assertIn('failed after returning', error)
        self.assertEqual(len(wallets[1].received), 3)
        self.assertEqual(wallets[1].floor, 3)
        self.assertIn('reply was lost', evidence[-1]['error'])

    def test_capacity_stop_returns_value_without_accepting_a_smaller_workload(self):
        result, error, evidence, wallets = self.run_history(137, capacity_after=65)
        self.assertIsNone(result)
        self.assertIn('four MiB', error)
        self.assertEqual(len(wallets[1].received), 65)
        self.assertEqual(evidence[-1]['requested_receipts'], 137)

    def test_setup_deadline_returns_original_value_and_keeps_required_workload(self):
        with patch('sim.receiver_history.time.monotonic', side_effect=range(100)):
            result, error, evidence, _ = self.run_history(10, setup_seconds=1)
        self.assertIsNone(result)
        self.assertIn('time budget', error)
        self.assertEqual(evidence[-1]['setup_limit_seconds'], 1)
        self.assertEqual(evidence[-1]['completed_receives'], 1)
        self.assertEqual(evidence[-1]['requested_receipts'], 10)


if __name__ == '__main__':
    unittest.main()
