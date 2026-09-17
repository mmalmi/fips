"""Live journal observations retain their shapes, sampling fence and wallet scope."""

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sim.paid_finances import financial_snapshot, payment_progress
from sim.paid_relay import PaidRelayRun


class JournalRun:
    def __init__(self):
        self.nodes = ("n01", "n02", "n03")
        self.events = []
        self.journals = {}
        self.statuses = {}
        self.wallet = Mock(return_value=[["UNSPENT", 1, 96]])
        self.on_read = lambda _node, _relative: None
        for node in self.nodes:
            buyer = node != "n02"
            self.statuses[node] = {
                "remaining_budget_sat": 62 if buyer else 64,
                "funding_budget": {"locked_sat": 32 if buyer else 0},
            }
            self.journals[node] = {
                "buyer/buyer.json": {
                    "total_budget_sat": 64,
                    "channels": {node: {"authorized_sat": 2}} if buyer else {},
                    "quotes": {node: {"submitted_units": 1500, "observed_units": 1490}} if buyer else {},
                },
                "controller/controller.json": {"funding": {
                    **({node: {"funded": {"terms": {"id": node},
                                         "wallet_operation_id": "operation-" + node}}} if buyer else {}),
                    "unfunded": {"funded": None},
                }},
                "seller/ledger.json": {"ledger": {
                    "channels": [] if buyer else [
                        {"terms": {"id": source}, "usage": {"paid_msat": 2000}}
                        for source in ("n01", "n03")],
                    "accounts": [] if buyer else [
                        {"contract": {"id": source},
                         "usage": {"submitted_units": 1500, "unconfirmed_units": 10}}
                        for source in ("n01", "n03")],
                }},
            }

    def ctl(self, node, kind):
        assert kind == "status"
        self.events.append((node, kind))
        return copy.deepcopy(self.statuses[node])

    def state_json(self, node, relative):
        self.events.append((node, relative))
        self.on_read(node, relative)
        return copy.deepcopy(self.journals[node][relative])


class PaidFinanceTests(unittest.TestCase):
    def test_ethernet_keeps_wallet_and_exact_accounting_shapes(self):
        run = JournalRun()
        result = PaidRelayRun.finances(run)
        self.assertEqual(run.wallet.call_count, 3)
        self.assertEqual(result["n01"], {
            "funding": {"n01": ("n01", "operation-n01")},
            "budget": {"locked_sat": 32}, "remaining": 62, "authorized": 2,
            "signed": {"n01": 2}, "signed_after": {"n01": 2},
            "credited": {}, "seller_channels": {},
            "buyer_units": {"n01": 1500}, "buyer_observed_units": {"n01": 1490},
            "seller_units": {}, "seller_unconfirmed_units": {},
            "wallet": [["UNSPENT", 1, 96]],
        })
        self.assertEqual(result["n02"]["credited"], {"n01": 2000, "n03": 2000})
        self.assertEqual(result["n02"]["seller_channels"],
                         {source: {"paid_msat": 2000} for source in ("n01", "n03")})
        self.assertEqual(result["n02"]["seller_units"], {"n01": 1500, "n03": 1500})
        self.assertEqual(result["n02"]["seller_unconfirmed_units"], {"n01": 10, "n03": 10})

    def test_router_explicitly_omits_wallet_without_changing_accounting(self):
        run = JournalRun()
        expected = PaidRelayRun.finances(run)
        for state in expected.values():
            state.pop("wallet")
        run.wallet.reset_mock()
        run.wallet.side_effect = AssertionError("offline wallet must not run")
        self.assertEqual(financial_snapshot(run, wallet=None), expected)
        run.wallet.assert_not_called()

    def test_inconsistent_status_and_buyer_is_rejected(self):
        run = JournalRun()
        run.statuses["n01"]["remaining_budget_sat"] += 1
        with self.assertRaisesRegex(RuntimeError, "changed during sampling"):
            financial_snapshot(run, wallet=run.wallet)
        run.wallet.assert_not_called()

    def test_credit_is_bracketed_by_a_later_durable_authorization(self):
        run = JournalRun()

        def advance(node, relative):
            if (node, relative) == ("n02", "seller/ledger.json"):
                run.journals["n01"]["buyer/buyer.json"]["channels"]["n01"]["authorized_sat"] = 3
                run.journals[node][relative]["ledger"]["channels"][0]["usage"]["paid_msat"] = 3000

        run.on_read = advance
        result = financial_snapshot(run, wallet=None)
        self.assertEqual(result["n01"]["signed"], {"n01": 2})
        self.assertEqual(result["n02"]["credited"]["n01"], 3000)
        self.assertEqual(result["n01"]["signed_after"], {"n01": 3})
        self.assertEqual(run.events[-3:], [(node, "buyer/buyer.json") for node in run.nodes])

    def test_progress_requires_all_sources_and_all_credited_channels(self):
        current = financial_snapshot(JournalRun(), wallet=None)
        prior = {node: {"authorized": 0} for node in current}
        self.assertIs(payment_progress(current, prior), current)
        for credit in (1999, None):
            with self.subTest(credit=credit):
                changed = copy.deepcopy(current)
                if credit is None:
                    changed["n02"]["credited"].pop("n01")
                else:
                    changed["n02"]["credited"]["n01"] = credit
                self.assertIsNone(payment_progress(changed, prior))
        prior["n03"]["authorized"] = 2
        self.assertIsNone(payment_progress(current, prior))
        self.assertIs(payment_progress(current, prior, sources=("n01",)), current)

    def test_ethernet_progress_samples_once_and_keeps_source_selection(self):
        current = financial_snapshot(JournalRun(), wallet=None)
        prior = {node: {"authorized": 2} for node in current}
        prior["n03"]["authorized"] = 0
        run = Mock()
        run.finances.return_value = current
        self.assertIs(PaidRelayRun.paid_after(run, prior, sources=("n03",)), current)
        run.finances.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
