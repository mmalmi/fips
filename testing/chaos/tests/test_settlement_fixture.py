"""Explicit financial fixtures share the existing single-shot collector."""

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import paid_settlement as settlement
from test_paid_settlement import FakeRun, MINT


ACCOUNTS = ("source", "n01", "n02", "n03")


class DiamondRun(FakeRun):
    def __init__(self, channels=2):
        super().__init__()
        self.nodes = dict.fromkeys(ACCOUNTS)
        self.owners = {f"channel-{i}": "source" for i in range(channels)}
        self.providers = {f"channel-{i}": f"n0{i + 1}" for i in range(channels)}
        self.initial = dict.fromkeys(ACCOUNTS, 0)
        self.initial["source"] = 128
        self.budgets = dict.fromkeys(ACCOUNTS, 64)
        self.budgets["source"] = 128
        self.reports = {name: [] for name in ACCOUNTS}
        self.balances = self.initial.copy()
        for i, (channel, owner) in enumerate(self.owners.items()):
            paid = 7 + 4 * i
            self.reports[owner].append({
                "channel_id": channel, "value_after_stage1_sat": 64, "paid_sat": paid,
                "receiver_fee_reserve_sat": 0, "refunded_sat": 64 - paid, "fee_sat": 0,
            })
            self.balances[owner] -= paid
            self.balances[self.providers[channel]] += paid
        self.prior = self.snapshot(settled=False)
        self.settled = self.snapshot(settled=True)

    def snapshot(self, *, settled):
        result = {}
        for name in ACCOUNTS:
            reports = self.reports[name]
            signed = {r["channel_id"]: r["paid_sat"] - (not settled) for r in reports}
            funded = 64 * len(reports)
            refunded = sum(r["refunded_sat"] for r in reports) if settled else 0
            result[name] = {
                "funding": {f"fund-{i}": (channel, f"operation-{i}")
                            for i, channel in enumerate(signed)},
                "signed": signed, "authorized": sum(signed.values()),
                "remaining": self.budgets[name] - sum(signed.values()),
                "budget": {"pending_reserved_sat": 0, "wallet_debited_sat": funded,
                           "wallet_refunded_sat": refunded, "locked_sat": 0 if settled else funded,
                           "exposure_sat": funded - refunded},
                "credited": {},
            }
        for report in self.reports["source"]:
            channel = report["channel_id"]
            result[self.providers[channel]]["credited"][channel] = (
                report["paid_sat"] - (not settled)) * 1000
        return result

    def fixture(self, *, providers=True):
        return settlement.SettlementFixture(
            initial_balances=self.initial, buyer_budgets=self.budgets,
            channel_capacity_sat=64, channel_owners=self.owners,
            channel_providers=self.providers if providers else None,
        )

    def execute(self, node, binary, action, request):
        if request["type"] == "report":
            self.calls.append((node, "report"))
            return self.transform("final_report" if self.collected else "initial_report", {
                "test_only": True, "url": MINT, "issued_sat": 128,
                "external_funding_sat": 128, "total_accounted_sat": 128,
                "collected_sat": self.collected, "conserved": True,
            })
        return super().execute(node, binary, action, request)


class FixtureTests(unittest.TestCase):
    def close(self, run, fixture=None):
        stop = Mock()
        settlement.settle_and_collect(run, run.prior, stop=stop,
                                      fixture=fixture or run.fixture())
        self.assertEqual([call.args[0] for call in stop.call_args_list], list(ACCOUNTS))

    def test_one_or_two_frozen_source_channels_collect_all_128_once(self):
        for count in (1, 2):
            with self.subTest(channels=count):
                run = DiamondRun(count)
                expected = run.balances.copy()
                self.close(run)
                self.assertEqual(run.collected, 128)
                self.assertEqual(run.balances, dict.fromkeys(ACCOUNTS, 0))
                self.assertEqual(run.calls[:5], [("mint", "report"),
                                                *((n, "settle") for n in ACCOUNTS)])
                for name, balance in expected.items():
                    self.assertEqual(run.calls.count((name, "export")), int(balance > 0))
                evidence = run.evidence["phases"][-1]["settlement_collection"]
                self.assertEqual(evidence["settled_wallet_balances"], expected)
                self.assertEqual(run.evidence["mint"]["collected_sat"], 128)
                self.assertNotIn("private-token", repr(run.evidence))

    def test_fixture_freezes_caller_maps_and_rejects_invalid_policy(self):
        run = DiamondRun()
        fixture = run.fixture()
        run.owners.clear()
        run.initial["source"] = 384
        self.assertEqual(len(fixture.channel_owners), 2)
        self.assertEqual(fixture.initial_balances["source"], 128)
        with self.assertRaises(TypeError):
            fixture.channel_owners["extra"] = "source"
        for field, value in (("initial_balances", {"source": -1}),
                             ("buyer_budgets", dict.fromkeys(ACCOUNTS, 0)),
                             ("channel_capacity_sat", True),
                             ("channel_owners", {"other": "unknown"}),
                             ("channel_providers", {"channel-0": "n01"})):
            with self.subTest(field=field):
                run = DiamondRun()
                values = dict(initial_balances=run.initial, buyer_budgets=run.budgets,
                              channel_capacity_sat=64, channel_owners=run.owners,
                              channel_providers=run.providers)
                values[field] = value
                with self.assertRaises(RuntimeError):
                    settlement.SettlementFixture(**values)

    def test_wrong_account_channel_budget_or_provider_fails_before_actions(self):
        changes = (
            lambda r: r.prior.pop("n03"),
            lambda r: r.prior["source"]["funding"].update({"extra": ("extra", "extra-op")}),
            lambda r: r.prior["source"]["budget"].update(pending_reserved_sat=64),
            lambda r: r.prior["source"]["budget"].update(wallet_debited_sat=64),
            lambda r: r.prior["source"].update(remaining=128),
            lambda r: r.prior["n01"]["budget"].update(wallet_debited_sat=1),
            lambda r: r.prior["n01"]["credited"].clear(),
        )
        for mutate in changes:
            with self.subTest(mutation=changes.index(mutate)):
                run = DiamondRun()
                mutate(run)
                with self.assertRaises(RuntimeError):
                    self.close(run)
                self.assertEqual(run.calls, [])

    def test_replacement_with_same_count_is_not_an_original_channel(self):
        run = DiamondRun(1)
        run.prior["source"]["funding"]["fund-0"] = ("replacement", "operation-0")
        run.prior["source"]["signed"] = {"replacement": 6}
        with self.assertRaises(RuntimeError):
            self.close(run)
        self.assertEqual(run.calls, [])

    def test_wrong_capacity_duplicate_report_or_budget_reset_prevents_export(self):
        changes = (
            lambda r: r.reports["source"][0].update(value_after_stage1_sat=32, refunded_sat=25),
            lambda r: r.reports["source"].append(copy.deepcopy(r.reports["source"][0])),
            lambda r: r.settled["source"].update(remaining=128),
            lambda r: r.settled["source"]["budget"].update(locked_sat=64),
            lambda r: r.settled["n01"]["credited"].update({"channel-0": 6000}),
        )
        for mutate in changes:
            with self.subTest(mutation=changes.index(mutate)):
                run = DiamondRun()
                mutate(run)
                with self.assertRaises(RuntimeError):
                    self.close(run)
                self.assertFalse(run.exports)

    def test_per_wallet_distribution_is_checked_before_any_export(self):
        run = DiamondRun()
        run.balances["source"] -= 1
        run.balances["n03"] += 1
        with self.assertRaisesRegex(RuntimeError, "wallet distribution"):
            self.close(run)
        self.assertFalse(run.exports)
        self.assertEqual(run.collected, 0)

    def test_optional_provider_map_retains_total_value_check(self):
        run = DiamondRun()
        self.close(run, run.fixture(providers=False))
        self.assertEqual(run.collected, 128)
        run = DiamondRun()
        run.balances["source"] -= 1
        with self.assertRaises(RuntimeError):
            self.close(run, run.fixture(providers=False))
        self.assertFalse(run.exports)

    def test_uncertain_collection_is_not_replayed(self):
        run = DiamondRun()
        def transform(stage, value):
            if stage == "collect":
                raise RuntimeError("collection reply lost")
            return value
        run.transform = transform
        with self.assertRaisesRegex(RuntimeError, "reply lost"):
            self.close(run)
        self.assertEqual(run.calls.count(("mint", "collect")), 1)
        self.assertEqual(len(run.exports), 1)
        self.assertNotIn("mint", run.evidence)

    def test_mint_cap_does_not_replace_exact_128_issuance(self):
        for field, value in (("issued_sat", 384), ("external_funding_sat", 384),
                             ("total_accounted_sat", 384), ("collected_sat", 1)):
            with self.subTest(field=field):
                run = DiamondRun()
                def transform(stage, result):
                    if stage == "initial_report":
                        result[field] = value
                    return result
                run.transform = transform
                with self.assertRaises(RuntimeError):
                    self.close(run)
                self.assertEqual(run.calls, [("mint", "report")])


if __name__ == "__main__":
    unittest.main()
