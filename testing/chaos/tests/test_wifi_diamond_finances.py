"""Frozen, acknowledged diamond funding; no devices or bearer proofs."""

import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_finances import financial_snapshot
from sim.paid_settlement import SettlementFixture
from sim.wifi_diamond_finances import freeze_fixture


NAMES = ("source", "n01", "n02", "n03")
MINT = "http://test.invalid:3338"


def fixture(count=2):
    profiles = {name: SimpleNamespace(node_addr=[0] * 15 + [i + 1])
                for i, name in enumerate(NAMES)}
    journals = {}
    for name, profile in profiles.items():
        policy = {"mint_url": MINT, "channel_capacity_sat": 64 if name == "source" else 32,
                  "max_locked_sat": 128 if name == "source" else 64,
                  "max_wallet_spend_sat": 128, "max_funding_overhead_sat": 0,
                  "channel_lifetime_secs": 1800, "renewal": None}
        journals[name] = {
            "controller": {"local": profile.node_addr, "policy": policy, "funding": {},
                           "history": None, "buyer_settlements": {}, "seller_settlements": {},
                           "renewals": {}, "requested": {}, "outgoing": {}, "incoming": {},
                           "watched_routes": {}, "route_changes": {}},
            "buyer": {"local": profile.node_addr, "total_budget_sat": 128 if name == "source" else 64,
                      "channels": {}, "quotes": {}, "history": None},
            "seller": {"ledger": {"channels": [], "accounts": [], "history": None}},
        }
    source = journals["source"]
    for i in range(count):
        provider, channel, funding, quote = f"n0{i + 1}", f"channel-{i}", f"fund-{i}", f"quote-{i}"
        terms = {"id": channel, "buyer": profiles["source"].node_addr, "mint_url": MINT,
                 "capacity_sat": 64, "expires_unix": 2_000_000_000, "grace_msat": 8000}
        source["controller"]["funding"][funding] = {
            "id": funding, "provider": profiles[provider].node_addr,
            "capacity_sat": 64, "max_wallet_debit_sat": 64, "grace_msat": 8000,
            "created_unix": 1_999_999_000, "expires_unix": 2_000_000_000,
            "funded": {"terms": terms, "wallet_operation_id": f"operation-{i}",
                       "opening": {"channel_id": channel, "balance": 0},
                       "wallet_cost": {"token_amount_sat": 64, "wallet_debit_sat": 64, "swap_fee_sat": 0}},
        }
        source["buyer"]["channels"][channel] = {
            "terms": terms, "provider": profiles[provider].node_addr, "authorized_sat": i + 1}
        offer = {"id": quote}
        source["controller"]["requested"][quote] = offer
        purchase = {"channel": terms, "provider": profiles[provider].node_addr}
        source["controller"]["outgoing"][quote] = {
            "offer": offer, "funding_id": funding, "purchase": purchase,
            "accepted": True, "retired": False,
        }
        journals[provider]["controller"]["incoming"][quote] = {
            "channel": terms, "phase": "Active", "downstream": None}
        journals[provider]["seller"]["ledger"]["channels"].append({
            "terms": terms, "usage": {"paid_msat": (i + 1) * 1000, "submitted_msat": 500,
                                       "reserved_msat": 500, "lost_msat": 0}})
    return profiles, journals


class Accounts:
    def __init__(self, journals):
        self.nodes, self.journals = NAMES, journals

    def state_json(self, name, relative):
        return copy.deepcopy(self.journals[name][relative.split("/")[0]])

    def ctl(self, name, _kind):
        state = self.journals[name]
        funded = 64 * len(state["controller"]["funding"])
        return {"remaining_budget_sat": state["buyer"]["total_budget_sat"] - sum(
            c["authorized_sat"] for c in state["buyer"]["channels"].values()),
                "funding_budget": {"wallet_debited_sat": funded, "locked_sat": funded,
                                   "exposure_sat": funded, "wallet_refunded_sat": 0,
                                   "pending_reserved_sat": 0}}


def finances(journals):
    return financial_snapshot(Accounts(journals), wallet=None)


class DiamondFinanceTests(unittest.TestCase):
    def test_zero_one_or_two_known_channels_build_exact_closure_policy(self):
        for count in range(3):
            with self.subTest(channels=count):
                profiles, raw = fixture(count)
                policy = freeze_fixture(profiles, raw, finances(raw), count)
                self.assertIsInstance(policy, SettlementFixture)
                self.assertEqual(policy.issued_sat, 128)
                self.assertEqual(policy.channel_capacity_sat, 64)
                self.assertEqual(dict(policy.initial_balances), dict(source=128, n01=0, n02=0, n03=0))
                self.assertEqual(dict(policy.buyer_budgets), dict(source=128, n01=64, n02=64, n03=64))
                self.assertEqual(dict(policy.channel_owners), {f"channel-{i}": "source" for i in range(count)})
                self.assertEqual(dict(policy.channel_providers),
                                 {f"channel-{i}": f"n0{i + 1}" for i in range(count)})

    def test_growth_and_reuse_keep_prior_terms_and_allow_payment_progress(self):
        profiles, initial = fixture(0)
        _, one = fixture(1)
        _, two = fixture(2)
        freeze_fixture(profiles, one, finances(one), 1, previous=initial)
        freeze_fixture(profiles, two, finances(two), 2, previous=one)
        later = copy.deepcopy(two)
        later["source"]["buyer"]["channels"]["channel-0"]["authorized_sat"] = 4
        later["n01"]["seller"]["ledger"]["channels"][0]["usage"]["paid_msat"] = 4000
        policy = freeze_fixture(profiles, later, finances(later), 2, previous=two)
        self.assertEqual(len(policy.channel_owners), 2)

    def test_missing_malformed_or_duplicate_identity_is_rejected(self):
        changes = (
            lambda p, j: j.pop("n03"),
            lambda p, j: setattr(p["n01"], "node_addr", [0] * 16),
            lambda p, j: j["n01"]["controller"].update(local=[0] * 15 + [True]),
            lambda p, j: j["n01"]["buyer"].update(local=j["n02"]["buyer"]["local"]),
        )
        for index, mutate in enumerate(changes):
            with self.subTest(case=index):
                profiles, raw = fixture()
                summary = finances(raw)
                mutate(profiles, raw)
                with self.assertRaises(RuntimeError):
                    freeze_fixture(profiles, raw, summary, 2)

    def test_unresolved_or_unacknowledged_financial_work_cannot_be_frozen(self):
        changes = (
            lambda j: j["source"]["controller"]["funding"]["fund-0"].update(funded=None),
            lambda j: j["source"]["controller"]["outgoing"]["quote-0"].update(accepted=False),
            lambda j: j["source"]["controller"]["requested"].update(extra={"id": "extra"}),
            lambda j: j["source"]["controller"]["watched_routes"].update(route={"pending": {"id": "new"}}),
            lambda j: j["source"]["controller"]["route_changes"].update(route={"offer": {"id": "new"}}),
            lambda j: j["n01"]["controller"]["incoming"]["quote-0"].update(phase="Prepared"),
            lambda j: j["source"]["controller"]["buyer_settlements"].update(extra={}),
            lambda j: j["source"]["controller"]["renewals"].update(extra={}),
        )
        for index, mutate in enumerate(changes):
            with self.subTest(case=index):
                profiles, raw = fixture()
                summary = finances(raw)
                mutate(raw)
                with self.assertRaises(RuntimeError):
                    freeze_fixture(profiles, raw, summary, 2)

    def test_zero_channel_stage_rejects_hidden_unresolved_intent(self):
        profiles, raw = fixture(0)
        summary = finances(raw)
        raw["source"]["controller"]["funding"]["pending"] = {"funded": None}
        with self.assertRaises(RuntimeError):
            freeze_fixture(profiles, raw, summary, 0)

    def test_invalid_acknowledged_channel_count_is_rejected(self):
        profiles, raw = fixture(0)
        for count in (True, -1, 3, 1.0):
            with self.subTest(count=count), self.assertRaises(RuntimeError):
                freeze_fixture(profiles, raw, finances(raw), count)

    def test_wrong_provider_capacity_cost_or_opening_is_rejected(self):
        changes = (
            lambda f, p: f.update(provider=p["n03"].node_addr),
            lambda f, p: f.update(capacity_sat=32),
            lambda f, p: f.update(max_wallet_debit_sat=65),
            lambda f, p: f["funded"]["terms"].update(mint_url="http://different.invalid"),
            lambda f, p: f["funded"]["wallet_cost"].update(swap_fee_sat=1),
            lambda f, p: f["funded"]["wallet_cost"].update(wallet_debit_sat=65),
            lambda f, p: f["funded"]["opening"].update(balance=1),
            lambda f, p: f["funded"]["opening"].update(channel_id="different"),
        )
        for index, mutate in enumerate(changes):
            with self.subTest(case=index):
                profiles, raw = fixture()
                summary = finances(raw)
                mutate(raw["source"]["controller"]["funding"]["fund-0"], profiles)
                with self.assertRaises(RuntimeError):
                    freeze_fixture(profiles, raw, summary, 2)

    def test_duplicates_extra_buyers_or_unmatched_ledgers_are_rejected(self):
        changes = (
            lambda j: j["source"]["controller"]["funding"]["fund-1"]["funded"].update(
                wallet_operation_id="operation-0"),
            lambda j: j["source"]["controller"]["funding"]["fund-1"].update(
                provider=j["n01"]["controller"]["local"]),
            lambda j: j["n01"]["buyer"]["channels"].update(
                j["source"]["buyer"]["channels"]),
            lambda j: j["n01"]["seller"]["ledger"]["channels"].append(
                copy.deepcopy(j["n01"]["seller"]["ledger"]["channels"][0])),
            lambda j: j["n01"]["seller"]["ledger"]["channels"].clear(),
        )
        for index, mutate in enumerate(changes):
            with self.subTest(case=index):
                profiles, raw = fixture()
                summary = finances(raw)
                mutate(raw)
                with self.assertRaises(RuntimeError):
                    freeze_fixture(profiles, raw, summary, 2)

    def test_policy_and_summary_must_match_exact_fixture_authority(self):
        for field, value in (("max_locked_sat", 129), ("max_wallet_spend_sat", 129),
                             ("channel_capacity_sat", 32), ("renewal", {})):
            with self.subTest(field=field):
                profiles, raw = fixture()
                raw["source"]["controller"]["policy"][field] = value
                with self.assertRaises(RuntimeError):
                    freeze_fixture(profiles, raw, finances(raw), 2)
        for key in ("funding", "signed", "credited"):
            profiles, raw = fixture()
            summary = finances(raw)
            summary["n01" if key == "credited" else "source"][key].clear()
            with self.subTest(summary=key), self.assertRaises(RuntimeError):
                freeze_fixture(profiles, raw, summary, 2)

    def test_summary_cannot_gain_an_unknown_channel_in_its_bracketing_read(self):
        profiles, raw = fixture(1)
        summary = finances(raw)
        summary["source"]["signed_after"]["new-channel"] = 0
        with self.assertRaisesRegex(RuntimeError, "unanchored channel"):
            freeze_fixture(profiles, raw, summary, 1)

    def test_buyer_and_seller_terms_must_match_funded_terms(self):
        for role in ("buyer", "seller"):
            profiles, raw = fixture(1)
            row = (raw["source"]["buyer"]["channels"]["channel-0"] if role == "buyer" else
                   raw["n01"]["seller"]["ledger"]["channels"][0])
            row["terms"] = {**row["terms"], "capacity_sat": 63}
            with self.subTest(role=role), self.assertRaises(RuntimeError):
                freeze_fixture(profiles, raw, finances(raw), 1)

    def test_matching_replacement_is_rejected_against_original_anchor(self):
        profiles, previous = fixture(1)
        raw = copy.deepcopy(previous)
        source = raw["source"]
        funded = source["controller"]["funding"]["fund-0"]["funded"]
        funded["terms"]["id"] = "replacement"
        funded["opening"]["channel_id"] = "replacement"
        source["buyer"]["channels"]["replacement"] = source["buyer"]["channels"].pop("channel-0")
        freeze_fixture(profiles, raw, finances(raw), 1)
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            freeze_fixture(profiles, raw, finances(raw), 1, previous=previous)

    def test_replacement_removed_channel_changed_operation_or_rollback_is_rejected(self):
        changes = (
            lambda j: j["source"]["controller"]["funding"]["fund-0"]["funded"].update(
                wallet_operation_id="replacement-operation"),
            lambda j: j["source"]["controller"]["policy"].update(channel_lifetime_secs=900),
            lambda j: j["source"]["buyer"]["channels"]["channel-0"].update(authorized_sat=0),
            lambda j: j["n01"]["seller"]["ledger"]["channels"][0]["usage"].update(paid_msat=0),
        )
        profiles, previous = fixture(2)
        for index, mutate in enumerate(changes):
            with self.subTest(case=index):
                raw = copy.deepcopy(previous)
                mutate(raw)
                with self.assertRaises(RuntimeError):
                    freeze_fixture(profiles, raw, finances(raw), 2, previous=previous)
        _, one = fixture(1)
        with self.assertRaises(RuntimeError):
            freeze_fixture(profiles, one, finances(one), 1, previous=previous)

    def test_later_summary_may_advance_but_cannot_precede_raw_payment_evidence(self):
        profiles, raw = fixture(1)
        later = copy.deepcopy(raw)
        later["source"]["buyer"]["channels"]["channel-0"]["authorized_sat"] = 3
        later["n01"]["seller"]["ledger"]["channels"][0]["usage"]["paid_msat"] = 3000
        freeze_fixture(profiles, raw, finances(later), 1)
        with self.assertRaises(RuntimeError):
            freeze_fixture(profiles, later, finances(raw), 1)


if __name__ == "__main__":
    unittest.main()
