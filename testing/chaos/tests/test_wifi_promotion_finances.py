"""Retained promotion funding and verified replacement; no wallet or router calls."""

import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from sim.paid_relay import relay_config
from sim.paid_wifi import retain_channels
from sim.wifi_promotion_checks import CEILING, FEE, FULL_QUOTA, POLICY
from sim.wifi_promotion_finances import NAMES, PromotionAccounts
from tests.test_paid_settlement import FakeRun


IDS = {name: [int(name[-1])] * 16 for name in NAMES}
MINT = "http://private-test:3338"


def empty():
    return {name: {"controller": {"local": IDS[name], "epoch": name, "next_funding": 1,
        "policy": relay_config([], MINT)["terms"]["controller"], "funding": {}, "renewals": {},
        "buyer_settlements": {}, "seller_settlements": {}, "outgoing": {}, "incoming": {},
        "watched_routes": {}, "recovery_only": []},
        "buyer": {"local": IDS[name], "total_budget_sat": 64, "channels": {}, "quotes": {}},
        "seller": {"ledger": {"channels": []}}} for name in NAMES}


def add_channel(raw, owner, suffix, signed):
    controller, buyer = raw[owner]["controller"], raw[owner]["buyer"]
    key, channel = "fund-" + suffix, "channel-" + suffix
    terms = {"id": channel, "buyer": IDS[owner], "mint_url": MINT, "capacity_sat": 32,
             "grace_msat": 8000, "expires_unix": 1900}
    controller["funding"][key] = {"id": key, "provider": IDS["n02"], "receiver_pubkey_hex": "receiver",
        "capacity_sat": 32, "max_wallet_debit_sat": 32, "grace_msat": 8000,
        "created_unix": 100, "expires_unix": 1900, "funded": {"terms": copy.deepcopy(terms),
            "opening": {"channel_id": channel, "balance": 0, "signature": "SECRET-PROOF"},
            "wallet_operation_id": "operation-" + suffix,
            "wallet_cost": {"token_amount_sat": 32, "wallet_debit_sat": 32, "swap_fee_sat": 0}}}
    controller["next_funding"] += 1
    buyer["channels"][channel] = {"terms": copy.deepcopy(terms), "provider": IDS["n02"],
                                  "authorized_sat": signed, "active": True}
    raw["n02"]["seller"]["ledger"]["channels"].append({"terms": copy.deepcopy(terms),
        "usage": {"paid_msat": signed * 1000, "submitted_msat": signed * 1000,
                  "reserved_msat": signed * 1000, "lost_msat": 0}})
    return terms


def add_route(raw, owner, terms, key, *, trial=False, quota=None, used=0, retired=False):
    quota = quota or (POLICY["trial_max_units"] if trial else FULL_QUOTA)
    purchase = {"provider": IDS["n02"], "channel": copy.deepcopy(terms), "contract": {
        "id": key, "channel_id": terms["id"], "destination": IDS["n03" if owner == "n01" else "n01"],
        "next_hop": IDS["n03" if owner == "n01" else "n01"], "expires_unix": 1200,
        "max_units": quota, "price": {"msat": FEE, "per_bytes": 1024}, "billing": "forwarding_data"}}
    offer = {"id": "offer-" + key, "max_units": quota, "trial": trial}
    controller = raw[owner]["controller"]
    funding_id = next(ident for ident, record in controller["funding"].items()
                      if record["funded"]["terms"]["id"] == terms["id"])
    controller["outgoing"][key] = {"purchase": copy.deepcopy(purchase), "offer": offer,
                                   "accepted": True, "retired": retired, "funding_id": funding_id}
    raw[owner]["buyer"]["quotes"][key] = {"contract": purchase["contract"], "active": not retired,
                                         "observed_units": used, "submitted_units": used}
    return purchase


def settle(raw, owner, channel):
    controller, buyer = raw[owner]["controller"], raw[owner]["buyer"]
    terms = buyer["channels"][channel]["terms"]
    paid = buyer["channels"][channel]["authorized_sat"]
    report = {"channel_id": channel, "value_after_stage1_sat": 32, "paid_sat": paid,
              "receiver_fee_reserve_sat": 0, "refunded_sat": 32 - paid, "fee_sat": 0}
    controller["buyer_settlements"][channel] = {"channel": copy.deepcopy(terms), "refunded": True,
        "wallet_refund_sat": 32 - paid, "report": copy.deepcopy(report)}
    buyer["channels"][channel]["active"] = False
    return report


def summary(raw):
    result = {}
    for name, state in raw.items():
        controller, buyer = state["controller"], state["buyer"]
        funding = {key: (r["funded"]["terms"]["id"], r["funded"]["wallet_operation_id"])
                   for key, r in controller["funding"].items() if r["funded"]}
        reserved = 32 * (len(controller["funding"]) - len(funding))
        refunds = [r for r in controller["buyer_settlements"].values() if r["refunded"]]
        signed = {key: row["authorized_sat"] for key, row in buyer["channels"].items()}
        credited = {row["terms"]["id"]: row["usage"]["paid_msat"]
                    for row in state["seller"]["ledger"]["channels"]}
        refunded = sum(row["wallet_refund_sat"] for row in refunds)
        result[name] = {"funding": funding, "budget": {"wallet_debited_sat": len(funding) * 32,
            "pending_reserved_sat": reserved, "locked_sat": (len(funding) - len(refunds)) * 32 + reserved,
            "wallet_refunded_sat": refunded, "exposure_sat": len(funding) * 32 + reserved - refunded},
            "remaining": 64 - sum(signed.values()), "authorized": sum(signed.values()),
            "signed": signed, "signed_after": dict(signed), "credited": credited,
            "buyer_units": {key: row["submitted_units"] for key, row in buyer["quotes"].items()},
            "buyer_observed_units": {key: row["observed_units"] for key, row in buyer["quotes"].items()}}
    return result


class Fixture:
    def __init__(self):
        self.raw = empty()
        self.run = Mock(mint_url=MINT)
        self.run.nodes = {name: SimpleNamespace(npub=name, node_addr=IDS[name], state="/tmp/bench-state", stop=Mock())
                          for name in NAMES}
        self.run.evidence = {"phases": []}
        self.run.finances.side_effect = lambda: summary(self.raw)
        self.run.state_json.side_effect = lambda name, path: copy.deepcopy(self.raw[name][path.split('/')[0]])
        self.accounts = PromotionAccounts(self.run, IDS)

    def funded(self):
        forward = add_channel(self.raw, "n01", "first", 4)
        reverse = add_channel(self.raw, "n03", "reverse", 2)
        self.trial = add_route(self.raw, "n01", forward, "trial", trial=True, used=4096, retired=True)
        add_route(self.raw, "n03", reverse, "reverse", used=2048)
        self.accounts.watch_started = True
        self.raw["n01"]["controller"]["watched_routes"] = {"n03": {"destination": "n03",
            "max_rate_msat_per_kib": CEILING, "billing": "forwarding_data", "paused": False, "pending": None}}
        self.accounts.observe()
        self.accounts.anchor_trial(self.trial, self.raw)
        return self

    def replacement(self):
        settle(self.raw, "n01", self.trial["channel"]["id"])
        replacement = add_channel(self.raw, "n01", "replacement", 1)
        self.remaining = add_route(self.raw, "n01", replacement, "remaining", trial=True,
                                   quota=POLICY["trial_max_units"] - self.accounts.used, used=512)
        return self


class PromotionFinanceTests(unittest.TestCase):
    def test_failed_pause_attempts_every_authority_stop_without_certifying_paused(self):
        f = Fixture()
        def pause(name, command):
            if (name, command) == ("n01", "pause_route_refresh"):
                raise RuntimeError("uncertain pause response")
        f.run.ctl.side_effect = pause
        with self.assertRaisesRegex(RuntimeError, "not fully paused"):
            f.accounts.pause()
        self.assertFalse(f.accounts.paused)
        self.assertEqual([call.args for call in f.run.ctl.call_args_list],
                         [(name, kind) for name in NAMES
                          for kind in ("pause_route_refresh", "pause_renewals")])
        self.assertEqual(f.run.evidence["promotion_pause_errors"],
                         [{"node": "n01", "command": "pause_route_refresh", "error": "RuntimeError"}])

    def test_exact_refunded_replacement_keeps_old_funding_and_lifetime_budget(self):
        f = Fixture().funded().replacement()
        raw, money, fixture = f.accounts.observe()
        self.assertEqual(len(fixture.channel_owners), 3)
        self.assertEqual(money["n01"]["budget"], {"wallet_debited_sat": 64, "pending_reserved_sat": 0,
            "wallet_refunded_sat": 28, "locked_sat": 32, "exposure_sat": 36})
        self.assertEqual(money["n01"]["remaining"], 59)
        self.assertNotIn("SECRET-PROOF", json.dumps(f.accounts.evidence(raw, money)))
        with self.assertRaises(RuntimeError):
            retain_channels(summary(Fixture().funded().raw), money)

    def test_missing_refund_and_changed_original_operation_are_rejected(self):
        for field in ("refunded", "wallet_refund_sat", "channel", "operation"):
            with self.subTest(field=field):
                f = Fixture().funded().replacement()
                record = f.raw["n01"]["controller"]["buyer_settlements"]["channel-first"]
                if field == "refunded":
                    record[field] = False
                elif field == "wallet_refund_sat":
                    record[field] = 27
                elif field == "channel":
                    record[field]["capacity_sat"] = 64
                else:
                    f.raw["n01"]["controller"]["funding"]["fund-first"]["funded"]["wallet_operation_id"] = "other"
                with self.assertRaises((ValueError, RuntimeError)):
                    f.accounts.observe()

    def test_additional_funding_unresolved_replacement_and_unknown_provider_fail(self):
        for mode in ("third", "pending_without_refund", "provider", "mint", "cost", "budget"):
            with self.subTest(mode=mode):
                f = Fixture().funded().replacement()
                record = f.raw["n01"]["controller"]["funding"]["fund-replacement"]
                if mode == "third":
                    add_channel(f.raw, "n01", "third", 0)
                elif mode == "pending_without_refund":
                    record["funded"] = None
                    f.raw["n01"]["controller"]["buyer_settlements"] = {}
                elif mode == "provider":
                    record["provider"] = IDS["n03"]
                elif mode == "mint":
                    record["funded"]["terms"]["mint_url"] = "http://other.invalid"
                elif mode == "cost":
                    record["funded"]["wallet_cost"]["swap_fee_sat"] = 1
                else:
                    f.raw["n01"]["buyer"]["total_budget_sat"] = 128
                with self.assertRaises((ValueError, RuntimeError)):
                    f.accounts.observe()

    def test_consumed_trial_cannot_reset_refill_or_receive_arbitrary_remainder(self):
        for mode in ("reset", "refill", "smaller", "old_terms", "extra_watch"):
            with self.subTest(mode=mode):
                f = Fixture().funded().replacement()
                state = f.raw["n01"]
                if mode == "reset":
                    state["buyer"]["quotes"]["trial"]["observed_units"] = 0
                elif mode in ("refill", "smaller"):
                    quota = 32768 if mode == "refill" else 123
                    row = state["controller"]["outgoing"]["remaining"]
                    row["offer"]["max_units"] = row["purchase"]["contract"]["max_units"] = quota
                elif mode == "old_terms":
                    state["controller"]["outgoing"]["trial"]["purchase"]["contract"]["price"]["msat"] = 1
                else:
                    state["controller"]["watched_routes"]["extra"] = {}
                with self.assertRaises((ValueError, RuntimeError)):
                    f.accounts.observe()

    def test_promotion_collection_reuses_exact_exports_and_all_384_sats(self):
        f = Fixture().funded().replacement()
        f.accounts.observe()
        collector = FakeRun()
        collector.balances = {"n01": 123, "n02": 135, "n03": 126}
        f.run.account_execute.side_effect = collector.execute
        read = f.run.state_json.side_effect
        f.run.state_json.side_effect = lambda name, path: (
            collector.state_json(name, path) if path.startswith("exports/") else read(name, path))
        def ctl(name, kind):
            if kind == "pause_route_refresh":
                for watch in f.raw[name]["controller"]["watched_routes"].values():
                    watch["paused"] = True
            elif kind == "settle":
                return {"settlements": [settle(f.raw, name, channel)
                                       for channel in f.raw[name]["buyer"]["channels"]]}
            elif kind != "pause_renewals":
                raise AssertionError(kind)
        f.run.ctl.side_effect = ctl
        f.accounts.collect()
        self.assertEqual(collector.collected, 384)
        self.assertEqual(collector.balances, dict.fromkeys(NAMES, 0))
        for node in f.run.nodes.values():
            node.stop.assert_called_once_with()
        self.assertEqual(len(f.run.evidence["phases"][-1]["settlement_collection"]["settlements"]), 3)
        self.assertNotIn("SECRET-PROOF", json.dumps(f.run.evidence))

    def test_unresolved_original_funding_never_exports_or_stops_accounts(self):
        f = Fixture()
        add_channel(f.raw, "n01", "first", 0)
        f.raw["n01"]["controller"]["funding"]["fund-first"]["funded"] = None
        f.raw["n01"]["buyer"]["channels"].clear()
        f.raw["n02"]["seller"]["ledger"]["channels"].clear()
        with self.assertRaisesRegex(ValueError, "unresolved promotion funding"):
            f.accounts.collect()
        f.run.account_execute.assert_not_called()
        for node in f.run.nodes.values():
            node.stop.assert_not_called()
