"""Bounded original authority plus one refunded-channel promotion replacement.

Raw funding records stay in memory for exact comparison; evidence contains only
hashes, public terms and monetary summaries, never proofs or signed payments.
"""

import copy
import json

from .paid_phone_finances import _address, _zero
from .paid_relay import eventually
from .paid_settlement import (
    SettlementFixture, amount, check_mint, collect_settled_wallets, require, validate_report,
)
from .wifi_promotion_checks import CEILING, FEE, FULL_QUOTA, POLICY
from .wifi_remote import digest


NAMES = ("n01", "n02", "n03")


def check(condition, message):
    # A financial violation is not an eventually-retryable observation race.
    if not condition:
        raise ValueError(message)


def refund(controller, channel, terms):
    record = controller["buyer_settlements"].get(channel)
    if record is None or record["refunded"] is not True:
        return None
    report = validate_report(record["report"])
    check(record["channel"] == terms and report["channel_id"] == channel
          and amount(record["wallet_refund_sat"]) == report["refunded_sat"],
          "released promotion capital lacks exact verified refund evidence")
    return report


def journals(run):
    return {name: {kind: run.state_json(name, relative) for kind, relative in (
        ("controller", "controller/controller.json"), ("buyer", "buyer/buyer.json"),
        ("seller", "seller/ledger.json"))} for name in NAMES}


class PromotionAccounts:
    def __init__(self, run, identities):
        self.run, self.identities = run, identities
        self.initial = journals(run)
        self.previous = copy.deepcopy(self.initial)
        self.previous_summary = None
        self.trial = self.used = None
        self.watch_started = False
        self.paused = False
        self.check(self.initial, run.finances())
        check(all(not state["controller"]["funding"] for state in self.initial.values()),
              "promotion fixture did not start with unfunded channels")

    def anchor_trial(self, trial, raw):
        used = amount(raw["n01"]["buyer"]["quotes"][trial["contract"]["id"]]["observed_units"])
        check(0 < used < POLICY["trial_max_units"] == trial["contract"]["max_units"],
              "promotion trial was not positively and partly consumed")
        self.trial, self.used = copy.deepcopy(trial), used

    def observe(self):
        raw = journals(self.run)
        summary = self.run.finances()
        fixture = self.check(raw, summary)
        self.previous, self.previous_summary = copy.deepcopy(raw), copy.deepcopy(summary)
        return raw, summary, fixture

    def check(self, raw, summary):
        check(set(raw) == set(summary) == set(NAMES), "promotion account set changed")
        channels, operations = {}, set()
        for name in NAMES:
            state, initial, previous = raw[name], self.initial[name], self.previous[name]
            controller, buyer = state["controller"], state["buyer"]
            policy = controller["policy"]
            check(_address(controller["local"]) == _address(buyer["local"]) == tuple(self.identities[name])
                  and policy == initial["controller"]["policy"]
                  and controller["epoch"] == initial["controller"]["epoch"],
                  "promotion changed original identity, epoch or spending policy")
            check(policy["mint_url"] == self.run.mint_url and policy["renewal"] is None
                  and policy["channel_capacity_sat"] == 32 and policy["max_locked_sat"] == 64
                  and policy["max_wallet_spend_sat"] == 128 and policy["max_funding_overhead_sat"] == 0
                  and buyer["total_budget_sat"] == 64 and not controller["renewals"],
                  "promotion widened the original capital or lifetime authority")
            history = controller.get("history") or {}
            check(_zero(buyer.get("history")) and _zero(state["seller"]["ledger"].get("history"))
                  and history.get("pending") is None and _zero(history.get("channels"))
                  and _zero(history.get("seller")), "promotion retired financial evidence")
            funding = controller["funding"]
            maximum = {"n01": 2, "n02": 0, "n03": 1}[name]
            check(len(funding) <= maximum and controller["next_funding"]
                  == initial["controller"]["next_funding"] + len(funding),
                  "promotion exceeded original funding count or one source replacement")
            for key, prior in previous["controller"]["funding"].items():
                check(key in funding and all(funding[key].get(field) == value
                      for field, value in prior.items() if field != "funded")
                      and (prior["funded"] is None or funding[key]["funded"] == prior["funded"]),
                      "promotion changed an existing funding intent, operation or opening")
            budget = dict.fromkeys(("pending_reserved_sat", "wallet_debited_sat",
                                   "wallet_refunded_sat", "locked_sat", "exposure_sat"), 0)
            owner_channels = {}
            for key, intent in funding.items():
                check(intent["id"] == key and _address(intent["provider"]) == tuple(self.identities["n02"])
                      and intent["capacity_sat"] == intent["max_wallet_debit_sat"] == 32
                      and intent["grace_msat"] == 8000
                      and amount(intent["created_unix"]) < amount(intent["expires_unix"]),
                      "promotion funding escaped the middle provider or 32-sat cap")
                funded = intent["funded"]
                if funded is None:
                    budget["pending_reserved_sat"] += 32
                    budget["locked_sat"] += 32
                    budget["exposure_sat"] += 32
                    continue
                terms, cost = funded["terms"], funded["wallet_cost"]
                channel, operation = terms["id"], funded["wallet_operation_id"]
                check(isinstance(channel, str) and channel and channel not in channels
                      and isinstance(operation, str) and operation and operation not in operations,
                      "duplicate or missing original funding identity")
                check(_address(terms["buyer"]) == tuple(self.identities[name])
                      and terms["mint_url"] == self.run.mint_url and terms["capacity_sat"] == 32
                      and terms["grace_msat"] == intent["grace_msat"]
                      and terms["expires_unix"] == intent["expires_unix"]
                      and cost == {"token_amount_sat": 32, "wallet_debit_sat": 32, "swap_fee_sat": 0}
                      and funded["opening"]["channel_id"] == channel
                      and funded["opening"]["balance"] == 0,
                      "promotion changed zero-fee funded channel terms")
                channels[channel] = {"owner": name, "terms": terms, "operation": operation, "key": key}
                owner_channels[channel] = terms
                operations.add(operation)
                budget["wallet_debited_sat"] += 32
                refunded = refund(controller, channel, terms)
                if refunded is None:
                    budget["locked_sat"] += 32
                else:
                    budget["wallet_refunded_sat"] += refunded["refunded_sat"]
                budget["exposure_sat"] += 32 - (refunded["refunded_sat"] if refunded else 0)
            if len(funding) == 2:
                check(self.trial is not None, "replacement appeared before the captured original trial")
                old = self.trial["channel"]
                check(refund(controller, old["id"], old) is not None,
                      "replacement appeared without the original verified refund")
                first = next(record for record in funding.values()
                             if record["funded"] and record["funded"]["terms"]["id"] == old["id"])
                check(all(record["receiver_pubkey_hex"] == first["receiver_pubkey_hex"]
                          for record in funding.values()), "replacement changed the receiver identity")
            require(summary[name]["budget"] == budget, "financial sampling changed capital boundaries")
            self.check_buyer(name, state, summary[name], owner_channels, previous)
            self.check_watch(name, controller)
        self.check_routes(raw, channels)
        self.check_seller(raw, summary, channels)
        return SettlementFixture(dict.fromkeys(NAMES, 128), dict.fromkeys(NAMES, 64), 32,
                                 {key: item["owner"] for key, item in channels.items()},
                                 dict.fromkeys(channels, "n02"))

    def check_buyer(self, name, state, summary, owner_channels, previous):
        buyer = state["buyer"]
        check(set(buyer["channels"]) <= set(owner_channels), "buyer has an unfunded promotion channel")
        for channel, row in buyer["channels"].items():
            check(row["terms"] == owner_channels[channel]
                  and _address(row["provider"]) == tuple(self.identities["n02"])
                  and amount(row["authorized_sat"]) <= 32, "buyer changed its channel authority")
        signed = {channel: row["authorized_sat"] for channel, row in buyer["channels"].items()}
        require(summary["signed"] == signed, "financial sampling changed authorization boundaries")
        check(summary["authorized"] == sum(signed.values())
              and summary["remaining"] + summary["authorized"] == 64,
              "promotion reset the lifetime buyer budget")
        if self.previous_summary is not None:
            check(summary["remaining"] <= self.previous_summary[name]["remaining"],
                  "promotion replenished lifetime spending authority")
        for channel, row in previous["buyer"]["channels"].items():
            check(channel in signed and signed[channel] >= row["authorized_sat"],
                  "promotion lost original authorization evidence")
        for quote, old in previous["buyer"]["quotes"].items():
            current = buyer["quotes"].get(quote)
            check(current is not None and all(amount(current[field]) >= amount(old[field])
                  for field in ("submitted_units", "observed_units")), "promotion reset prior trial accounting")

    def check_watch(self, name, controller):
        watches = controller["watched_routes"]
        if name != "n01" or not self.watch_started:
            check(not watches, "promotion created extra automatic spending authority")
            return
        destination = self.run.nodes["n03"].npub
        check(set(watches) == {destination}, "promotion changed the original Watch roster")
        watch = watches[destination]
        check(watch["destination"] == destination and watch["billing"] == "forwarding_data"
              and watch["max_rate_msat_per_kib"] == CEILING and watch["paused"] is self.paused,
              "promotion changed the original Watch authority")

    def check_routes(self, raw, channels):
        for name, state in raw.items():
            for key, row in state["controller"]["outgoing"].items():
                purchase = row["purchase"]
                channel = channels.get(purchase["channel"]["id"])
                check(channel is not None and channel["owner"] == name
                      and purchase["channel"] == channel["terms"] and row["funding_id"] == channel["key"]
                      and _address(purchase["provider"]) == tuple(self.identities["n02"])
                      and purchase["contract"]["id"] == key
                      and purchase["contract"]["channel_id"] == purchase["channel"]["id"]
                      and purchase["contract"]["destination"] == self.identities["n03" if name == "n01" else "n01"]
                      and purchase["contract"]["billing"] == "forwarding_data"
                      and purchase["contract"]["price"] == {"msat": FEE, "per_bytes": 1024}
                      and row["offer"]["max_units"] == purchase["contract"]["max_units"]
                      and (row["offer"].get("trial", False) is True
                           or purchase["contract"]["max_units"] == FULL_QUOTA),
                      "promotion route escaped its original funding")
        if self.trial is not None:
            source = raw["n01"]
            key = self.trial["contract"]["id"]
            old = source["controller"]["outgoing"].get(key)
            check(old is not None and old["purchase"] == self.trial
                  and old["accepted"] is True and old["retired"] is True
                  and source["buyer"]["quotes"][key]["observed_units"] == self.used,
                  "retired original trial changed or consumed more allowance")
            replacements = [row for ident, row in source["controller"]["outgoing"].items()
                            if ident != key and row["offer"].get("trial", False) is True]
            remainder = self.trial["contract"]["max_units"] - self.used
            check(len(replacements) <= 1 and all(row["offer"]["max_units"] == remainder
                  for row in replacements), "same-path recovery did not retain the exact trial remainder")

    def check_seller(self, raw, summary, channels):
        for name, state in raw.items():
            ledger = state["seller"]["ledger"]
            rows = {row["terms"]["id"]: row for row in ledger["channels"]}
            check(len(rows) == len(ledger["channels"]) and set(rows) <= set(channels)
                  and (name == "n02" or not rows), "seller has an unknown or duplicate channel")
            for channel, row in rows.items():
                usage = row["usage"]
                signed = summary[channels[channel]["owner"]]["signed_after"].get(channel)
                check(row["terms"] == channels[channel]["terms"] and signed is not None
                      and amount(usage["paid_msat"]) <= amount(signed) * 1000
                      and amount(usage["lost_msat"]) == 0
                      and amount(usage["submitted_msat"]) <= amount(usage["reserved_msat"])
                      <= min(32_000, usage["paid_msat"] + row["terms"]["grace_msat"]),
                      "seller credit or unpaid exposure escaped retained authorization")
                old = next((item for item in self.previous[name]["seller"]["ledger"]["channels"]
                            if item["terms"]["id"] == channel), None)
                if old is not None:
                    check(usage["paid_msat"] >= old["usage"]["paid_msat"], "seller credit decreased")

    def evidence(self, raw, summary):
        return {"financial": summary, "trial_used_units": self.used,
                "funding_sha256": {name: digest(json.dumps(state["controller"]["funding"],
                    sort_keys=True).encode()) for name, state in raw.items()}}

    def pause(self):
        # Cleanup only; never used to obtain recovery acceptance.
        if not self.paused:
            failures = []
            for name in NAMES:
                for command in ("pause_route_refresh", "pause_renewals"):
                    try:
                        self.run.ctl(name, command)
                    except Exception as error:
                        failures.append({"node": name, "command": command, "error": type(error).__name__})
            self.run.evidence["promotion_pause_errors"] = failures
            require(not failures, "promotion spending authority was not fully paused")
            self.paused = True

    def collect(self):
        self.pause()
        raw, summary, fixture = eventually("bounded promotion accounts before collection", self.observe)
        check(all(record["funded"] is not None for state in raw.values()
                  for record in state["controller"]["funding"].values()),
              "unresolved promotion funding retains the original mint and accounts")
        initial = self.run.account_execute("mint", "fips-relay-test-mint", "ctl", {"type": "report"})
        check_mint(initial, 0)
        reports = {}
        for name in NAMES:
            reply = self.run.ctl(name, "settle")
            for report in reply["settlements"]:
                channel = report["channel_id"]
                check(fixture.channel_owners.get(channel) == name and channel not in reports,
                      "promotion settlement returned an unexpected or duplicate channel")
                reports[channel] = validate_report(report)
        check(set(reports) == set(fixture.channel_owners), "promotion settlement omitted a retained channel")
        final_raw, final, final_fixture = eventually("settled promotion accounts", self.observe)
        check(final_fixture == fixture, "settlement changed the promotion channel roster")
        for name in NAMES:
            check(final[name]["budget"]["locked_sat"] == final[name]["budget"]["pending_reserved_sat"] == 0,
                  "promotion settlement left unresolved capital")
        for channel, owner in fixture.channel_owners.items():
            terms = next(record["funded"]["terms"] for record in final_raw[owner]["controller"]["funding"].values()
                         if record["funded"]["terms"]["id"] == channel)
            check(refund(final_raw[owner]["controller"], channel, terms) == reports[channel]
                  and final[owner]["signed"][channel] == reports[channel]["paid_sat"]
                  and final["n02"]["credited"][channel] == reports[channel]["paid_sat"] * 1000,
                  "final promotion payment, refund and provider credit disagree")
        collect_settled_wallets(self.run, final, reports, fixture.channel_owners, initial["url"],
            execute=self.run.account_execute, stop=lambda name: self.run.nodes[name].stop(),
            export_path=lambda name, relative: self.run.nodes[name].state + "/" + relative, fixture=fixture)
        self.run.phase("all 384 promotion test sats collected; every test wallet empty")
