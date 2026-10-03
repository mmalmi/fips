"""Retained authority and real successor channels for the finite renewal run.

Raw funding and signed records stay in memory. Evidence contains public channel
identifiers, monetary summaries and digests, never proofs or payment signatures.
"""

import copy
import json

from .paid_finances import FinancialObservationChanged, account_journals, consistent_observation
from .paid_phone_finances import _address, _zero
from .paid_relay import eventually
from .paid_settlement import SettlementFixture, amount, require, settle_and_collect, verified_refund
from .wifi_remote import digest


NAMES = ("n01", "n02", "n03")
ENDPOINTS = ("n01", "n03")
QUOTE_UNITS = 32 * 1024 * 1024
RENEWAL = {"at_capacity_percent": 80, "before_expiry_secs": 30}


def check(condition, message):
    # Real authority violations are not eventually-retryable sampling races.
    if not condition:
        raise ValueError(message)


class RenewalAccounts:
    def __init__(self, run, identities):
        self.run, self.identities = run, identities
        self.initial = account_journals(run)
        self.previous = copy.deepcopy(self.initial)
        self.latest_signed = {name: {} for name in NAMES}
        self.paused = False
        self.check(self.initial, run.finances())
        check(all(not state["controller"]["funding"] for state in self.initial.values()),
              "renewal fixture must start before any channel funding")

    def observe(self):
        try:
            raw, summary = account_journals(self.run), self.run.finances()
            fixture, lineage = self.check(raw, summary)
        except FinancialObservationChanged:
            raise
        except (RuntimeError, FileNotFoundError, json.JSONDecodeError) as error:
            # The shared eventually helper retries RuntimeError. Only the named
            # cross-snapshot inconsistencies are transient in this experiment.
            raise ValueError(str(error)) from error
        self.previous = copy.deepcopy(raw)
        self.latest_signed = {name: dict(state["signed_after"]) for name, state in summary.items()}
        return {"financial": summary, "renewals": lineage,
                "funding_sha256": {name: digest(json.dumps(state["controller"]["funding"],
                    sort_keys=True).encode()) for name, state in raw.items()}}, fixture

    def check(self, raw, summary):
        check(set(raw) == set(summary) == set(NAMES), "renewal participant set changed")
        channels, operations, refunds = {}, set(), {}
        for name, state in raw.items():
            controller, buyer = state["controller"], state["buyer"]
            check(state["seller"]["version"] == 2 and state["seller"]["window_msat"] == 4000,
                  "renewal changed the durable accounting window")
            original, previous = self.initial[name]["controller"], self.previous[name]
            policy = controller["policy"]
            check(_address(controller["local"]) == _address(buyer["local"])
                  == tuple(self.identities[name]) and controller["epoch"] == original["epoch"]
                  and policy == original["policy"], "renewal changed identity, epoch or policy")
            check(policy["mint_url"] == self.run.mint_url and policy["renewal"] == RENEWAL
                  and policy["channel_capacity_sat"] == 32 and policy["max_locked_sat"] == 64
                  and policy["max_wallet_spend_sat"] == 128 and policy["max_funding_overhead_sat"] == 0
                  and policy["channel_lifetime_secs"] == 1800 and buyer["total_budget_sat"] == 64,
                  "renewal widened the original spending, lifetime or capital bounds")
            check(controller["renewals_paused"] is self.paused and not controller["watched_routes"],
                  "renewal changed its autonomous purchase policy")
            history = controller.get("history") or {}
            check(_zero(buyer.get("history")) and _zero(state["seller"]["ledger"].get("history"))
                  and _zero(history.get("channels")) and _zero(history.get("seller"))
                  and history.get("pending") is None, "renewal retired financial evidence")
            funding = controller["funding"]
            # Acceptance requires one replacement. A third known channel still
            # needs financial closure if the workload fails that requirement.
            check(len(funding) <= (3 if name in ENDPOINTS else 0)
                  and controller["next_funding"] == original["next_funding"] + len(funding),
                  "renewal escaped the bounded funding roster")
            check(len({row["receiver_pubkey_hex"] for row in funding.values()}) <= 1,
                  "renewal changed the provider receiver identity")
            for key, old in previous["controller"]["funding"].items():
                check(key in funding and all(funding[key].get(field) == value
                      for field, value in old.items() if field != "funded")
                      and (old["funded"] is None or funding[key]["funded"] == old["funded"]),
                      "renewal changed original funding or wallet operation evidence")
            budget = dict.fromkeys(("pending_reserved_sat", "wallet_debited_sat",
                                   "wallet_refunded_sat", "locked_sat", "exposure_sat"), 0)
            owner_channels = {}
            for key, intent in funding.items():
                check(intent["id"] == key and _address(intent["provider"]) == tuple(self.identities["n02"])
                      and intent["capacity_sat"] == intent["max_wallet_debit_sat"] == 32
                      and intent["grace_msat"] == 8000
                      and amount(intent["expires_unix"]) == amount(intent["created_unix"]) + 900
                      and amount(intent["refund_after_unix"]) == intent["created_unix"] + 1800,
                      "renewal funding changed provider, capacity, grace or deadlines")
                funded = intent["funded"]
                if funded is None:
                    budget["pending_reserved_sat"] += 32
                    budget["locked_sat"] += 32
                    continue
                terms, cost = funded["terms"], funded["wallet_cost"]
                channel, operation = terms["id"], funded["wallet_operation_id"]
                check(isinstance(channel, str) and channel and channel not in channels
                      and isinstance(operation, str) and operation and operation not in operations,
                      "renewal duplicated a channel or wallet operation")
                check(_address(terms["buyer"]) == tuple(self.identities[name])
                      and terms["mint_url"] == self.run.mint_url and terms["capacity_sat"] == 32
                      and terms["grace_msat"] == 8000 and terms["expires_unix"] == intent["expires_unix"]
                      and terms["refund_after_unix"] == intent["refund_after_unix"]
                      and cost == {"token_amount_sat": 32, "wallet_debit_sat": 32, "swap_fee_sat": 0}
                      and funded["opening"]["channel_id"] == channel and funded["opening"]["balance"] == 0,
                      "renewal changed acknowledged zero-fee funding terms")
                operations.add(operation)
                channels[channel] = {"owner": name, "terms": terms, "key": key}
                owner_channels[channel] = terms
                budget["wallet_debited_sat"] += 32
                try:
                    report = verified_refund(controller, channel, terms)
                except RuntimeError as error:
                    raise ValueError(str(error)) from error
                if report is None:
                    budget["locked_sat"] += 32
                else:
                    refunds[channel] = report
                    budget["wallet_refunded_sat"] += report["refunded_sat"]
                old_refund = previous["controller"]["buyer_settlements"].get(channel)
                if old_refund is not None and old_refund["refunded"] is True:
                    check(report is not None and report == verified_refund(
                        previous["controller"], channel, terms), "renewal reset a verified refund")
            budget["exposure_sat"] = (budget["wallet_debited_sat"] + budget["pending_reserved_sat"]
                                      - budget["wallet_refunded_sat"])
            check(0 <= budget["exposure_sat"] <= 128 and budget["locked_sat"] <= 64,
                  "renewal exceeded the original capital limits")
            observed = summary[name]["budget"]
            check(set(observed) == set(budget) and all(amount(value) >= 0 for value in observed.values())
                  and observed["pending_reserved_sat"] <= observed["locked_sat"] <= 64
                  and observed["wallet_refunded_sat"] <= observed["wallet_debited_sat"]
                  and observed["exposure_sat"] == observed["wallet_debited_sat"]
                  + observed["pending_reserved_sat"] - observed["wallet_refunded_sat"] <= 128,
                  "observed renewal capital violates its own exposure bounds")
            consistent_observation(observed == budget, "capital changed during renewal sampling")
            expected_funding = {key: (record["funded"]["terms"]["id"], record["funded"]["wallet_operation_id"])
                                for key, record in funding.items() if record["funded"] is not None}
            consistent_observation(summary[name]["funding"] == expected_funding, "funding changed during renewal sampling")
            self.check_buyer(name, state, summary[name], owner_channels, previous)
        lineage = self.check_routes(raw, channels, refunds)
        self.check_seller(raw, summary, channels)
        fixture = SettlementFixture(dict.fromkeys(NAMES, 128), dict.fromkeys(NAMES, 64), 32,
            {key: row["owner"] for key, row in channels.items()}, dict.fromkeys(channels, "n02"), refunds)
        return fixture, lineage

    def check_buyer(self, name, state, summary, channels, previous):
        buyer = state["buyer"]
        later = {key: amount(value) for key, value in summary["signed_after"].items()}
        check(amount(summary["authorized"]) == sum(amount(value) for value in summary["signed"].values()) <= 64
              and sum(later.values()) <= 64 and all(value <= 32 for value in later.values())
              and amount(summary["remaining"]) + summary["authorized"] == 64,
              "renewal reset the lifetime buyer budget")
        observed = (summary["signed"], self.latest_signed[name],
                    {key: row["authorized_sat"] for key, row in buyer["channels"].items()})
        check(all(later.get(key, -1) >= amount(value) for snapshot in observed for key, value in snapshot.items()),
              "later buyer snapshot lost signed liability")
        check(sum(amount(row["authorized_sat"]) for row in buyer["channels"].values()) <= 64,
              "renewal exceeded durable lifetime buyer authority")
        consistent_observation(set(buyer["channels"]) <= set(channels), "buyer registration changed during renewal sampling")
        signed = {}
        for key, row in buyer["channels"].items():
            check(row["terms"] == channels[key] and _address(row["provider"]) == tuple(self.identities["n02"])
                  and amount(row["authorized_sat"]) <= 32, "buyer changed its retained channel authority")
            signed[key] = row["authorized_sat"]
        consistent_observation(summary["signed"] == signed, "authorization changed during renewal sampling")
        for key, old in previous["buyer"]["channels"].items():
            check(key in signed and signed[key] >= old["authorized_sat"], "renewal erased prior signed liability")
        for key, old in previous["buyer"]["quotes"].items():
            row = buyer["quotes"].get(key)
            check(row is not None and row["contract"] == old["contract"]
                  and all(amount(row[field]) >= amount(old[field]) for field in ("observed_units", "submitted_units")),
                  "renewal erased prior route usage")
        for row in buyer["quotes"].values():
            check(amount(row["submitted_units"]) <= amount(row["observed_units"]) <= QUOTE_UNITS,
                  "renewal exceeded its byte allowance")

    def check_routes(self, raw, channels, refunds):
        lineage = {}
        for name, state in raw.items():
            controller = state["controller"]
            outgoing = controller["outgoing"]
            for key, old in self.previous[name]["controller"]["renewals"].items():
                current = controller["renewals"].get(key)
                check(current is not None and current["previous"] == old["previous"]
                      and (old["replacements"] is None or current["replacements"] == old["replacements"])
                      and (not old["completed"] or current["completed"] is True),
                      "renewal erased or rewrote a retained successor intent")
            for key, row in outgoing.items():
                purchase, offer = row["purchase"], row["offer"]
                channel = channels.get(purchase["channel"]["id"])
                check(channel is not None and channel["owner"] == name
                      and purchase["channel"] == channel["terms"] and row["funding_id"] == channel["key"]
                      and purchase["provider"] == self.identities["n02"], "renewal route changed its funding owner")
                contract = purchase["contract"]
                check(contract["id"] == key and contract["channel_id"] == purchase["channel"]["id"]
                      and contract["destination"] == self.identities["n03" if name == "n01" else "n01"]
                      and contract["billing"] == "forwarding_data"
                      and contract["price"] == {"msat": 1, "per_bytes": 1024}
                      and contract["max_units"] == offer["max_units"] == QUOTE_UNITS
                      and offer.get("trial", False) is False, "renewal changed route price, destination or allowance")
            lineage[name] = []
            for old_id, renewal in controller["renewals"].items():
                check(old_id in channels and channels[old_id]["owner"] == name
                      and len(renewal["previous"]) == 1, "renewal lacks one retained predecessor")
                previous = renewal["previous"][0]
                old_key = previous["purchase"]["contract"]["id"]
                check(old_key in outgoing and outgoing[old_key]["purchase"] == previous["purchase"]
                      and previous["purchase"]["channel"]["id"] == old_id,
                      "renewal changed its predecessor purchase")
                if not renewal["completed"]:
                    continue
                offers = renewal["replacements"]
                check(old_id in refunds and outgoing[old_key]["retired"] is True
                      and isinstance(offers, list) and len(offers) == 1,
                      "completed renewal lacks predecessor refund and one replacement")
                successors = [row for row in outgoing.values() if row["offer"] == offers[0]]
                check(len(successors) == 1 and successors[0]["accepted"] is True,
                      "completed renewal lacks an accepted successor")
                next_purchase = successors[0]["purchase"]
                successor = next_purchase["channel"]["id"]
                check(successor != old_id and successor in channels, "renewal reused closed funding")
                for key in ("buyer", "provider", "destination", "next_hop", "path", "price", "billing", "mint_url"):
                    check(offers[0][key] == previous["offer"][key], "renewal changed its quoted service")
                lineage[name].append({"previous": old_id, "replacement": successor,
                    "previous_paid_sat": refunds[old_id]["paid_sat"],
                    "replacement_signed_sat": state["buyer"]["channels"][successor]["authorized_sat"]})
        return lineage

    def check_seller(self, raw, summary, channels):
        for name, state in raw.items():
            rows = state["seller"]["ledger"]["channels"]
            check(len({row["terms"]["id"] for row in rows}) == len(rows)
                  and (name == "n02" or not rows), "renewal created an unexpected provider channel")
            check({row["terms"]["id"] for row in self.previous[name]["seller"]["ledger"]["channels"]}
                  <= {row["terms"]["id"] for row in rows}, "renewal erased provider history")
            for row in rows:
                key, usage = row["terms"]["id"], row["usage"]
                # Buyer and provider snapshots are not atomic across devices.
                consistent_observation(key in channels, "provider registration changed during renewal sampling")
                signed = summary[channels[key]["owner"]]["signed_after"].get(key)
                consistent_observation(signed is not None, "buyer acceptance changed during renewal sampling")
                check(row["terms"] == channels[key]["terms"] and amount(usage["paid_msat"]) <= amount(signed) * 1000
                      and amount(usage["lost_msat"]) == 0
                      and amount(usage["submitted_msat"]) <= amount(usage["reserved_msat"])
                      <= min(32000, usage["paid_msat"] + 8000), "seller exceeded retained credit or exposure")
                previous = next((old for old in self.previous[name]["seller"]["ledger"]["channels"]
                                 if old["terms"]["id"] == key), None)
                if previous:
                    check(all(usage[field] >= previous["usage"][field]
                              for field in ("paid_msat", "submitted_msat", "reserved_msat")),
                          "renewal reset provider accounting")

    def collect(self):
        # Only after both exact senders have terminated. Do not pause renewal
        # during the measured stream or use settlement to prove automatic credit.
        errors = []
        for name in NAMES:
            try:
                self.run.ctl(name, "pause_renewals")
            except Exception as error:
                errors.append({"node": name, "error": type(error).__name__})
        self.run.evidence["renewal_pause_errors"] = errors
        require(not errors, "renewal pause incomplete; original accounts retained")
        self.paused = True
        observed, fixture = eventually("known renewal accounts before collection", self.observe)
        require(all(state["budget"]["pending_reserved_sat"] == 0
                    for state in observed["financial"].values()), "unresolved renewal funding retains all accounts")
        self.run.evidence["renewal_before_collection"] = observed
        settle_and_collect(self.run, observed["financial"], execute=self.run.account_execute,
            stop=lambda name: self.run.nodes[name].stop(),
            export_path=lambda name, relative: self.run.nodes[name].state + "/" + relative, fixture=fixture)
        self.run.phase("all 384 renewal test sats collected; every test wallet empty")
