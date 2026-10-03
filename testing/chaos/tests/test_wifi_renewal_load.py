"""Continuous workload and retained renewal authority without devices or funds."""

import copy
import json
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.paid_settlement import SettlementFixture, settle_and_collect
from sim.paid_finances import FinancialObservationChanged
from sim.wifi_profiles import RelayCommands
from sim.wifi_renewal_finances import NAMES, QUOTE_UNITS, RENEWAL, RenewalAccounts
from sim.wifi_renewal_load import PACKETS, RATE, RenewalLoadRun, validate
from tests.test_paid_settlement import FakeRun
from tests.test_wifi_promotion_finances import IDS, MINT, add_channel, add_route, empty, settle, summary
from tests.test_wifi_priority import reports


class AccountsFixture:
    def __init__(self):
        self.raw = empty()
        for state in self.raw.values():
            state["controller"]["policy"]["renewal"] = dict(RENEWAL)
            state["controller"]["renewals_paused"] = False
            state["seller"].update(version=2, window_msat=4000)
        self.run = Mock(mint_url=MINT)
        self.run.nodes = {name: SimpleNamespace(npub=name, state="/tmp/bench-state", stop=Mock()) for name in NAMES}
        self.run.evidence = {"phases": []}
        self.run.finances.side_effect = lambda: summary(self.raw)
        self.run.state_json.side_effect = lambda name, path: copy.deepcopy(self.raw[name][path.split('/')[0]])
        self.accounts = RenewalAccounts(self.run, IDS)

    def channel(self, source, suffix, paid):
        terms = add_channel(self.raw, source, suffix, paid)
        terms.update(expires_unix=1000, refund_after_unix=1900)
        intent = self.raw[source]["controller"]["funding"]["fund-" + suffix]
        intent.update(expires_unix=1000, refund_after_unix=1900)
        intent["funded"]["terms"] = copy.deepcopy(terms)
        self.raw[source]["buyer"]["channels"][terms["id"]]["terms"] = copy.deepcopy(terms)
        self.raw["n02"]["seller"]["ledger"]["channels"][-1]["terms"] = copy.deepcopy(terms)
        purchase = add_route(self.raw, source, terms, "quote-" + suffix, quota=QUOTE_UNITS, used=paid * 1024 * 1000)
        purchase["contract"]["price"] = {"msat": 1, "per_bytes": 1024}
        outgoing = self.raw[source]["controller"]["outgoing"][purchase["contract"]["id"]]
        outgoing["purchase"] = copy.deepcopy(purchase)
        self.raw[source]["buyer"]["quotes"][purchase["contract"]["id"]]["contract"] = copy.deepcopy(purchase["contract"])
        outgoing["offer"].update(buyer=IDS[source], provider=IDS["n02"], destination=purchase["contract"]["destination"],
            next_hop=purchase["contract"]["next_hop"], path=[IDS["n02"], purchase["contract"]["destination"]],
            price=purchase["contract"]["price"], billing="forwarding_data", mint_url=MINT)
        return outgoing

    def funded(self):
        self.original = {name: self.channel(name, name + "-old", 26) for name in ("n01", "n03")}
        self.accounts.observe()
        return self

    def renewed(self):
        for name, outgoing in self.original.items():
            before = copy.deepcopy(outgoing)
            old = outgoing["purchase"]["channel"]["id"]
            settle(self.raw, name, old)
            outgoing["retired"] = True
            new = self.channel(name, name + "-new", 10)
            self.raw[name]["controller"]["renewals"][old] = {
                "previous": [before], "replacements": [copy.deepcopy(new["offer"])], "completed": True}
        return self


def accepted_evidence():
    shape, sent, received = reports(PACKETS, 1000)
    sent["elapsed_us"] = (PACKETS - 1) * 1_000_000 // RATE
    streams = {}
    for index, name in enumerate(("n01", "n03"), 1):
        identifier = f"{index:032x}"
        streams[name] = {"shape": {**shape, "stream_id": identifier},
            "sender": {**sent, "stream_id": identifier},
            "receiver": {**received, "stream_id": identifier, "source": name}, "dispatch_started": 100}
    def observation(count, credit):
        return {"ended_at": 100 + count, "accounts": {
            "renewals": {name: [{"previous": "old-" + name, "replacement": "new-" + name}]
                         for name in ("n01", "n03")},
            "financial": {"n02": {"credited": {"new-n01": credit, "new-n03": credit}}}},
            "receivers": {name: {**row["receiver"], "unique_packets": count,
                "unique_bytes": count * 1000, "missing_packets": PACKETS - count} for name, row in streams.items()}}
    process = {"npub": "identity", "host_process": {"host": "host", "pid": 10, "start_ticks": 20}}
    return {"streams": streams, "samples": [observation(100, 1000), observation(110, 2000)],
        "accounts_after": {"renewals": {name: [{}] for name in ("n01", "n03")},
            "financial": {name: {"funding": {"old": [], "new": []}, "signed": {"new-" + name: 2},
                                 "authorized": 28} for name in ("n01", "n03")}},
        "before": dict.fromkeys(NAMES, process), "after": dict.fromkeys(NAMES, process)}


class RenewalTests(unittest.TestCase):
    def test_config_preserves_both_spend_limits_and_enables_only_explicit_renewal(self):
        run = object.__new__(RenewalLoadRun)
        run.args, run.mint_url = SimpleNamespace(), MINT
        cfg = run.profile_config(Mock(interface="mesh0", state="/private/state"))
        self.assertEqual(cfg["terms"]["buyer_budget_sat"], 64)
        self.assertEqual(cfg["terms"]["controller"], {
            "mint_url": MINT, "channel_capacity_sat": 32, "max_locked_sat": 64,
            "max_wallet_spend_sat": 128, "max_funding_overhead_sat": 0,
            "channel_lifetime_secs": 1800, "renewal": RENEWAL})
        self.assertEqual((cfg["terms"]["window_msat"], cfg["terms"]["grace_msat"]), (4000, 8000))
        self.assertEqual((cfg["terms"]["quote_lifetime_secs"], cfg["terms"]["quote_max_units"]), (1200, QUOTE_UNITS))

    def test_control_timeout_is_local_bounded_and_default_unchanged(self):
        node = RelayCommands()
        node.binary, node.config = "/owned/relay", "/owned/config.json"
        node.remote = Mock(return_value=b'{}')
        node.control("status")
        self.assertEqual(node.remote.call_args.kwargs["timeout"], 45)
        node.control("send_probe", operation_timeout=330, probe={"max_duration_secs": 300})
        self.assertEqual(node.remote.call_args.kwargs["timeout"], 330)
        self.assertEqual(json.loads(node.remote.call_args.args[1]),
                         {"type": "send_probe", "probe": {"max_duration_secs": 300}})
        for value in (True, 0, 331, 45.0):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                node.control("status", operation_timeout=value)

    def test_real_replacement_retains_refunds_lineage_and_secret_free_evidence(self):
        f = AccountsFixture().funded().renewed()
        observed, fixture = f.accounts.observe()
        self.assertEqual(len(fixture.channel_owners), 4)
        self.assertEqual(set(fixture.prior_settlements), {"channel-n01-old", "channel-n03-old"})
        self.assertEqual(observed["financial"]["n01"]["budget"]["wallet_refunded_sat"], 6)
        self.assertEqual(observed["financial"]["n01"]["remaining"], 28)
        self.assertEqual(observed["renewals"]["n01"], [{"previous": "channel-n01-old",
            "replacement": "channel-n01-new", "previous_paid_sat": 26, "replacement_signed_sat": 10}])
        self.assertNotIn("SECRET-PROOF", json.dumps(observed))

    def test_changed_funding_authority_refund_or_successor_cannot_pass(self):
        changes = (
            lambda f: f.raw["n02"]["seller"].update(window_msat=8000),
            lambda f: f.raw["n01"]["controller"]["policy"].update(max_wallet_spend_sat=129),
            lambda f: f.raw["n01"]["buyer"].update(total_budget_sat=128),
            lambda f: f.raw["n01"]["buyer"]["channels"]["channel-n01-old"].update(authorized_sat=25),
            lambda f: f.raw["n01"]["controller"]["funding"]["fund-n01-old"]["funded"].update(wallet_operation_id="other"),
            lambda f: f.raw["n01"]["controller"]["buyer_settlements"]["channel-n01-old"].update(wallet_refund_sat=7),
            lambda f: f.raw["n01"]["controller"]["renewals"]["channel-n01-old"]["replacements"][0].update(price={"msat": 2, "per_bytes": 1024}),
            lambda f: f.raw["n01"]["controller"]["outgoing"]["quote-n01-new"].update(accepted=False),
        )
        for change in changes:
            f = AccountsFixture().funded().renewed()
            change(f)
            with self.subTest(change=change), self.assertRaises(ValueError):
                f.accounts.observe()

    def test_acceptance_needs_delivery_and_fresh_successor_credit_during_both_sends(self):
        evidence = accepted_evidence()
        validate(evidence, dict(zip(NAMES, NAMES)))
        changes = (
            lambda e: e["streams"]["n01"]["sender"].update(submitted_packets=PACKETS - 1),
            lambda e: e["streams"]["n01"]["receiver"].update(unique_packets=PACKETS - 1, unique_bytes=(PACKETS - 1) * 1000, missing_packets=1),
            lambda e: e["samples"][-1]["accounts"]["financial"]["n02"]["credited"].update({"new-n01": 1000}),
            lambda e: e["samples"][-1]["receivers"]["n01"].update(unique_packets=100),
            lambda e: e["samples"][-1].update(ended_at=500),
            lambda e: e["accounts_after"]["financial"]["n01"]["funding"].update(extra=[]),
        )
        for change in changes:
            candidate = copy.deepcopy(evidence)
            change(candidate)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                validate(candidate, dict(zip(NAMES, NAMES)))

    def test_self_consistent_shorter_workload_or_reused_stream_cannot_pass(self):
        for count, size in ((1, 1000), (PACKETS, 999)):
            evidence = accepted_evidence()
            row = evidence["streams"]["n01"]
            row["shape"].update(packet_count=count, payload_bytes=size)
            row["sender"].update(requested_packets=count, submitted_packets=count, submitted_bytes=count * size)
            row["receiver"].update(expected_packets=count, unique_packets=count, unique_bytes=count * size,
                                   payload_bytes=size, missing_packets=0)
            with self.subTest(count=count, size=size), self.assertRaisesRegex(RuntimeError, "distinct exact"):
                validate(evidence, dict(zip(NAMES, NAMES)))
        evidence = accepted_evidence()
        identifier = evidence["streams"]["n01"]["shape"]["stream_id"]
        for key in ("shape", "sender", "receiver"):
            evidence["streams"]["n03"][key]["stream_id"] = identifier
        with self.assertRaisesRegex(RuntimeError, "distinct exact"):
            validate(evidence, dict(zip(NAMES, NAMES)))
        evidence = accepted_evidence()
        evidence["samples"][0]["receivers"]["n01"]["source"] = "n03"
        with self.assertRaisesRegex(RuntimeError, "identity or shape"):
            validate(evidence, dict(zip(NAMES, NAMES)))

    def test_only_live_snapshot_disagreement_is_retryable(self):
        f = AccountsFixture().funded()
        observed = summary(f.raw)
        observed["n01"]["signed"]["channel-n01-old"] += 1
        observed["n01"]["signed_after"]["channel-n01-old"] += 1
        observed["n01"]["authorized"] += 1
        observed["n01"]["remaining"] -= 1
        f.run.finances.side_effect = None
        f.run.finances.return_value = observed
        with self.assertRaisesRegex(FinancialObservationChanged, "authorization changed"):
            f.accounts.observe()
        observed["n01"]["remaining"] += 1
        with self.assertRaisesRegex(ValueError, "lifetime buyer budget"):
            f.accounts.observe()
        f.run.finances.side_effect = RuntimeError("invalid monetary evidence")
        with self.assertRaisesRegex(ValueError, "invalid monetary evidence"):
            f.accounts.observe()

    def test_later_signature_snapshot_preserves_total_budget_and_all_seen_liability(self):
        for later in ({"channel-n01-old": 32, "channel-n01-new": 32, "third": 1},
                      {"channel-n01-old": 25, "channel-n01-new": 10},
                      {"channel-n01-new": 10}):
            f = AccountsFixture().funded().renewed()
            observed = summary(f.raw)
            observed["n01"]["signed_after"] = later
            f.run.finances.side_effect = None
            f.run.finances.return_value = observed
            with self.subTest(later=later), self.assertRaises(ValueError):
                f.accounts.observe()
        f = AccountsFixture().funded().renewed()
        observed = summary(f.raw)
        observed["n01"]["signed_after"]["channel-n01-new"] = 11
        f.run.finances.side_effect = None
        f.run.finances.return_value = observed
        f.accounts.observe()
        observed["n01"]["signed_after"]["channel-n01-new"] = 10
        with self.assertRaisesRegex(ValueError, "later buyer snapshot lost signed liability"):
            f.accounts.observe()

    def test_delivery_failure_still_collects_without_replaying_or_pausing_the_stream(self):
        run = object.__new__(RenewalLoadRun)
        run.nodes = {name: SimpleNamespace(npub=name) for name in NAMES}
        run.evidence = {"renewal_load": {}}
        run.form_line, run.save, run.phase, run.ctl, run.warmup = Mock(), Mock(), Mock(), Mock(), Mock()
        run.samples = Mock(return_value={name: {"native": {"status": {"data": {
            "npub": name, "node_addr": bytes(IDS[name]).hex()}}}} for name in NAMES})
        run.continuous_streams = Mock(side_effect=RuntimeError("delivery lost"))
        accounts = Mock()
        accounts.observe.return_value = ({"financial": {name: {"funding": {"first": []}} for name in NAMES}}, None)
        with patch("sim.wifi_renewal_load.RenewalAccounts", return_value=accounts), \
             patch("sim.wifi_renewal_load.signal.alarm"), self.assertRaisesRegex(RuntimeError, "delivery lost"):
            run.exercise()
        run.continuous_streams.assert_called_once_with(accounts)
        accounts.collect.assert_called_once_with()
        self.assertEqual([call.args[1] for call in run.ctl.call_args_list], ["buy", "buy"])

    def test_both_receivers_arm_first_and_failed_observation_drains_both_exact_senders(self):
        run = object.__new__(RenewalLoadRun)
        run.nodes = dict.fromkeys(NAMES)
        run.evidence = {"renewal_load": {"streams": {}, "samples": [], "sample_errors": []}}
        run.samples, run.save = Mock(return_value={}), Mock()
        shape, sent, raw = reports(PACKETS, 1000)
        raw.update(unique_packets=1, unique_bytes=1000, missing_packets=PACKETS - 1)
        run.ctl = Mock(return_value={"probe": raw})
        armed, sending, finished = [], [], []
        release, ready = threading.Event(), threading.Event()
        def arm(_run, source, *_args, **kwargs):
            self.assertEqual(kwargs, {"lifetime_secs": 360})
            armed.append(source)
            return copy.deepcopy(shape)
        def send(_run, source, *_args, **kwargs):
            self.assertEqual(armed, ["n01", "n03"])
            self.assertEqual(kwargs, {"max_duration_secs": 300, "operation_timeout": 330})
            sending.append(source)
            if len(sending) == 2:
                ready.set()
            self.assertTrue(release.wait(3))
            finished.append(source)
            return sent
        observations = []
        def observe():
            self.assertTrue(ready.wait(3))
            observations.append(1)
            if len(observations) == 1:
                raise FinancialObservationChanged("authorization changed during renewal sampling")
            release.set()
            raise RuntimeError("bad financial invariant")
        accounts = SimpleNamespace(observe=observe)
        with patch("sim.wifi_renewal_load.probes.arm", side_effect=arm), \
             patch("sim.wifi_renewal_load.probes.send", side_effect=send) as dispatch, \
             patch("sim.wifi_renewal_load.time.sleep"), \
             self.assertRaisesRegex(RuntimeError, "bad financial invariant"):
            run.continuous_streams(accounts)
        self.assertEqual(sorted(finished), ["n01", "n03"])
        self.assertEqual(dispatch.call_count, 2)
        self.assertEqual(len(observations), 2)
        errors = run.evidence["renewal_load"]["sample_errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual((errors[0]["error"], errors[0]["reason"]),
                         ("FinancialObservationChanged", "authorization changed during renewal sampling"))
        self.assertEqual(run.evidence["renewal_load"]["observation_failure"],
                         {"error": "RuntimeError", "reason": "bad financial invariant"})
        for row in run.evidence["renewal_load"]["streams"].values():
            self.assertEqual(row["sender"], sent)
            self.assertEqual(row["receiver"]["unique_packets"], 1)


class PriorSettlementTests(unittest.TestCase):
    def fixture(self):
        run = FakeRun()
        old = copy.deepcopy(run.reports["n01"][0])
        old.update(channel_id="old-n01", paid_sat=26, refunded_sat=6)
        for values, settled in ((run.prior, False), (run.settled, True)):
            state = values["n01"]
            state["funding"]["old-funding"] = ("old-n01", "old-operation")
            state["signed"]["old-n01"] = 26
            state["authorized"] += 26
            state["remaining"] -= 26
            state["budget"]["wallet_debited_sat"] += 32
            state["budget"]["wallet_refunded_sat"] += 6
            state["budget"]["exposure_sat"] += 26
        run.reports["n01"].append(copy.deepcopy(old))
        run.balances["n01"] -= 26
        run.balances["n02"] += 26
        owners = {channel: name for name, state in run.prior.items() for channel, _ in state["funding"].values()}
        for values in (run.prior, run.settled):
            values["n02"]["credited"] = {channel: values[owner]["signed"][channel] * 1000
                                         for channel, owner in owners.items()}
        fixture = SettlementFixture(dict.fromkeys(NAMES, 128), dict.fromkeys(NAMES, 64), 32,
                                    owners, dict.fromkeys(owners, "n02"), {"old-n01": old})
        return run, fixture, old

    def test_shared_closure_collects_predecessor_and_successor_exactly_once(self):
        run, fixture, old = self.fixture()
        old["paid_sat"] = 1
        self.assertEqual(fixture.prior_settlements["old-n01"]["paid_sat"], 26)
        with self.assertRaises(TypeError):
            fixture.prior_settlements["old-n01"]["paid_sat"] = 1
        with patch("sim.paid_settlement.stop_relay"):
            settle_and_collect(run, run.prior, fixture=fixture)
        self.assertEqual(run.collected, 384)
        self.assertEqual(len(run.evidence["phases"][-1]["settlement_collection"]["settlements"]), 3)

    def test_prior_refunds_need_exact_owned_reports_and_cannot_relax_default_closure(self):
        run, fixture, _ = self.fixture()
        with self.assertRaises(RuntimeError):
            settle_and_collect(run, run.prior)
        self.assertEqual(run.calls, [])
        for channel, report in (("foreign", dict(fixture.prior_settlements["old-n01"])),
                                ("old-n01", {**fixture.prior_settlements["old-n01"], "paid_sat": 33})):
            with self.subTest(channel=channel), self.assertRaises(RuntimeError):
                SettlementFixture(fixture.initial_balances, fixture.buyer_budgets, 32,
                                  fixture.channel_owners, prior_settlements={channel: report})
        run.reports["n01"][-1].update(paid_sat=25, refunded_sat=7)
        with self.assertRaises(RuntimeError):
            settle_and_collect(run, run.prior, fixture=fixture)
        self.assertFalse(run.exports)


if __name__ == "__main__":
    unittest.main()
