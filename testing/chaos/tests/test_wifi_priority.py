"""Reject fabricated overlap/pressure and preserve normal three-account recovery."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_priority import PriorityRun, parser
from sim.wifi_priority_checks import (
    acknowledged, adjacency, bounded_free, free_policy, loopback_address, patch_config,
    payment, pressure_pair, received, running, submitted, workload,
)


def arguments(**changes):
    args = parser().parse_args([
        "--inventory", "/inventory.json", "--binary", "/relay", "--mint-binary", "/mint",
        "--mint-address", "127.0.0.1", "--mint-ssh-forward", "--output", "/new-output",
    ])
    for name, value in changes.items():
        setattr(args, name, value)
    return args


def middle(stamp, *, drops=0, admitted=10, charged=100):
    return {
        "host_process": {"host": "n02", "pid": 22, "start_ticks": 100},
        "sample_timing": {"started_monotonic_ns": stamp * 1_000_000_000,
                          "finished_monotonic_ns": stamp * 1_000_000_000 + 100_000_000},
        "native": {"status": {"data": {"forwarding": {
            "drop_background_full_packets": drops, "drop_background_full_bytes": drops * 1000,
        }}}},
        "free_routes": {"bandwidth": {
            "admitted_packets": admitted, "charged_units": charged, "rate_denied": 0,
            "peer_capacity_denied": 0, "tracked_peers": 1,
        }},
    }


def segment(stamp, before, after, drops):
    return {"receiver_before": {"unique_packets": before}, "middle": middle(stamp, drops=drops),
            "receiver_after": {"unique_packets": after}}


def reports(count=24, size=128):
    shape = {"stream_id": "a" * 32, "packet_count": count, "payload_bytes": size}
    sent = {"stream_id": shape["stream_id"], "requested_packets": count, "submitted_packets": count,
            "submitted_bytes": count * size, "stopped_reason": None}
    receiver = {"stream_id": shape["stream_id"], "source": "paid-source", "expected_packets": count,
                "payload_bytes": size, "unique_packets": count, "unique_bytes": count * size,
                "missing_packets": 0, "duplicate_packets": 0, "invalid_packets": 0, "latency": None}
    return shape, sent, receiver


def payment_status(evidence=500, authorized=1, ack=1000):
    return {"measurements": {"version": 1, "process_id": 11}, "payment_progress": {"original": {
        "evidence_msat": evidence, "authorized_sat": authorized, "acknowledged_msat": ack, "in_flight": False,
    }}}


class EvidenceTests(unittest.TestCase):
    def test_only_middle_overflow_during_partial_paid_progress_counts(self):
        first, last = segment(0, 2, 3, 10), segment(1, 5, 6, 12)
        self.assertEqual(pressure_pair(first, last, 24), {
            "drop_background_full_packets": 2, "drop_background_full_bytes": 2000,
        })
        for changed in (segment(1, 5, 6, 10), segment(1, 24, 24, 12),
                        segment(1, 0, 0, 12), segment(1, 3, 3, 12)):
            self.assertFalse(pressure_pair(first, changed, 24))
        for field, value in (("host", "n01"), ("pid", 99), ("start_ticks", 999)):
            changed = copy.deepcopy(last)
            changed["middle"]["host_process"][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                pressure_pair(first, changed, 24)
        with self.assertRaises(RuntimeError):
            pressure_pair(first, segment(1, 5, 6, 9), 24)

    def test_complete_paid_delivery_checks_bytes_identity_duplicates_and_latency(self):
        shape, sent, receiver = reports()
        submitted(sent, shape)
        self.assertEqual(received(receiver, shape, "paid-source", complete=True), 24)
        for changes in ({"source": "free-source"}, {"stream_id": "b" * 32},
                        {"unique_packets": 23, "unique_bytes": 23 * 128, "missing_packets": 1},
                        {"duplicate_packets": 1}, {"invalid_packets": 1}, {"unique_bytes": 1},
                        {"latency": {"samples": 24}}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                received({**receiver, **changes}, shape, "paid-source", complete=True)
        for changes in ({"submitted_packets": 23}, {"submitted_bytes": 1},
                        {"stopped_reason": "duration limit"}, {"stream_id": "b" * 32}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                submitted({**sent, **changes}, shape)
        partial = {**receiver, "unique_packets": 2, "unique_bytes": 256, "missing_packets": 22}
        self.assertEqual(received(partial, shape, "paid-source"), 2)

    def test_future_completion_cannot_be_called_concurrent_traffic(self):
        future = Mock()
        future.done.return_value = False
        running(future)
        future.result.assert_not_called()
        future.done.return_value = True
        with self.assertRaisesRegex(RuntimeError, "free sender completed"):
            running(future)
        future.result.side_effect = ValueError("actual sender failure")
        with self.assertRaisesRegex(ValueError, "actual sender failure"):
            running(future)

    def test_payment_must_advance_and_acknowledge_the_same_process_and_channel(self):
        first, last = payment(payment_status()), payment(payment_status(2000, 2, 2000))
        self.assertTrue(acknowledged(first, last))
        for changes in ({"acknowledged_msat": None}, {"acknowledged_msat": 1999},
                        {"in_flight": True}, {"evidence_msat": 500}, {"authorized_sat": 1}):
            self.assertFalse(acknowledged(first, {**last, **changes}))
        for changes in ({"channel": "replacement"}, {"process_id": 99}, {"evidence_msat": 1}):
            with self.assertRaises(RuntimeError):
                acknowledged(first, {**last, **changes})
        bad = payment_status()
        bad["payment_progress"]["other"] = bad["payment_progress"]["original"]
        with self.assertRaises(RuntimeError):
            payment(bad)

    def test_free_allowance_uses_charged_units_and_conservative_sample_bracket(self):
        first, last = middle(0, charged=100), middle(2, admitted=20, charged=140)
        policy = {"global_bytes_per_second": 10, "global_burst_bytes": 10,
                  "peer_bytes_per_second": 10, "peer_burst_bytes": 10}
        evidence = bounded_free(first, last, policy)
        self.assertEqual(evidence["charged_units"], 40)
        self.assertEqual(evidence["elapsed_seconds_upper_bound"], 3)
        last["free_routes"]["bandwidth"]["charged_units"] = 141
        with self.assertRaises(RuntimeError):
            bounded_free(first, last, policy)
        for key, value in (("tracked_peers", 2), ("peer_capacity_denied", 1), ("admitted_packets", 10)):
            last = middle(2, admitted=20, charged=120)
            last["free_routes"]["bandwidth"][key] = value
            with self.assertRaises(RuntimeError):
                bounded_free(first, last, policy)


class TopologyTests(unittest.TestCase):
    def fixture(self):
        edges = {"n01": {"n02": "ethernet"},
                 "n02": {"n01": "ethernet", "n03": "ethernet", "free-source": "udp"},
                 "n03": {"n02": "ethernet", "free-sink": "udp"},
                 "free-source": {"n02": "udp"}, "free-sink": {"n03": "udp"}}
        identities = {name: "npub-" + name for name in edges}
        addresses = {name: f"127.0.0.1:{1000 + i}" for i, name in enumerate(edges) if name != "n01"}
        states = {name: {"npub": identities[name], "peers": [
            {"npub": identities[other], "transport": transport, "connected": True,
             "address": addresses[other] if transport == "udp" else "mesh-peer"}
            for other, transport in neighbors.items()]} for name, neighbors in edges.items()}
        return states, identities, addresses

    def test_exact_five_identity_adjacency_has_no_management_or_wireless_shortcut(self):
        states, identities, addresses = self.fixture()
        self.assertIs(adjacency(states, identities, addresses), states)
        for field, value in (("connected", False), ("transport", "udp"), ("npub", identities["n03"])):
            changed = copy.deepcopy(states)
            changed["n01"]["peers"][0][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                adjacency(changed, identities, addresses)
        states["free-source"]["peers"][0]["address"] = "192.0.2.1:1002"
        with self.assertRaises(RuntimeError):
            adjacency(states, identities, addresses)
        for address in ("0.0.0.0:1234", "127.0.0.2:1234", "127.0.0.1:0", "127.0.0.1:65536"):
            with self.assertRaises(RuntimeError):
                loopback_address(address)


class ConfigurationTests(unittest.TestCase):
    def service(self, **args):
        service = object.__new__(PriorityRun)
        service.args = arguments(**args)
        service.schedule = workload(service.args)
        service.mint_url = "http://127.0.0.1:12345"
        service.nodes = {name: Mock(interface="mesh0", state="/owned/" + name, npub=name)
                         for name in ("n01", "n02", "n03")}
        return service

    def test_profiles_keep_three_funded_accounts_and_only_expected_loopback_transports(self):
        service = self.service()
        for name, node in service.nodes.items():
            config = service.profile_config(node)
            self.assertEqual(config["state_directory"], node.state)
            self.assertEqual("udp" in config["transports"], name != "n01")
            self.assertFalse(config["return_allowance"])
            self.assertEqual(config["terms"]["quote_max_units"], 96 * 1024 * 1024)
            self.assertEqual(config["terms"]["controller"]["channel_capacity_sat"], 32)
            self.assertEqual(config["terms"]["controller"]["max_wallet_spend_sat"], 128)
            self.assertIsNone(config["terms"]["controller"]["renewal"])
            if name == "n02":
                self.assertEqual(config["free_bandwidth"], free_policy(service.schedule))
        config = service.auxiliary_config(Mock(state="/owned/aux/state"))
        self.assertEqual(set(config["transports"]), {"udp"})
        self.assertEqual(config["transports"]["udp"]["bind_addr"], "127.0.0.1:0")
        self.assertFalse(config["transports"]["udp"]["advertise_on_nostr"])
        self.assertEqual(config["terms"]["fee_msat_per_kib"], 0)
        self.assertEqual(config["terms"]["max_rate_msat_per_kib"], 0)
        self.assertEqual(config["neighbors"], [])

    def test_post_init_updates_cannot_change_immutable_terms_or_transports(self):
        original = self.service().auxiliary_config(Mock(state="/owned/aux/state"))
        changed = patch_config(original, {"destination_fees": {"sink": 0}, "neighbors": []})
        self.assertEqual(changed["terms"], original["terms"])
        self.assertEqual(changed["state_directory"], original["state_directory"])
        self.assertNotIn("destination_fees", original)
        for field in ("terms", "state_directory", "transports", "return_allowance"):
            with self.assertRaises(RuntimeError):
                patch_config(original, {field: None})

    def test_workloads_are_bounded_by_real_probe_and_small_paid_fixture_limits(self):
        self.assertEqual(workload(arguments())["free_packets"], 64000)
        for changes in ({"free_packets": 65537}, {"free_rate": 16001}, {"free_bytes": 1001},
                        {"paid_bytes": 1000}, {"paid_packets": 65}, {"free_burst_bytes": 1},
                        {"free_rate": True}, {"free_rate": 1}, {"overlap_seconds": 31}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                workload(arguments(**changes))

    def test_auxiliary_profiles_are_registered_before_guard_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mint = root / "mint"
            mint.write_bytes(b"a provided executable, not run by this test")
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps({"nodes": [{
                "host": "lab" + str(i), "interface": "mesh0", "management_interface": "br-lan",
                "original_binary": "/usr/bin/original", "original_config": "/etc/original.json",
                "state_parent": "/etc/bench",
            } for i in range(3)]}))
            service = PriorityRun(arguments(inventory=inventory, mint_binary=mint, output=root / "result"))
            self.assertEqual(set(service.nodes), {"n01", "n02", "n03"})
            self.assertEqual(len(service.nodes["n01"].profiles()), 1)
            self.assertEqual(len(service.nodes["n02"].profiles()), 2)
            self.assertEqual(len(service.nodes["n03"].profiles()), 2)
            accounts = {(getattr(p, "owner", p).host, p.state)
                        for p in service.participants().values()}
            self.assertEqual(len(accounts), 5)
            self.assertTrue(all(not node.created for node in service.nodes.values()))

    def test_auxiliary_accounts_cannot_acquire_money_or_change_financial_journals(self):
        service = self.service()
        profile = Mock()
        service.auxiliary = {"free-source": profile}
        service.auxiliary_initial = {"free-source": {"buyer": "original empty account"}}
        profile.monetary_journals.return_value = {"buyer": "original empty account"}
        profile.control.return_value = {"mint_url": service.mint_url, "unit": "sat", "balance_sat": 0}
        service.verify_auxiliary(stopped=True)
        profile.control.return_value["balance_sat"] = 1
        with self.assertRaisesRegex(RuntimeError, "acquired funds"):
            service.verify_auxiliary(stopped=True)
        profile.control.return_value["balance_sat"] = 0
        profile.monetary_journals.return_value = {"buyer": "changed account"}
        with self.assertRaisesRegex(RuntimeError, "financial journals changed"):
            service.verify_auxiliary(stopped=True)

    def test_topology_only_preparation_never_invokes_funding(self):
        service = self.service(topology_only=True, mint_ssh_forward=False)
        service.auxiliary = {name: Mock(state="/owned/" + name, npub=name)
                             for name in ("free-source", "free-sink")}
        service.auxiliary_initial, service.evidence = {}, {}
        service.configure_stopped, service.phase, service.verify_auxiliary = Mock(), Mock(), Mock()
        with patch("sim.wifi_priority.PaidWifiRun.before_launch") as funded:
            service.before_launch()
        funded.assert_not_called()
        self.assertEqual(service.configure_stopped.call_count, 5)
        for call in service.configure_stopped.call_args_list:
            self.assertEqual(call.kwargs, {"destination_fees": {"free-sink": 0}})
        service.verify_auxiliary.assert_called_once_with(stopped=True)


class RecoveryTests(unittest.TestCase):
    def service(self):
        service = object.__new__(PriorityRun)
        service.args = arguments()
        service.nodes = {name: Mock(npub=name) for name in ("n01", "n02", "n03")}
        service.evidence, service.channel_anchor = {}, None
        for name in ("form_line", "start_auxiliaries", "open_free", "verify_shortcuts", "collect", "save"):
            setattr(service, name, Mock())
        service.finances = Mock(return_value={"fixed": "original channels"})
        service.paid_streams = Mock(return_value={"fixed": "warmed original channels"})
        service.ctl, service.mixed = Mock(), Mock()
        return service

    def test_inconclusive_pressure_still_collects_known_funds_and_preserves_failure(self):
        service = self.service()
        service.mixed.side_effect = RuntimeError("no observed n02 background overflow")
        with patch("sim.wifi_priority.original_channels"), patch("sim.wifi_priority.signal.alarm") as alarm:
            with self.assertRaisesRegex(RuntimeError, "no observed n02"):
                service.exercise()
        service.collect.assert_called_once_with()
        alarm.assert_called_once_with(0)
        self.assertIn("no observed n02", service.evidence["acceptance_failure"])
        self.assertFalse(service.evidence["mixed_priority_accepted"])

    def test_uncertain_purchase_is_neither_retried_nor_blindly_collected(self):
        service = self.service()
        service.ctl.side_effect = TimeoutError("uncertain purchase")
        with self.assertRaises(TimeoutError):
            service.exercise()
        service.ctl.assert_called_once_with("n01", "buy", destination="n03")
        service.collect.assert_not_called()

    def test_settlement_failure_retains_both_the_acceptance_and_collection_failures(self):
        service = self.service()
        service.mixed.side_effect = RuntimeError("insufficient overlap")
        service.collect.side_effect = RuntimeError("uncertain settlement")
        with patch("sim.wifi_priority.original_channels"), patch("sim.wifi_priority.signal.alarm"):
            with self.assertRaisesRegex(RuntimeError, "uncertain settlement"):
                service.exercise()
        self.assertEqual(service.evidence["acceptance_failure"], "insufficient overlap")
        self.assertEqual(service.evidence["collection_failure"], "uncertain settlement")


if __name__ == "__main__":
    unittest.main()
