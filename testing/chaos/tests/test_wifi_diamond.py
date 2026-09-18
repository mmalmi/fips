"""A co-located source/destination must still traverse the two chosen links."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from sim.wifi_diamond import DiamondRun, parser
from sim.wifi_diamond_checks import adjacency, denied_stream, listener, management_address
from sim.wifi_profiles import configure_stopped


def topology():
    edges = {
        "source": {"n01": "udp", "n02": "udp"},
        "n01": {"source": "udp", "n03": "ethernet"},
        "n02": {"source": "udp", "n03": "ethernet"},
        "n03": {"n01": "ethernet", "n02": "ethernet"},
    }
    identities = {name: "npub-" + name for name in edges}
    addresses = {"source": "192.168.1.13:4001", "n01": "192.168.1.11:4002", "n02": "192.168.1.12:4003"}
    states = {name: {"npub": identities[name], "peers": [
        {"npub": identities[other], "transport": kind, "connected": True,
         "address": addresses[other] if kind == "udp" else "mesh-peer"}
        for other, kind in peers.items()]} for name, peers in edges.items()}
    return states, identities, addresses


class ObservationTests(unittest.TestCase):
    def test_exact_diamond_and_partial_startup(self):
        states, identities, addresses = topology()
        self.assertIs(adjacency(states, identities, addresses), states)
        del states["source"], identities["source"]
        for name in ("n01", "n02"):
            states[name]["peers"] = states[name]["peers"][1:]
        self.assertIs(adjacency(states, identities, addresses, source=False), states)

    def test_duplicate_stale_local_and_cross_provider_shortcuts_are_rejected(self):
        for node, peer in (("source", "n03"), ("n01", "n02"), ("source", "n01")):
            states, identities, addresses = topology()
            states[node]["peers"].append({"npub": identities[peer], "transport": "udp",
                                         "connected": False, "address": "127.0.0.1:1234"})
            with self.subTest(node=node, peer=peer), self.assertRaises(RuntimeError):
                adjacency(states, identities, addresses)

    def test_wrong_peer_address_transport_identity_or_connectivity_is_rejected(self):
        for field, value in (("address", "127.0.0.1:1234"), ("transport", "ethernet"),
                             ("npub", "other"), ("connected", False)):
            states, identities, addresses = topology()
            states["source"]["peers"][0][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                adjacency(states, identities, addresses)
        states, identities, addresses = topology()
        identities["source"] = identities["n03"]
        with self.assertRaises(RuntimeError):
            adjacency(states, identities, addresses)

    def test_radio_outage_keeps_its_source_udp_edge_and_removes_both_native_views(self):
        states, identities, addresses = topology()
        states["n01"]["peers"] = states["n01"]["peers"][:1]
        states["n03"]["peers"] = states["n03"]["peers"][1:]
        self.assertIs(adjacency(states, identities, addresses, radio_down="n01"), states)
        states["n01"]["peers"] = []
        with self.assertRaises(RuntimeError):
            adjacency(states, identities, addresses, radio_down="n01")

    def test_management_address_requires_a_single_actual_private_interface_address(self):
        record = b"3: br-lan    inet 192.168.1.13/24 scope global br-lan\n"
        self.assertEqual(management_address(record, "br-lan"), "192.168.1.13")
        broadcast = record.replace(b" scope", b" brd 192.168.1.255 scope")
        self.assertEqual(management_address(broadcast, "br-lan"), "192.168.1.13")
        for changed in (b"", record + record, record.replace(b"br-lan", b"mesh0"),
                        record.replace(b"192.168.1.13", b"127.0.0.1"),
                        record.replace(b"192.168.1.13", b"8.8.8.8"),
                        record.replace(b"192.168.1.13", b"192.0.2.1"),
                        record.replace(b"global", b"host"),
                        broadcast.replace(b"192.168.1.255", b"192.168.2.255")):
            with self.subTest(record=changed), self.assertRaises((RuntimeError, ValueError)):
                management_address(changed, "br-lan")

    def test_listener_is_ephemeral_but_bound_to_exact_observed_address(self):
        self.assertEqual(listener("192.168.1.13:4001", "192.168.1.13"), "192.168.1.13:4001")
        for value in ("0.0.0.0:4001", "192.168.1.14:4001", "127.0.0.1:4001",
                      "192.168.1.13:0", "192.168.1.13:65536", "192.168.1.13:http"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                listener(value, "192.168.1.13")

    def test_empty_reception_requires_native_sends_and_actual_provider_denials(self):
        before = {name: {"npub": name, "host_process": {"host": name, "pid": 5, "start_ticks": 10,
                                                       "rss_kib": 100, "rchar": 1000},
                         "native": {"routing": {"data": {"forwarding": {
                             "drop_policy_denied_packets": 0, "drop_policy_denied_bytes": 0,
                         }}}}} for name in ("n01", "n02", "source")}
        before["sessions"] = {"status": "ok", "data": {"sessions": []}}
        after = copy.deepcopy(before)
        for name in ("n01", "n02", "source"):
            after[name]["host_process"].update(rss_kib=200, rchar=2000)
        after["n01"]["native"]["routing"]["data"]["forwarding"].update(
            drop_policy_denied_packets=8, drop_policy_denied_bytes=2800)
        after["sessions"]["data"]["sessions"] = [{"npub": "destination", "state": "established",
                                                   "stats": {"packets_sent": 8, "bytes_sent": 2080}}]
        result = denied_stream(before, after, "destination", 8, 256)
        self.assertEqual(result["source_application_data"]["packets"], 8)
        for changed in ("no_session", "cold_session", "no_sends", "no_drops", "process_reset", "pid_reset"):
            candidate = copy.deepcopy(after)
            session = candidate["sessions"]["data"]["sessions"]
            if changed == "no_session":
                session.clear()
            elif changed == "cold_session":
                session[0]["state"] = "initiating"
            elif changed == "no_sends":
                session[0]["stats"]["packets_sent"] = 0
            elif changed == "no_drops":
                candidate["n01"] = copy.deepcopy(before["n01"])
            elif changed == "pid_reset":
                candidate["source"]["host_process"]["pid"] = 99
            else:
                candidate["source"]["host_process"]["start_ticks"] = 20
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                denied_stream(before, candidate, "destination", 8, 256)


class FixtureTests(unittest.TestCase):
    def service(self):
        run = object.__new__(DiamondRun)
        run.nodes = {name: SimpleNamespace(
            interface="mesh0", management="br-lan", state="/owned/" + name, npub=name,
            remote=Mock(return_value=f"3: br-lan inet 192.168.1.{11 + i}/24 scope global br-lan".encode()),
        ) for i, name in enumerate(("n01", "n02", "n03"))}
        run.source = Mock(state="/owned/source", npub="source")
        run.management_addresses, run.udp_addresses = {}, {}
        run.mint_url = "http://127.0.0.1:9"
        return run

    def test_bindings_force_management_to_provider_and_native_wifi_to_destination(self):
        run = self.service()
        for name, node in run.nodes.items():
            config = run.profile_config(node)
            self.assertEqual(set(config["transports"]["ethernet"]), {"mesh0"})
            self.assertEqual("udp" in config["transports"], name != "n03")
            self.assertEqual(config["neighbors"], [])
            self.assertEqual(config["terms"]["controller"]["channel_capacity_sat"], 64)
            if name != "n03":
                self.assertEqual(config["transports"]["udp"]["bind_interface"], "br-lan")
                self.assertFalse(config["transports"]["udp"]["advertise_on_nostr"])
        source = run.source_config()
        self.assertEqual(set(source["transports"]), {"udp"})
        self.assertEqual(source["transports"]["udp"]["bind_addr"], "192.168.1.13:0")
        self.assertEqual(source["terms"]["buyer_budget_sat"], 128)
        self.assertEqual(source["terms"]["controller"]["max_wallet_spend_sat"], 128)
        self.assertIsNone(source["terms"]["controller"]["renewal"])
        self.assertEqual(source["neighbors"], [])

    def test_management_address_changes_or_duplicate_router_addresses_are_rejected(self):
        run = self.service()
        run.management_address("n01")
        run.nodes["n02"].remote.return_value = run.nodes["n01"].remote.return_value
        with self.assertRaises(RuntimeError):
            run.management_address("n02")
        run.nodes["n01"].remote.return_value = b"3: br-lan inet 192.168.1.99/24 scope global br-lan"
        with self.assertRaises(RuntimeError):
            run.management_address("n01")

    def test_four_profiles_registered_before_any_guard_can_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps({"nodes": [{
                "host": "lab" + str(i), "interface": "mesh0", "management_interface": "br-lan",
                "original_binary": "/usr/bin/original", "original_config": "/etc/original.json",
                "state_parent": "/etc/bench",
            } for i in range(3)]}))
            args = parser().parse_args(["--inventory", str(inventory), "--binary", "/relay",
                                        "--output", str(root / "result")])
            run = DiamondRun(args)
            self.assertEqual([len(node.profiles()) for node in run.nodes.values()], [1, 1, 2])
            self.assertFalse(any(node.created for node in run.nodes.values()))
            self.assertEqual(len({(getattr(p, "owner", p).host, p.state)
                                  for p in run.participants().values()}), 4)
            self.assertFalse(run.evidence["money_operations"])

    def test_reconfigure_uses_the_exact_profile_guard_and_cannot_change_authority(self):
        owner = SimpleNamespace(temporary="/owned/guard", guarded=Mock())
        profile = SimpleNamespace(owner=owner, config="/owned/source/config.json",
                                  remote=Mock(return_value=b'{"terms":{"budget":128},"neighbors":[]}'))
        configure_stopped(profile, neighbors=[{"npub": "first"}])
        command, data = owner.guarded.call_args.args
        self.assertIn("/owned/guard/guard.sh can-start /owned/source/config.json", command)
        self.assertEqual(json.loads(data)["terms"], {"budget": 128})
        owner.guarded.reset_mock()
        for changes in ({"terms": {}}, {"transports": {}}, {"state_directory": "/elsewhere"}):
            with self.assertRaises(RuntimeError):
                configure_stopped(profile, **changes)
        owner.guarded.assert_not_called()

    def exercise_service(self):
        run = self.service()
        for node in run.nodes.values():
            node.stop = Mock()
        for name in ("form_diamond", "assert_finances", "topology", "verify_shortcuts", "phase", "denied_stream"):
            setattr(run, name, Mock())
        run.diagnostic = Mock()
        run.offline_empty = Mock(return_value={name: 0 for name in run.participants()})
        probe = {"sent": {"stream_id": "a" * 32, "requested_packets": 8, "submitted_packets": 8,
                          "submitted_bytes": 2048, "stopped_reason": None},
                 "received": {"stream_id": "a" * 32, "source": "source", "expected_packets": 8,
                              "payload_bytes": 256, "unique_packets": 0, "unique_bytes": 0,
                              "missing_packets": 8, "invalid_packets": 0, "duplicate_packets": 0,
                              "latency": None}}
        run.denied_stream.return_value = copy.deepcopy(probe)
        run.topology.return_value = {"n03": {"probe": copy.deepcopy(probe["received"])}}
        return run

    def test_topology_pilot_uses_direct_probes_then_denies_unpurchased_end_to_end(self):
        run = self.exercise_service()
        run.exercise()
        self.assertEqual(run.diagnostic.call_count, 4)
        run.denied_stream.assert_called_once_with()
        for provider in ("n01", "n02"):
            run.diagnostic.assert_any_call("source", provider)
            run.diagnostic.assert_any_call(provider, "n03")
        for node in run.nodes.values():
            node.stop.assert_called_once_with()
        run.offline_empty.assert_called_once_with()

    def test_delayed_delivery_after_denial_snapshots_cannot_pass(self):
        run = self.exercise_service()
        run.topology.return_value["n03"]["probe"].update(unique_packets=1, unique_bytes=256,
                                                      missing_packets=7)
        with self.assertRaisesRegex(RuntimeError, "delivery differs"):
            run.exercise()
        run.offline_empty.assert_not_called()


if __name__ == "__main__":
    unittest.main()
