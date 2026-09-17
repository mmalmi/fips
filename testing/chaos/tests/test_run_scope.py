"""Ownership regressions; every Docker/network mutation is mocked."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_relay import PaidRelayRun, relay_config
from sim.run_scope import OwnedResources, RUN_LABEL, docker, inspect_owned, refuse_name_collision
from sim.scoped_veth import ScopedVeth, host_names
from sim.topology import SimNode, SimTopology
from sim.veth import VethManager

RUN = "a12b34c5"
ID = "a" * 64


def topology(run=RUN):
    nodes = {name: SimNode(name, "", "", "") for name in ("n01", "n02")}
    edge = ("n01", "n02")
    return SimTopology(nodes, {edge}, {edge: "ethernet"}, run)


class RunScopeTests(unittest.TestCase):
    def test_default_names_unchanged_and_scoped_names_bounded(self):
        self.assertEqual(topology(None).container_name("n01"), "fips-node-n01")
        self.assertEqual(topology().container_name("n01"), f"fips-{RUN}-n01")
        self.assertTrue(all(len(name) <= 15 for name in host_names(RUN, "n01", "n02")))
        self.assertNotEqual(host_names(RUN, "n01", "n02"), host_names("b12b34c5", "n01", "n02"))
        for bad in ("", "../else", "123456789", "a;rm -rf"):
            with self.assertRaises(ValueError):
                topology(bad)

    def test_existing_container_or_network_is_refused_without_removal(self):
        for kind in ("container", "network"):
            with patch("sim.run_scope.docker", return_value="mine\nother") as command:
                with self.assertRaises(RuntimeError):
                    refuse_name_collision(kind, "mine")
                self.assertEqual(command.call_count, 1)
                self.assertIn("ls", command.call_args.args[0])

    def test_cleanup_uses_only_recorded_ids_and_checks_labels_again(self):
        resource = OwnedResources(RUN)
        owned = {"Id": ID, "Config": {"Labels": {RUN_LABEL: RUN}}}
        with patch("sim.run_scope.docker", return_value=json.dumps([owned])) as command:
            resource.remember("container", ID)
            self.assertEqual(resource.cleanup(), [])
            self.assertEqual(command.call_args.args[0], ["container", "rm", "--force", ID])
        foreign = {"Id": ID, "Config": {"Labels": {RUN_LABEL: "other"}}}
        with patch("sim.run_scope.docker", return_value=json.dumps([foreign])) as command:
            self.assertTrue(resource.cleanup())
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0], ["container", "inspect", ID])

    def test_container_label_mismatch_fails_closed(self):
        with patch("sim.run_scope.docker", return_value=json.dumps([{"Config": {"Labels": {}}}])):
            with self.assertRaises(RuntimeError):
                inspect_owned("container", ID, RUN)

    def test_failed_first_inspection_keeps_created_id_for_checked_cleanup(self):
        resource = OwnedResources(RUN)
        owned = {"Id": ID, "Config": {"Labels": {RUN_LABEL: RUN}}}
        with patch("sim.run_scope.docker", side_effect=[RuntimeError("temporary inspect failure"),
                                                      json.dumps([owned]), ""]) as command:
            with self.assertRaises(RuntimeError):
                resource.remember("container", ID)
            self.assertEqual(resource.created, [("container", ID)])
            self.assertEqual(resource.cleanup(), [])
            self.assertEqual(command.call_args.args[0], ["container", "rm", "--force", ID])

    def test_docker_timeout_is_normalized_without_request_body(self):
        with patch("sim.run_scope.subprocess.run", side_effect=subprocess.TimeoutExpired("exec", 1)):
            with self.assertRaisesRegex(RuntimeError, "Docker exec timed out") as error:
                docker(["exec", ID], data="private test token", timeout=1)
            self.assertNotIn("private test token", str(error.exception))

    def test_cleanup_failure_does_not_skip_remaining_resource_ids(self):
        resource = OwnedResources(RUN)
        other = "b" * 64
        resource.created = [("container", ID), ("container", other)]
        owned = {"Id": ID, "Config": {"Labels": {RUN_LABEL: RUN}}}
        with patch("sim.run_scope.docker", side_effect=[RuntimeError("Docker inspect timed out"),
                                                      json.dumps([owned]), ""]) as command:
            self.assertEqual(len(resource.cleanup()), 1)
            self.assertEqual(command.call_args.args[0], ["container", "rm", "--force", ID])

    def test_scoped_veth_collision_never_runs_a_delete_or_create(self):
        links = ScopedVeth(topology())
        left = {"Id": ID, "State": {"Running": True, "Pid": 42}}
        collision = {host_names(RUN, "n01", "n02")[0]: {"ifalias": "foreign"}}
        with patch.object(links, "container", return_value=left), \
                patch.object(links, "links", return_value=collision), \
                patch.object(links, "host") as host:
            with self.assertRaises(RuntimeError):
                links.create("n01", "n02")
            host.assert_not_called()
            self.assertEqual(links.created, [])

    def test_scoped_veth_cleanup_never_deletes_foreign_alias(self):
        links = ScopedVeth(topology())
        links.created = [("n01", "n02")]
        collision = {name: {"ifalias": "foreign"} for name in host_names(RUN, "n01", "n02")}
        with patch.object(links, "container", return_value={"Id": ID}), \
                patch.object(links, "links", return_value=collision), \
                patch.object(links, "host") as host, patch("sim.scoped_veth.docker") as command:
            with self.assertRaises(RuntimeError):
                links.teardown_all()
            host.assert_not_called()
            command.assert_not_called()

    def test_pair_is_tagged_in_owned_namespace_before_peer_move(self):
        links = ScopedVeth(topology())
        left = {"Id": ID, "State": {"Running": True, "Pid": 42}}
        right = {"Id": "b" * 64, "State": {"Running": True, "Pid": 43}}
        a, b = host_names(RUN, "n01", "n02")
        owner = links.owner("n01", "n02")
        tagged = {a: {"ifalias": owner}, b: {"ifalias": owner}}
        moved = {"ve-n01-n02": {"ifalias": owner, "address": "a"},
                 "ve-n02-n01": {"ifalias": owner, "address": "b"}}
        with patch.object(links, "container", side_effect=[left, right, left, right]), \
                patch.object(links, "links", side_effect=[{}, {}, {}, {}, tagged, tagged, moved, moved]), \
                patch.object(links, "host") as host, patch("sim.scoped_veth.docker") as command:
            links.create("n01", "n02")
        self.assertEqual(command.call_args_list[0].args[0][:3], ["exec", ID, "ip"])
        self.assertTrue(all("alias" in call.args[0] for call in command.call_args_list[1:3]))
        host.assert_called_once_with(["-t", "42", "-n", "ip", "link", "set", b, "netns", "43"], entrypoint="nsenter")

    def test_missing_alias_stops_before_namespace_move(self):
        links = ScopedVeth(topology())
        item = {"Id": ID, "State": {"Running": True, "Pid": 42}}
        with patch.object(links, "container", return_value=item), \
                patch.object(links, "links", return_value={}), \
                patch.object(links, "host") as host, patch("sim.scoped_veth.docker"):
            with self.assertRaisesRegex(RuntimeError, "ownership alias"):
                links.create("n01", "n02")
            host.assert_not_called()

    def test_cleanup_removes_only_owned_partial_host_pair(self):
        links = ScopedVeth(topology())
        links.created = [("n01", "n02")]
        name = host_names(RUN, "n01", "n02")[0]
        def snapshot(container=None):
            return {} if container else {name: {"ifalias": links.owner("n01", "n02")}}
        with patch.object(links, "container", return_value={"Id": ID}), \
                patch.object(links, "links", side_effect=snapshot), patch.object(links, "host") as host:
            links.teardown_all()
            host.assert_called_once_with(["link", "delete", name])
            self.assertEqual(links.created, [])

    def test_scoped_node_replacement_does_not_use_legacy_stale_cleanup(self):
        manager = VethManager(topology())
        with patch("sim.veth._run_host") as host:
            with self.assertRaises(RuntimeError):
                manager.setup_node("n01")
            host.assert_not_called()

    def test_existing_output_is_untouched_even_through_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "result.json"
            sentinel.write_text("unchanged")
            args = argparse.Namespace(output=root, binary_dir=root, image="unused")
            with patch("sim.paid_relay.docker") as command:
                with self.assertRaises(RuntimeError):
                    PaidRelayRun(args).run()
                command.assert_not_called()
            self.assertEqual(sentinel.read_text(), "unchanged")

    def test_config_has_only_native_ethernet_discovery(self):
        config = relay_config(["ve-n01-n02"], "http://172.25.0.2:3338")
        self.assertEqual(set(config["transports"]), {"ethernet"})
        self.assertEqual(config["neighbors"], [])
        self.assertEqual(config["neighbor_admission"], "authenticated_adjacent")
        self.assertNotIn("identity", config)
        self.assertEqual(config["transports"]["ethernet"], {
            "ve-n01-n02": {"interface": "ve-n01-n02", "discovery": True,
                           "announce": True, "auto_connect": True,
                           "accept_connections": True},
        })
        self.assertEqual(config["state_directory"], "/tmp/bench-state")

    def test_container_mounts_only_executables_and_private_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = PaidRelayRun(argparse.Namespace(output=root, binary_dir=root / "bin", image="unused"))
            with patch("sim.paid_relay.refuse_name_collision"), \
                    patch("sim.paid_relay.docker", side_effect=[ID, ""]) as command, \
                    patch.object(run.resources, "remember"):
                run.create_container("mint", "owned-network", "exact-image")
            args = command.call_args_list[0].args[0]
            mounts = [args[index + 1] for index, arg in enumerate(args) if arg == "--mount"]
            self.assertEqual(len(mounts), 3)
            self.assertEqual(mounts[0], f"type=bind,src={root.resolve()}/mint,dst=/run/bench")
            for binary, mount in zip(("fips-relay", "fips-relay-test-mint"), mounts[1:]):
                self.assertEqual(mount, f"type=bind,src={root.resolve()}/bin/{binary},dst=/opt/bench/{binary},readonly")

    def test_veth_timeout_still_cleans_containers_and_records_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "new-run"
            run = PaidRelayRun(argparse.Namespace(output=root, binary_dir=root, image="unused"))
            def setup():
                root.mkdir()
                run.output_created = True
            with patch.object(run, "setup", side_effect=setup), patch.object(run, "exercise"), \
                    patch.object(run.veth, "teardown_all", side_effect=subprocess.TimeoutExpired("ip", 1)), \
                    patch.object(run.resources, "cleanup", return_value=[]) as cleanup, \
                    patch("sim.paid_relay.signal.alarm") as alarm:
                with self.assertRaises(RuntimeError):
                    run.run()
                cleanup.assert_called_once()
                alarm.assert_called_once_with(0)
            result = json.loads((root / "result.json").read_text())
            self.assertFalse(result["passed"])
            self.assertEqual(len(result["cleanup_errors"]), 1)

    def test_unpaid_probe_observes_interval_and_rejects_delivered_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = PaidRelayRun(argparse.Namespace(output=root, binary_dir=root, image="unused"))
            before = {"wallet": "unchanged"}
            replies = [{}, {"probe": {"requested_packets": 4, "submitted_packets": 4}},
                       {"probe": {"unique_packets": 0, "invalid_packets": 0}},
                       {"probe": {"unique_packets": 0, "invalid_packets": 0}}]
            with patch.object(run, "ctl", side_effect=replies) as ctl, \
                    patch.object(run, "finances", return_value=before), \
                    patch("sim.paid_relay.time.monotonic", side_effect=[0, 1, 3, 4, 4]), \
                    patch("sim.paid_relay.time.sleep") as sleep:
                run.unpaid_probe(before)
                self.assertEqual(ctl.call_count, 4)
                sleep.assert_called_once_with(0.25)
            replies[2] = {"probe": {"unique_packets": 1, "invalid_packets": 0}}
            with patch.object(run, "ctl", side_effect=replies), \
                    patch("sim.paid_relay.time.monotonic", return_value=0):
                with self.assertRaisesRegex(RuntimeError, "unpaid traffic reached"):
                    run.unpaid_probe(before)


if __name__ == "__main__":
    unittest.main()
