"""Impairments must stay within the exact interfaces created by the run."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.netem_params import NetemParams
from sim.scoped_veth import ScopedVeth
from sim.topology import SimNode, SimTopology
from sim.veth import VethManager

RUN = "1234abcd"
ID = "a" * 64
IFACE = "ve-n02-n01"
NOQUEUE = [{"kind": "noqueue", "handle": "0:", "root": True}]
NETEM = [{"kind": "netem", "handle": "7a11:", "root": True,
          "options": {"limit": 1000}, "packets": 8, "bytes": 2560,
          "drops": 0, "qlen": 0, "backlog": 0}]


def scoped():
    nodes = {name: SimNode(name, "", "", "") for name in ("n01", "n02")}
    edge = ("n01", "n02")
    value = ScopedVeth(SimTopology(nodes, {edge}, {edge: "ethernet"}, RUN))
    value.created = [edge]
    return value


class ScopedNetemTests(unittest.TestCase):
    def test_numeric_arguments_and_deterministic_reorder(self):
        self.assertEqual(NetemParams().to_tc_args(), "delay 0ms")
        self.assertEqual(NetemParams(delay_ms=80, reorder_pct=100, gap=2).to_tc_argv(),
                         ["delay", "80ms", "reorder", "100.0%", "gap", "2"])
        for invalid in ({"loss_pct": float("nan")}, {"loss_pct": 101},
                        {"delay_ms": -1}, {"delay_ms": "80;bad"},
                        {"gap": 2}, {"reorder_pct": 1}, {"loss_pct": True}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                NetemParams(**invalid).to_tc_argv()

    def test_legacy_sampling_retains_zero_delay_omission_without_mutation(self):
        params = NetemParams(jitter_ms=1, reorder_pct=2, loss_pct=3)
        self.assertEqual(params.to_tc_args(), "loss 3.0%")
        self.assertEqual(params.jitter_ms, 1)
        self.assertEqual(params.reorder_pct, 2)
        with self.assertRaises(ValueError):
            params.to_tc_argv()

    def test_alias_or_uncreated_edge_refused_before_tc(self):
        value = scoped()
        with patch.object(value, "container", return_value={"Id": ID}), \
                patch.object(value, "links", return_value={IFACE: {"ifalias": "foreign"}}), \
                patch("sim.scoped_veth.docker") as command:
            for node, peer in (("n02", "n01"), ("n02", "n03")):
                with self.assertRaises(RuntimeError):
                    value.set_impairment(node, peer, NetemParams(loss_pct=100))
            command.assert_not_called()

    def test_non_scoped_manager_cannot_apply_read_or_clear_impairments(self):
        topology = scoped().topology
        topology.run_name = None
        manager = VethManager(topology)
        with patch("sim.scoped_veth.docker") as command:
            for action, args in ((manager.set_scoped_impairment, (NetemParams(),)),
                                 (manager.scoped_impairment_stats, ()),
                                 (manager.clear_scoped_impairment, ())):
                with self.assertRaises(RuntimeError):
                    action("n02", "n01", *args)
            command.assert_not_called()

    def test_existing_qdisc_is_never_replaced_or_removed(self):
        value = scoped()
        with patch.object(value, "endpoint", return_value=(ID, IFACE, "owned")), \
                patch("sim.scoped_veth.docker", return_value=json.dumps(NETEM)) as command:
            with self.assertRaisesRegex(RuntimeError, "existing qdisc"):
                value.set_impairment("n02", "n01", NetemParams(loss_pct=100))
            self.assertEqual(command.call_count, 1)
            self.assertIn("show", command.call_args.args[0])

    def test_exact_owned_direction_observed_and_removed(self):
        value = scoped()
        with patch.object(value, "endpoint", return_value=(ID, IFACE, "owned")), \
                patch("sim.scoped_veth.docker", side_effect=[json.dumps(NOQUEUE), "",
                      json.dumps(NETEM), json.dumps(NETEM), "", json.dumps(NOQUEUE)]) as command:
            report = value.set_impairment("n02", "n01", NetemParams(loss_pct=100))
            self.assertEqual(report["qdiscs"], NETEM)
            self.assertEqual(report["container_id"], ID)
            self.assertEqual(report["requested"], ["loss", "100.0%"])
            value.clear_impairment("n02", "n01")
            args = [call.args[0] for call in command.call_args_list]
            self.assertEqual(args[1], ["exec", ID, "tc", "qdisc", "add", "dev", IFACE,
                                      "root", "handle", "7a11:", "netem", "loss", "100.0%"])
            self.assertEqual(args[4], ["exec", ID, "tc", "qdisc", "del", "dev", IFACE,
                                      "root", "handle", "7a11:"])
            self.assertTrue(all("eth0" not in arg for arg in args))
            with self.assertRaises(RuntimeError):
                value.impairment_stats("n02", "n01")

    def test_changed_container_or_qdisc_fails_closed_on_clear(self):
        for changed in ("container", "handle", "kind"):
            value = scoped()
            qdisc = json.loads(json.dumps(NETEM))
            with patch.object(value, "endpoint", return_value=(ID, IFACE, "owned")) as endpoint, \
                    patch("sim.scoped_veth.docker", side_effect=[json.dumps(NOQUEUE), "",
                          json.dumps(NETEM)]) as command:
                value.set_impairment("n02", "n01", NetemParams(loss_pct=100))
                if changed == "container":
                    endpoint.return_value = ("b" * 64, IFACE, "owned")
                else:
                    qdisc[0][changed] = "different"
                command.side_effect = None
                command.return_value = json.dumps(qdisc)
                command.reset_mock()
                with self.assertRaises(RuntimeError):
                    value.clear_impairment("n02", "n01")
                self.assertFalse(any("del" in call.args[0] for call in command.call_args_list))

    def test_unverified_qdisc_installation_is_not_reported_as_success(self):
        value = scoped()
        with patch.object(value, "endpoint", return_value=(ID, IFACE, "owned")), \
                patch("sim.scoped_veth.docker", side_effect=[json.dumps(NOQUEUE), "",
                      json.dumps(NOQUEUE)]) as command:
            with self.assertRaisesRegex(RuntimeError, "netem qdisc"):
                value.set_impairment("n02", "n01", NetemParams(loss_pct=100))
            self.assertFalse(any("del" in call.args[0] for call in command.call_args_list))

    def test_link_flap_checks_both_endpoints_before_first_mutation(self):
        value = scoped()
        with patch.object(value, "endpoint", side_effect=[(ID, IFACE, "owned"),
                                                         RuntimeError("foreign")]), \
                patch("sim.scoped_veth.docker") as command:
            with self.assertRaises(RuntimeError):
                value.set_edge("n01", "n02", False)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
