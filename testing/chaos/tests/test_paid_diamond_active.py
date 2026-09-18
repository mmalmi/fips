"""Live provider loss keeps traffic active and preserves exact route attribution."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_diamond_checks import transitional_adjacency
from sim.wifi_diamond_selection import ACTIVE_WORKLOAD, FEES, PAYLOAD_BYTES, POLICY
from test_paid_diamond_drive import DriveFixture
from test_paid_diamond_lifecycle import runner
from test_wifi_diamond import topology
from test_wifi_diamond_selection import observation


ALTERNATIVE = [2] * 16


class ActiveDriveTests(DriveFixture, unittest.TestCase):
    def setUp(self):
        self.switch_at = 60
        super().setUp()
        self.packet_count = ACTIVE_WORKLOAD.packets
        self.run.nodes["n02"] = SimpleNamespace(node_addr=ALTERNATIVE)
        self.radio = Mock()
        self.run.record_active_recovery = Mock()
        patch("sim.paid_diamond.probes.send_with_radio_cut", side_effect=self.cut).start()

    def status(self):
        value = super().status()
        if self.clock.now >= self.switch_at:
            purchase = value["purchases"][0]
            purchase["provider"] = ALTERNATIVE
            purchase["channel"]["id"] = "alternative"
            purchase["contract"]["id"] = "alternative-full"
            purchase["contract"]["price"]["msat"] = FEES["n02"]
            value["history"] = [{**copy.deepcopy(purchase), "contract": {
                **purchase["contract"], "id": "new-alternative-trial", "max_units": POLICY["trial_max_units"]}}]
            value["payment_progress"]["alternative"] = value["payment_progress"].pop("original")
        return value

    def observe(self):
        value = super().observe()
        value["quality"]["quality"]["next_hop"] = value["after"]["purchases"][0]["provider"]
        return value

    def cut(self, run, source, destination, shape, rate, radio, evidence, *, verify_route):
        self.assertEqual((radio, rate), (self.radio, ACTIVE_WORKLOAD.rate))
        evidence["pre_cut_route"] = verify_route()
        evidence["cut_started"] = self.clock.now
        evidence["cut_attempted"] = True
        radio.mesh_down()
        evidence["cut_completed"] = self.clock.now
        return self.send(run, source, destination, shape, rate)

    def test_sending_during_cooldown_reaches_fresh_alternative_without_eviction_wait(self):
        self.run.drive_route("n02", self.baseline, "active", radio=self.radio)
        self.radio.mesh_down.assert_called_once_with()
        self.assertLess(self.clock.now, 180)
        self.assertGreaterEqual(self.clock.now, 60)
        rows = self.run.evidence["route_phases"]["active"]
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[-1]["receiver"]["unique_packets"], 32)
        self.assertLessEqual(sum(r["shape"]["packet_count"] * PAYLOAD_BYTES for r in rows), 65536)
        self.assertTrue(all(b["started_at"] == a["observation_finished_at"] for a, b in zip(rows, rows[1:])))
        self.run.record_active_recovery.assert_called_once_with(rows[-1])
        self.run.reconciled.assert_called_once_with()
        # The burst that crosses selection cannot satisfy the final proof.
        self.assertNotEqual(rows[-2]["initial"]["purchases"], rows[-2]["observation"]["after"]["purchases"])

    def test_pre_cut_change_of_actual_carrier_prevents_radio_mutation(self):
        initial = observation()["after"]
        changed = observation()
        changed["quality"]["quality"]["next_hop"] = ALTERNATIVE
        self.run.observe = Mock(return_value=changed)
        with self.assertRaisesRegex(RuntimeError, "original cheaper agreement"):
            self.run.confirm_pre_cut_route(initial)
        self.radio.mesh_down.assert_not_called()

    def test_no_healthy_alternative_exhausts_same_finite_bytes(self):
        self.switch_at = 1000
        with self.assertRaisesRegex(RuntimeError, "finite packet allowance"):
            self.run.drive_route("n02", self.baseline, "active", radio=self.radio)
        rows = self.run.evidence["route_phases"]["active"]
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(r["shape"]["packet_count"] * PAYLOAD_BYTES for r in rows), 65536)
        self.run.record_active_recovery.assert_not_called()


class ActiveLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch("sim.paid_diamond.signal.alarm").start()
        patch("sim.paid_diamond.eventually", side_effect=lambda _name, check, *_args: check()).start()

    def test_eviction_is_observed_after_accepted_recovery_and_before_rejoin(self):
        run = runner()
        run.active_failover = True
        run.collect = Mock()
        events = []
        def drive(provider, *_args, **fields):
            if provider == "n02":
                self.assertIs(fields["radio"], run.nodes["n01"])
                run.evidence["active_failover"] = {"cut_started": 1, "cut_attempted": True}
                events.append("accepted alternate")
        run.drive_route.side_effect = drive
        run.topology.side_effect = lambda **fields: events.append("evicted" if fields else "rejoined") or {}
        run.nodes["n01"].mesh_up.side_effect = lambda: events.append("up")
        run.exercise()
        self.assertEqual(events, ["accepted alternate", "evicted", "up", "rejoined"])
        run.nodes["n01"].mesh_down.assert_not_called()
        self.assertEqual(sum(c.args[1] == "watch" for c in run.ctl.call_args_list), 1)
        run.collect.assert_called_once_with()

    def test_only_attempted_cut_is_restored_before_collection(self):
        for attempted in (False, True):
            with self.subTest(attempted=attempted):
                run = runner()
                run.active_failover = True
                events = []
                def fail(provider, *_args, **_fields):
                    if provider == "n02":
                        run.evidence["active_failover"] = {"cut_started": 1, "cut_attempted": attempted}
                        raise RuntimeError("cut or verification failed")
                run.drive_route.side_effect = fail
                run.nodes["n01"].mesh_up.side_effect = lambda: events.append("up")
                run.collect = Mock(side_effect=lambda: events.append("collect"))
                with self.assertRaisesRegex(RuntimeError, "cut or verification failed"):
                    run.exercise()
                self.assertEqual(events, ["up", "collect"] if attempted else ["collect"])
                self.assertEqual(run.nodes["n01"].mesh_up.call_count, int(attempted))


class MembershipTests(unittest.TestCase):
    def test_only_departing_edge_can_be_connected_disconnected_or_absent(self):
        for state in (True, False, None):
            states, identities, addresses = topology()
            for name, other in (("n01", "n03"), ("n03", "n01")):
                if state is None:
                    states[name]["peers"] = [p for p in states[name]["peers"] if p["npub"] != identities[other]]
                else:
                    for peer in states[name]["peers"]:
                        if peer["npub"] == identities[other]:
                            peer["connected"] = state
            before = copy.deepcopy(states)
            self.assertIs(transitional_adjacency(states, identities, addresses), states)
            self.assertEqual(states, before)

    def test_client_disconnection_alternative_loss_and_shortcuts_fail(self):
        for name, peer in (("source", "n01"), ("source", "n02"), ("n02", "n03"), ("n03", "n02")):
            states, identities, addresses = topology()
            for row in states[name]["peers"]:
                if row["npub"] == identities[peer]:
                    row["connected"] = False
            with self.subTest(name=name, peer=peer), self.assertRaises(RuntimeError):
                transitional_adjacency(states, identities, addresses)
        states, identities, addresses = topology()
        states["source"]["peers"].append({"npub": identities["n03"], "transport": "udp", "connected": True})
        with self.assertRaises(RuntimeError):
            transitional_adjacency(states, identities, addresses)


if __name__ == "__main__":
    unittest.main()
