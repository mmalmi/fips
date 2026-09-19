"""Recovery diagnostics cannot weaken acceptance or invent precise transitions."""

from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.paid_wifi import PaidWifiRun
from sim.wifi_recovery_timing import RecoveryTiming, bracket, radio_state, stations


class RecoveryTimingTests(unittest.TestCase):
    def fixture(self):
        run = Mock()
        node = Mock(interface="mesh0")
        node.remote.return_value = b"Station 02:00:00:00:00:01 (on mesh0)\n\tmesh plink: ESTAB\n"
        node.native.return_value = {"status": "ok", "data": {"transports": [{
            "name": "mesh0", "type": "ethernet", "transport_id": 1,
            "stats": {"beacons_recv": 2, "beacons_sent": 1, "beacons_dropped": 0}}]}}
        run.nodes = {"n02": node}
        run.evidence = {"last_peer_observation": {"n02": [{"npub": "n01", "connected": False}]}}
        evidence = {}
        return run, node, evidence, RecoveryTiming(run, evidence, "n02")

    def test_slow_read_is_an_observation_interval(self):
        with patch("sim.wifi_recovery_timing.time.monotonic", side_effect=[10, 17]):
            self.assertEqual(bracket(lambda: 42), {"started": 10, "completed": 17, "value": 42})

    def test_failed_topology_stays_failed_and_peer_snapshot_is_retained(self):
        run, _, evidence, timing = self.fixture()
        run.ready.return_value = False
        with patch("sim.wifi_recovery_timing.time.monotonic", side_effect=range(100, 107)):
            self.assertFalse(timing.ready("partition", line=True, isolated=True, outage_node="n02"))
        run.ready.assert_called_once_with(line=True, isolated=True, outage_node="n02")
        sample = evidence["timing"]["samples"][0]
        self.assertEqual((sample["started"], sample["peers_observed"], sample["completed"]),
                         (100, 101, 106))
        self.assertEqual((sample["adapter"]["started"], sample["adapter"]["completed"]), (102, 103))
        self.assertEqual((sample["stations"]["started"], sample["stations"]["completed"]), (104, 105))
        run.evidence["last_peer_observation"]["n02"][0]["connected"] = True
        self.assertFalse(sample["peers"]["n02"][0]["connected"])

    def test_diagnostic_failure_is_recorded_and_cannot_be_a_success(self):
        run, node, evidence, timing = self.fixture()
        run.ready.return_value = {"n02": {"peers": []}}
        node.native.side_effect = RuntimeError("missing native status")
        with self.assertRaisesRegex(RuntimeError, "missing native"):
            timing.ready("rejoin", line=True)
        sample = evidence["timing"]["samples"][0]
        self.assertEqual(sample["error"], "RuntimeError")
        self.assertIn("completed", sample)
        run.save.assert_called_once_with()

    def test_sample_and_station_output_limits(self):
        run, node, _, timing = self.fixture()
        with patch("sim.wifi_recovery_timing.MAX_SAMPLES", 0), self.assertRaisesRegex(RuntimeError, "limit"):
            timing.ready("rejoin", line=True)
        run.ready.assert_not_called()
        node.remote.return_value = b"x" * 65537
        with self.assertRaisesRegex(RuntimeError, "bound"):
            stations(node)

    def test_native_adapter_identity_and_counters_are_required(self):
        _, node, _, _ = self.fixture()
        adapter = node.native.return_value["data"]["transports"][0]
        adapter["name"] = "management0"
        with self.assertRaisesRegex(RuntimeError, "exact mesh"):
            radio_state(node)
        adapter["name"] = "mesh0"
        adapter["stats"]["beacons_recv"] = -1
        with self.assertRaisesRegex(ValueError, "unsigned"):
            radio_state(node)

    def test_clock_anchor_retains_resolution_and_independent_router_time(self):
        _, node, evidence, timing = self.fixture()
        node.remote.return_value = b"1000\n25.75\n"
        with patch("sim.wifi_recovery_timing.time.monotonic", side_effect=[10, 10.5]):
            timing.anchor("before_cut")
        self.assertEqual(evidence["timing"]["anchors"]["before_cut"]["n02"], {
            "started": 10, "completed": 10.5, "wall_seconds": 1000,
            "wall_resolution_seconds": 1, "uptime_seconds": 25.75})
        for value in (b"invalid\n25\n", b"1000\nnan\n", b"1000\n-1\n"):
            node.remote.return_value = value
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                timing.anchor("invalid")

    def test_timing_requires_an_active_outage(self):
        with self.assertRaisesRegex(ValueError, "requires --active-outage"):
            PaidWifiRun(SimpleNamespace(recovery_timing=True, active_outage=False))


if __name__ == "__main__":
    unittest.main()
