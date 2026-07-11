#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "fairness_analyze", Path(__file__).with_name("analyze.py")
)
assert SPEC and SPEC.loader
ANALYZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZE)


class FairnessGateTests(unittest.TestCase):
    requirements = {
        "d_min_throughput_mbps": 1.0,
        "d_max_loss_percent": 50.0,
        "d_max_ping_loss_percent": 50.0,
        "d_min_ping_replies": 10,
    }

    def summary(self) -> dict:
        return {
            "a_tcp8": {"throughput_mbps": 100.0},
            "d_small_flow": {"throughput_mbps": 9.0, "loss_percent": 0.1},
            "d_loaded_ping": {"received": 100, "loss_percent": 0.0},
            "b_forwarded_packets_delta": 1000,
            "connected_peers_before": {"a": 1, "b": 3, "c": 1, "d": 1},
            "connected_peers_after": {"a": 1, "b": 3, "c": 1, "d": 1},
        }

    def test_healthy_sibling_flow_and_liveness_pass(self) -> None:
        self.assertTrue(all(ANALYZE.evaluate_gates(self.summary(), self.requirements).values()))

    def test_starved_sibling_flow_fails_even_if_bulk_progresses(self) -> None:
        summary = self.summary()
        summary["d_small_flow"] = {"throughput_mbps": 0.0, "loss_percent": 100.0}
        summary["d_loaded_ping"] = {"received": 0, "loss_percent": 100.0}
        gates = ANALYZE.evaluate_gates(summary, self.requirements)
        self.assertTrue(gates["a_saturated_flow_progress"])
        self.assertFalse(gates["d_small_flow_progress"])
        self.assertFalse(gates["d_loaded_ping_progress"])

    def test_lost_control_peer_fails_liveness_gate(self) -> None:
        summary = self.summary()
        summary["connected_peers_after"]["b"] = 2
        gates = ANALYZE.evaluate_gates(summary, self.requirements)
        self.assertFalse(gates["peer_liveness_preserved"])


if __name__ == "__main__":
    unittest.main()
