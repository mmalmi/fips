"""Matched workloads and failure recovery without hardware or funds."""

import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from sim.wifi_cadence import CadenceRun, run


class CadenceTests(unittest.TestCase):
    def service(self):
        service = object.__new__(CadenceRun)
        service.nodes = {name: Mock(npub=name) for name in ("n01", "n02", "n03")}
        return service

    def test_workload_failure_collects_known_original_channels_before_propagating(self):
        service = self.service()
        service.form_line = Mock()
        service.ctl = Mock()
        service.finances = Mock(return_value={"known": "channels"})
        service.warmup = Mock()
        service.workload = Mock(side_effect=ValueError("bad sampler"))
        calls = Mock()
        service.collect = calls.collect
        with patch("sim.wifi_cadence.original_channels"), \
                patch("sim.wifi_cadence.signal.alarm", calls.alarm), \
                self.assertRaisesRegex(ValueError, "bad sampler"):
            service.exercise()
        service.collect.assert_called_once_with()
        self.assertEqual([call[0] for call in calls.mock_calls], ["alarm", "collect"])
        calls.alarm.assert_called_once_with(0)
        service.workload.assert_called_once_with("idle")

    def test_uncertain_funding_does_not_blindly_settle_or_retry_purchase(self):
        service = self.service()
        service.form_line = Mock()
        service.ctl = Mock(side_effect=TimeoutError("unknown purchase"))
        service.collect = Mock()
        with self.assertRaises(TimeoutError):
            service.exercise()
        service.ctl.assert_called_once_with("n01", "buy", destination="n03")
        service.collect.assert_not_called()

    def test_partial_probe_is_preserved_without_resending_measured_data(self):
        service = self.service()
        sent = {"stream_id": "a" * 32, "requested_packets": 8000, "submitted_packets": 7900}
        received = {"stream_id": "a" * 32, "source": "n01", "unique_packets": 7800}
        service.ctl = Mock(side_effect=[{}, {"probe": sent}, {"probe": received}])
        with patch("sim.wifi_cadence.secrets.token_hex", return_value="a" * 32), \
                patch("sim.wifi_cadence.time.monotonic", side_effect=[0, 3]):
            result = service.stream(8000, 4000)
        self.assertIs(result["sender"], sent)
        self.assertIs(result["receiver"], received)
        self.assertEqual([call.args[1] for call in service.ctl.call_args_list],
                         ["receive_probe", "send_probe", "status"])
        self.assertIs(service.ctl.call_args_list[0].kwargs["probe"]["measure_one_way_latency"], False)

    def test_burst_window_includes_all_eight_sleeps_and_fixed_tail(self):
        service = self.service()
        service.sample = Mock(side_effect=["guard1", "before", "after", "guard2"])
        service.stream = Mock(side_effect=lambda count, rate: {"packets_per_second": rate})
        service.emit, service.phase = Mock(), Mock()
        with patch("sim.wifi_cadence.time.monotonic", side_effect=[0, 8, 11.1]), \
                patch("sim.wifi_cadence.time.sleep") as sleep:
            service.workload("bursty")
        self.assertEqual([call.args for call in sleep.call_args_list], [(0.8,)] * 8 + [(3,)])
        self.assertEqual([call.args for call in service.stream.call_args_list], [(64, 1000)] * 8)
        data = service.emit.call_args.kwargs["data"]
        self.assertEqual(data["offered_elapsed_ms"], 8000)
        self.assertEqual(data["observation_elapsed_ms"], 11100)
        self.assertEqual(data["after"], "after")
        self.assertEqual(data["after_guard"], "guard2")
        self.assertTrue(all(p["after_sleep_ms"] == 800 for p in data["probes"]))
        self.assertEqual(service.sample.call_count, 4)

    def test_profile_keeps_spending_caps_and_binds_cadence_to_actual_config(self):
        service = self.service()
        service.delay, service.mint_url = 2000, "http://192.168.1.2:12345"
        config = service.profile_config(Mock(interface="mesh0", state="/test/state"))
        self.assertEqual(config["payment_cadence"], {"max_delay_ms": 2000, "unpaid_percent": 50})
        terms = config["terms"]
        self.assertEqual(terms["quote_max_units"], 16 * 1024 * 1024)
        self.assertEqual(terms["fee_msat_per_kib"], 1)
        self.assertEqual(terms["controller"]["channel_capacity_sat"], 32)
        self.assertEqual(terms["controller"]["max_wallet_spend_sat"], 128)
        self.assertIsNone(terms["controller"]["renewal"])
        self.assertEqual(terms["billing"], "forwarding_data")

    def test_pilot_cannot_claim_completed_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "pilot"
            args = argparse.Namespace(output=output, pilot=True)
            with patch("sim.wifi_cadence.metadata", return_value={"schema": 3}), \
                    patch("sim.wifi_cadence.CadenceRun") as service, \
                    patch("sim.wifi_cadence.signal.alarm"):
                run(args)
            result = json.loads((output / "result.json").read_text())
            self.assertTrue(result["passed"])
            self.assertFalse(result["comparison_complete"])
            self.assertEqual(result["trials_completed"], 1)
            self.assertEqual(service.call_count, 1)
            passed_args = service.call_args.args[0]
            self.assertFalse(passed_args.open_mesh)
            self.assertFalse(passed_args.mint_ssh_forward)

    def test_failed_trial_stops_matrix_and_records_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "matrix"
            args = argparse.Namespace(output=output, pilot=False)
            with patch("sim.wifi_cadence.metadata", return_value={"schema": 3}), \
                    patch("sim.wifi_cadence.CadenceRun") as service, \
                    patch("sim.wifi_cadence.signal.alarm"), self.assertRaises(RuntimeError):
                service.return_value.execute.side_effect = RuntimeError("uncollected funds")
                run(args)
            result = json.loads((output / "result.json").read_text())
            self.assertFalse(result["passed"])
            self.assertFalse(result["comparison_complete"])
            self.assertEqual(result["trials_completed"], 0)
            self.assertEqual(service.call_count, 1)


if __name__ == "__main__":
    unittest.main()
