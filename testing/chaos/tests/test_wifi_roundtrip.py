"""Same-clock timing must describe complete paid replies and honest histograms."""

import copy
import itertools
import unittest
from unittest.mock import Mock, patch

from sim.wifi_priority import PriorityRun
from sim.wifi_priority_checks import received, reconciled, round_trip_latency, workload
import test_wifi_priority as fixtures
from test_wifi_priority import arguments, payment_status, reports


def round_trip_report():
    shape, sent, report = reports()
    report["source"] = "n03"
    report["round_trip_latency"] = {
        "samples": 24, "invalid_timestamps": 0, "min_us": 500, "max_us": 3000,
        "sum_us": 29000, "bucket_upper_bounds_us": [1000, 2000, 5000],
        "bucket_counts": [10, 12, 2, 0],
    }
    return shape, sent, report


class HistogramTests(unittest.TestCase):
    def test_delivery_requires_explicit_round_trip_histogram(self):
        shape, _, report = round_trip_report()
        self.assertEqual(received(report, shape, "n03", complete=True, round_trip=True), 24)
        summary = round_trip_latency(report)
        self.assertEqual(summary["p50_upper_bound_us"], 2000)
        self.assertEqual(summary["p95_upper_bound_us"], 5000)
        self.assertEqual(summary["mean_us"], 29000 / 24)
        with self.assertRaises(RuntimeError):
            received(report, shape, "n03", complete=True)
        with self.assertRaises(RuntimeError):
            received({**report, "round_trip_latency": None}, shape, "n03", round_trip=True)

    def test_bad_clock_counts_or_histogram_cannot_report_latency(self):
        changes = (
            {"samples": 23}, {"invalid_timestamps": 1}, {"sum_us": 1},
            {"min_us": 4000}, {"max_us": None}, {"bucket_upper_bounds_us": [2000, 1000, 5000]},
            {"bucket_upper_bounds_us": [1000, 1000, 5000]}, {"bucket_counts": [9, 12, 2, 0]},
            {"bucket_counts": [10, 12, 2]}, {"samples": True},
            {"bucket_counts": [10, 12, 0, 2]},
            {"bucket_counts": [24, 0, 0, 0]}, {"sum_us": 50000},
        )
        for change in changes:
            _, _, report = round_trip_report()
            report["round_trip_latency"].update(change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                round_trip_latency(report)

    def test_empty_measurement_and_unbounded_tail_do_not_invent_percentiles(self):
        _, _, report = round_trip_report()
        report["unique_packets"] = 0
        report["round_trip_latency"].update(samples=0, min_us=None, max_us=None,
                                            sum_us=0, bucket_counts=[0, 0, 0, 0])
        result = round_trip_latency(report)
        self.assertIsNone(result["mean_us"])
        self.assertIsNone(result["p95_upper_bound_us"])
        _, _, report = round_trip_report()
        report["round_trip_latency"].update(max_us=9000, sum_us=45000, bucket_counts=[10, 12, 0, 2])
        self.assertIsNone(round_trip_latency(report)["p95_upper_bound_us"])

    def test_usage_and_authorization_must_both_be_acknowledged(self):
        current = next(iter(payment_status()["payment_progress"].values()))
        self.assertTrue(reconciled(current))
        for change in ({"evidence_msat": 1001}, {"authorized_sat": 2},
                       {"acknowledged_msat": None}, {"in_flight": True}):
            self.assertFalse(reconciled({**current, **change}))


class DirectionTests(unittest.TestCase):
    def service(self):
        service = fixtures.ConfigurationTests().service(round_trip=True, payment_delay_ms=500)
        service.auxiliary = {name: Mock(npub=name) for name in ("free-source", "free-sink")}
        service.ctl = Mock(return_value={"probe": {}})
        return service

    def test_only_paid_probe_arms_reflection_and_local_round_trip(self):
        service = self.service()
        shape = service.arm("n01", "n03", 24, 128)
        request = service.ctl.call_args.kwargs["probe"]
        self.assertTrue(request["reflect"])
        self.assertFalse(request["measure_one_way_latency"])
        service.send("n01", "n03", shape, 4)
        self.assertTrue(service.ctl.call_args.kwargs["probe"]["measure_round_trip"])
        for source, destination in (("free-source", "free-sink"), ("n03", "n01")):
            shape = service.arm(source, destination, 4, 128)
            self.assertNotIn("reflect", service.ctl.call_args.kwargs["probe"])
            service.send(source, destination, shape, 4)
            self.assertNotIn("measure_round_trip", service.ctl.call_args.kwargs["probe"])
        self.assertEqual(service.profile_config(service.nodes["n02"])["payment_cadence"]["max_delay_ms"], 500)

    def test_round_trip_reads_sender_clock_and_authenticates_returning_peer(self):
        service = self.service()
        shape, _, report = round_trip_report()
        service.ctl.return_value = {"probe": report}
        self.assertIs(service.receive("n01", "n03", shape, complete=True), report)
        service.ctl.assert_called_once_with("n01", "status")
        changed = copy.deepcopy(report)
        changed["source"] = "n01"
        service.ctl.return_value = {"probe": changed}
        with self.assertRaises(RuntimeError):
            service.receive("n01", "n03", shape)

    def test_receiver_startup_wait_does_not_accept_previous_stream(self):
        service = self.service()
        future = Mock()
        future.done.return_value = False
        shape = {"stream_id": "new"}
        service.ctl.return_value = {"probe": {"stream_id": "old"}}
        with patch("sim.wifi_priority.eventually", side_effect=lambda _d, f, _s: self.assertIsNone(f())):
            service.wait_paid_armed(future, shape)
        future.done.return_value = True
        with patch("sim.wifi_priority.eventually", side_effect=lambda _d, f, _s: f()):
            with self.assertRaises(RuntimeError):
                service.wait_paid_armed(future, shape)

    def test_unfunded_topology_mode_rejects_paid_timing_before_setup(self):
        with self.assertRaises(ValueError):
            PriorityRun(arguments(round_trip=True, topology_only=True))

    def test_three_phase_workload_cannot_exhaust_fixed_channels_before_recovery(self):
        for changes in ({"paid_packets": 25}, {"paid_bytes": 129},
                        {"paid_packets": 64, "paid_bytes": 256}):
            with patch("sim.wifi_priority.PaidWifiRun.__init__") as setup:
                with self.assertRaises(ValueError):
                    PriorityRun(arguments(round_trip=True, **changes))
                setup.assert_not_called()


class MixedRecoveryTests(unittest.TestCase):
    def test_unacknowledged_reverse_payment_fails_and_collects_original_accounts(self):
        service = fixtures.RecoveryTests().service()
        service.args = arguments(round_trip=True)
        service.schedule = workload(service.args)
        service.auxiliary = {}
        service.mixed = PriorityRun.mixed.__get__(service)
        service.latency_phase = Mock()
        free_shape, free_sent, _ = reports(64000, 1000)
        paid_shape, paid_sent, paid_report = round_trip_report()
        for item in (paid_shape, paid_sent, paid_report):
            item["stream_id"] = "b" * 32
        service.arm = Mock(side_effect=[free_shape, paid_shape])
        service.send = Mock()
        service.wait_paid_armed = Mock()
        service.wait_free_progress = Mock(return_value=fixtures.middle(5))
        service.middle = Mock(side_effect=[fixtures.middle(i, drops=i) for i in range(5)])

        def partial(count):
            report = copy.deepcopy(paid_report)
            report.update(unique_packets=count, unique_bytes=count * 128, missing_packets=24-count)
            report["round_trip_latency"].update(samples=count, min_us=1000, max_us=1000,
                                                sum_us=count * 1000, bucket_counts=[count, 0, 0, 0])
            return report

        service.receive = Mock(side_effect=[partial(n) for n in (2, 3, 5, 6, 23)] + [paid_report])
        observed = {"n01": 0, "n03": 0}

        def control(node, kind, **_fields):
            if kind != "status":
                return {}
            observed[node] += 1
            if observed[node] == 1:
                return payment_status()
            return payment_status(2000, 2, 2000 if node == "n01" else None)

        service.ctl = Mock(side_effect=control)
        free_future, paid_future = Mock(), Mock()
        free_future.done.return_value = False
        paid_future.done.return_value = True
        free_future.result.return_value = free_sent
        paid_future.result.return_value = paid_sent
        pool = Mock()
        pool.submit.side_effect = [free_future, paid_future]
        clock = itertools.count()
        with patch("sim.wifi_priority.ThreadPoolExecutor") as executor, \
                patch("sim.wifi_priority.original_channels"), \
                patch("sim.wifi_priority.signal.alarm") as alarm, \
                patch("sim.wifi_priority.time.sleep"), \
                patch("sim.wifi_priority.time.monotonic", side_effect=lambda: next(clock)):
            executor.return_value.__enter__.return_value = pool
            with self.assertRaisesRegex(RuntimeError, "automatic payment was not acknowledged"):
                service.exercise()
        evidence = service.evidence["mixed_priority"]
        self.assertEqual(evidence["paid_receiver"]["unique_packets"], 24)
        self.assertTrue(evidence["reverse_payment_observations"])
        self.assertNotIn("payment_during_free", evidence)
        self.assertFalse(service.evidence["mixed_priority_accepted"])
        service.collect.assert_called_once_with()
        alarm.assert_called_once_with(0)


if __name__ == "__main__":
    unittest.main()
