"""Finite fresh traffic must outlast cooldown and still prove delivery/payment."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.paid_diamond import PaidDiamondRun
from sim.wifi_diamond_selection import MAX_PHASE_BATCHES, PACKETS, PAYLOAD_BYTES, POLICY
from sim.wifi_priority_checks import received
from test_wifi_diamond_selection import DESTINATION, PROVIDER, observation


class Clock:
    now = 0.0

    def sleep(self, seconds):
        assert 0 <= seconds <= 0.5
        self.now += seconds


class DriveTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.ready_at = 0
        self.delay_last = False
        self.never_complete = False
        self.changed_agreement = False
        self.acknowledged = True
        self.bad_sender = self.bad_receiver = False
        self.streams, self.receptions = [], {}
        self.run = object.__new__(PaidDiamondRun)
        self.run.nodes = {"n01": SimpleNamespace(node_addr=PROVIDER),
                          "n03": SimpleNamespace(node_addr=DESTINATION, npub="dest")}
        self.run.evidence = {}
        for name in ("save", "check_forwards", "process_snapshots", "phase"):
            setattr(self.run, name, Mock())
        self.run.monitor = Mock()
        self.run.ctl = Mock(side_effect=lambda *_args, **_kwargs: self.status())
        self.run.reconciled = Mock(return_value={"original": "credited"})
        self.run.observe = self.observe
        self.baseline = self.status()
        self.baseline["history"] = []
        self.baseline["payment_progress"]["original"]["authorized_sat"] = 0
        self.addCleanup(patch.stopall)
        for name, method in (("arm", self.arm), ("send", self.send), ("receive", self.receive)):
            patch("sim.paid_diamond.probes." + name, side_effect=method).start()
        patch("sim.paid_diamond.time.monotonic", side_effect=lambda: self.clock.now).start()
        patch("sim.paid_diamond.time.sleep", side_effect=self.clock.sleep).start()

    def status(self):
        value = observation()["after"]
        value["payment_progress"] = {"original": {
            "authorized_sat": 2, "evidence_msat": 1500,
            "acknowledged_msat": 2000 if self.acknowledged else None, "in_flight": False,
        }}
        if self.clock.now < self.ready_at:
            value["purchases"][0]["contract"].update(id="trial", max_units=POLICY["trial_max_units"])
            value["history"] = []
        return value

    def observe(self):
        value = observation()
        value["before"] = self.status()
        if self.changed_agreement:
            value["before"]["purchases"][0]["contract"]["id"] = "changed-during-send"
        value["after"] = copy.deepcopy(value["before"])
        return value

    def arm(self, _run, source, destination, count, size):
        self.assertEqual((source, destination, count, size), ("source", "n03", PACKETS, PAYLOAD_BYTES))
        shape = {"stream_id": str(len(self.streams)), "packet_count": count, "payload_bytes": size}
        self.streams.append(shape)
        return shape

    def send(self, _run, _source, _destination, shape, rate):
        self.clock.now += (PACKETS - 1) / rate
        return {"stream_id": shape["stream_id"], "requested_packets": PACKETS,
                "submitted_packets": PACKETS, "submitted_bytes": PACKETS * PAYLOAD_BYTES,
                "stopped_reason": "send failed" if self.bad_sender else None}

    def receive(self, _run, _source, _destination, shape):
        stream = shape["stream_id"]
        first = self.receptions.get(stream, 0) == 0
        self.receptions[stream] = self.receptions.get(stream, 0) + 1
        count = PACKETS - int(self.never_complete or self.delay_last and first)
        report = {"stream_id": stream, "source": "source", "expected_packets": PACKETS,
                  "payload_bytes": PAYLOAD_BYTES, "unique_packets": count,
                  "unique_bytes": count * PAYLOAD_BYTES, "missing_packets": PACKETS - count,
                  "duplicate_packets": int(self.bad_receiver), "invalid_packets": 0, "latency": None}
        received(report, shape, "source")
        return report

    def drive(self):
        return self.run.drive_route("n01", self.baseline, "test")

    def test_cooldown_then_trial_and_confirmation_fit_without_more_bytes(self):
        # No provider is eligible for 60s; its ordinary trial then takes 40s.
        self.ready_at = 100
        result = self.drive()
        self.assertGreaterEqual(self.clock.now, 100)
        self.assertLess(self.clock.now, 180)
        self.assertEqual(len(self.streams), 11)
        self.assertLessEqual(len(self.streams) * PACKETS * PAYLOAD_BYTES, 65536)
        self.assertEqual(result["purchases"][0]["contract"]["id"], "full")
        self.run.reconciled.assert_called_once_with()

    def test_late_last_packet_drains_same_stream_without_extra_sends(self):
        self.delay_last = True
        self.drive()
        self.assertEqual(len(self.streams), 1)
        record, = self.run.evidence["route_phases"]["test"]
        self.assertEqual([r["unique_packets"] for r in record["receiver_samples"]], [15, 16])
        self.assertEqual(record["receiver"]["unique_packets"], PACKETS)
        self.assertEqual(self.clock.now, 4)

    def test_duplicate_receiver_evidence_is_not_retried_as_packet_delay(self):
        self.bad_receiver = True
        with self.assertRaisesRegex(RuntimeError, "invalid, duplicate"):
            self.drive()
        self.assertEqual(sum(self.receptions.values()), 1)
        self.run.reconciled.assert_not_called()

    def test_incomplete_payload_never_passes_even_with_good_quality_and_payment(self):
        self.never_complete = True
        with self.assertRaisesRegex(RuntimeError, "finite packet allowance"):
            self.drive()
        self.assertEqual(len(self.streams), MAX_PHASE_BATCHES)
        self.assertLess(self.clock.now, 180)
        self.run.reconciled.assert_not_called()

    def test_trial_changed_agreement_and_unacknowledged_payment_exhaust_finite_allowance(self):
        for failure in ("never promoted", "changed agreement", "unacknowledged"):
            with self.subTest(failure=failure):
                self.clock.now = 0
                self.streams.clear()
                self.ready_at = 1000 if failure == "never promoted" else 0
                self.changed_agreement = failure == "changed agreement"
                self.acknowledged = failure != "unacknowledged"
                with self.assertRaisesRegex(RuntimeError, "finite packet allowance"):
                    self.drive()
                self.assertEqual(len(self.streams), MAX_PHASE_BATCHES)
                self.assertLess(self.clock.now, 180)
        self.run.reconciled.assert_not_called()

    def test_partial_sender_result_is_saved_before_rejection(self):
        self.bad_sender = True
        with self.assertRaisesRegex(RuntimeError, "not fully submitted"):
            self.drive()
        record, = self.run.evidence["route_phases"]["test"]
        self.assertEqual(record["sender"]["stopped_reason"], "send failed")
        self.assertEqual(self.receptions, {})

    def test_time_bound_also_rejects_slow_final_observation(self):
        original = self.run.observe
        def slow():
            self.clock.now = 181
            return original()
        self.run.observe = slow
        with self.assertRaisesRegex(RuntimeError, "bounded window"):
            self.drive()
        self.run.reconciled.assert_not_called()


if __name__ == "__main__":
    unittest.main()
