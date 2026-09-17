"""Carrier interruption needs positive observations, not a configured loss rate."""

import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sim.paid_payment_faults import (classify, diagnostics, exercise_payment_faults,
                                    interrupt, reconciled, sample, short_fault,
                                    supported_target, unresolved, validate_interruption)
from sim.paid_faults import validate_effect, validate_impairment
from sim.paid_relay import PaidRelayRun
from test_paid_faults import finances, reports, snapshot


def status():
    return {
        "measurements": {"version": 1, "process_id": 42,
                         "operations": {name: {"spans": 2, "journal_commits": 3}
                                        for name in ("payment_usage", "payment_update", "payment_sign")}},
        "payment_progress": {"n01": {"evidence_msat": 2528, "authorized_sat": 3,
                                     "acknowledged_msat": 3000, "in_flight": False}},
        "control_traffic": [{"service_port": 44743, "counters": {
            "stream_bytes_sent": 100, "stream_bytes_received": 90,
            "requests_started": 2, "requests_received": 1}}],
    }


def observation(start=0):
    value = status()
    return {"started": start, "finished": start + 0.1, "buyer": diagnostics(value, "n01"),
            "provider": diagnostics(value), "seller_usage": {
                "paid_msat": 3000, "submitted_msat": 2528, "reserved_msat": 2528, "lost_msat": 0}}


def delayed(start):
    value = observation(start)
    value["buyer"]["progress"].update(evidence_msat=5094, in_flight=True)
    value["buyer"]["control"]["requests_started"] += 1
    value["seller_usage"].update(submitted_msat=5094, reserved_msat=5094)
    return value


def phase():
    before, after = snapshot(0, 0, "loss"), snapshot(0, 4, "loss")
    before["peer"] = after["peer"] = "n01"
    return {"before": observation(), "observations": [delayed(2), delayed(4)],
            "qdisc_before": before, "qdisc_after": after, "observation_seconds": 8.5}


class PaymentCarrierTests(unittest.TestCase):
    def test_measurements_and_original_channel_are_required(self):
        self.assertEqual(diagnostics(status(), "n01")["progress"]["acknowledged_msat"], 3000)
        cases = []
        for field in ("measurements", "payment_progress", "control_traffic"):
            value = status()
            del value[field]
            cases.append(value)
        value = status()
        value["measurements"] = None
        cases.append(value)
        value = status()
        value["payment_progress"] = {"replacement": value["payment_progress"]["n01"]}
        cases.append(value)
        value = status()
        value["control_traffic"] *= 2
        cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                diagnostics(value, "n01")

    def test_unknown_ack_is_preserved_but_invalid_evidence_rejected(self):
        value = status()
        value["payment_progress"]["n01"]["acknowledged_msat"] = None
        self.assertIsNone(diagnostics(value, "n01")["progress"]["acknowledged_msat"])
        for field in ("authorized_sat", "evidence_msat", "acknowledged_msat"):
            for bad in (-1, True, 1.5, "1"):
                with self.subTest(field=field, bad=bad):
                    value = status()
                    value["payment_progress"]["n01"][field] = bad
                    with self.assertRaises(RuntimeError):
                        diagnostics(value, "n01")

    def test_one_inflight_or_instantaneous_observation_is_insufficient(self):
        evidence = phase()
        validate_interruption(evidence)
        for observations in ([delayed(2)], [delayed(2), delayed(2.5)]):
            evidence["observations"] = observations
            with self.assertRaisesRegex(RuntimeError, "separated"):
                validate_interruption(evidence)

    def test_stable_lag_requires_fresh_evidence_and_real_payment_attempt(self):
        self.assertTrue(unresolved(observation(), delayed(2)))
        for field, value in (("in_flight", False), ("evidence_msat", 2528),
                             ("acknowledged_msat", 2000), ("acknowledged_msat", None)):
            changed = delayed(2)
            changed["buyer"]["progress"][field] = value
            self.assertFalse(unresolved(observation(), changed))
        changed = delayed(2)
        changed["buyer"]["control"]["requests_started"] = 2
        self.assertFalse(unresolved(observation(), changed))

    def test_setup_can_advance_ack_before_the_first_stable_unresolved_sample(self):
        evidence = phase()
        for item in evidence["observations"]:
            item["buyer"]["progress"]["acknowledged_msat"] = 4000
        validate_interruption(evidence)
        evidence["observations"][-1]["buyer"]["progress"]["acknowledged_msat"] = 5000
        with self.assertRaisesRegex(RuntimeError, "changed among"):
            validate_interruption(evidence)

    def test_optional_mode_is_explicit_in_evidence_and_defaults_off(self):
        args = SimpleNamespace(output=Path("/tmp/not-created"))
        self.assertFalse(PaidRelayRun(args).evidence["payment_faults_requested"])
        args.payment_faults = True
        self.assertTrue(PaidRelayRun(args).evidence["payment_faults_requested"])

    def test_changed_process_or_reset_counters_cannot_certify_lag(self):
        for side in ("buyer", "provider"):
            for mutation in ("process", "control", "operation"):
                value = delayed(2)
                if mutation == "process":
                    value[side]["process_id"] += 1
                elif mutation == "control":
                    value[side]["control"]["stream_bytes_received"] = 0
                else:
                    value[side]["operations"]["payment_update"]["journal_commits"] = 0
                with self.subTest(side=side, mutation=mutation), self.assertRaises(RuntimeError):
                    unresolved(observation(), value)

    def test_owned_drops_and_short_fault_bound_are_required(self):
        for duration in (0, 7.9, 12, 30):
            value = phase()
            value["observation_seconds"] = duration
            with self.subTest(duration=duration), self.assertRaisesRegex(RuntimeError, "bound"):
                validate_interruption(value)
        value = phase()
        value["qdisc_after"]["qdiscs"][0]["drops"] = 0
        with self.assertRaisesRegex(RuntimeError, "no observed drops"):
            validate_interruption(value)
        value = phase()
        value["qdisc_after"]["alias"] = "another run"
        with self.assertRaisesRegex(RuntimeError, "owned interface"):
            validate_interruption(value)

    def test_reverse_carrier_loss_does_not_require_losing_the_forward_data(self):
        evidence = {**phase(), **reports()}
        self.assertEqual(validate_impairment("loss", evidence)["drops"], 4)
        validate_interruption(evidence)
        with self.assertRaisesRegex(RuntimeError, "delivery differs"):
            validate_effect("loss", evidence)

    def test_usage_and_update_spans_are_not_accepted_credit_or_packet_identity(self):
        before, after = observation(), delayed(2)
        after["provider"]["operations"]["payment_update"]["spans"] += 2
        result = classify(before, after)
        self.assertEqual(result["provider_update_spans_delta"], 2)
        self.assertEqual(result["original_channel_credit_delta_msat"], 0)
        self.assertIn("cannot identify", result["request_type"])
        self.assertIn("not proof", result["scope"])

    def test_supported_target_is_capped_by_evidence_and_preserves_prior_authorization(self):
        value = delayed(2)
        self.assertEqual(supported_target(value), 6000)
        value["seller_usage"]["submitted_msat"] = 100_000
        self.assertEqual(supported_target(value), 6000)
        value["buyer"]["progress"]["authorized_sat"] = 7
        self.assertEqual(supported_target(value), 7000)
        value["buyer"]["progress"]["authorized_sat"] = 33
        with self.assertRaisesRegex(RuntimeError, "original channel"):
            supported_target(value)

    def test_recovery_uses_frozen_target_not_new_background_debt(self):
        prior = finances()
        current = copy.deepcopy(prior)
        current["n01"].update(remaining=58, authorized=6, signed={"n01": 6},
                              signed_after={"n01": 6}, buyer_units={"n01": 7094})
        current["n02"]["credited"]["n01"] = 6000
        current["n02"]["seller_units"]["n01"] = 7094
        current["n02"]["seller_channels"]["n01"].update(
            paid_msat=6000, submitted_msat=7094, reserved_msat=7094)
        run = SimpleNamespace(finances=Mock(return_value=current))
        evidence = {"before": observation(), "target_msat": 6000}
        after = delayed(10)
        after["buyer"]["progress"].update(
            acknowledged_msat=6000, authorized_sat=6, evidence_msat=7094)
        after["seller_usage"].update(paid_msat=6000, submitted_msat=7094, reserved_msat=7094)
        with patch("sim.paid_payment_faults.sample", return_value=after):
            self.assertIs(reconciled(run, prior, "n01", "n01", evidence), current)
            self.assertEqual(evidence["target_msat"], 6000)
            after["buyer"]["progress"]["acknowledged_msat"] = None
            self.assertIsNone(reconciled(run, prior, "n01", "n01", evidence))
            after["buyer"]["progress"]["acknowledged_msat"] = 5000
            self.assertIsNone(reconciled(run, prior, "n01", "n01", evidence))

    def test_recovery_rejects_changed_financial_authority(self):
        prior, current = finances(), finances()
        current["n01"]["funding"] = {}
        run = SimpleNamespace(finances=Mock(return_value=current))
        evidence = {"before": observation(), "target_msat": 6000}
        with self.assertRaisesRegex(RuntimeError, "funding"):
            reconciled(run, prior, "n01", "n01", evidence)
        self.assertIn("funding", evidence["last_financial_validation_error"])
        self.assertIs(evidence["last_financial_observation"], current)

    def test_snapshot_keeps_only_aggregate_counters_and_original_channel_amounts(self):
        run = SimpleNamespace(ctl=Mock(return_value=status()), state_json=Mock(return_value={
            "ledger": {"channels": [{"terms": {"id": "n01", "private": "never-record"},
                                      "usage": observation()["seller_usage"]}],
                       "private": "never-record"}}))
        value = sample(run, "n01", "n01")
        self.assertNotIn("never-record", repr(value))
        run.state_json.return_value["ledger"]["channels"] = []
        with self.assertRaisesRegex(RuntimeError, "original seller channel"):
            sample(run, "n01", "n01")

    def test_probe_or_alarm_failure_still_clears_exact_reverse_qdisc(self):
        for failure in (RuntimeError("probe failed"), TimeoutError("observation bound")):
            run = SimpleNamespace(evidence={"phases": []}, veth=Mock())
            with patch("sim.paid_payment_faults.short_fault"), \
                    patch("sim.paid_payment_faults.capture_probe", side_effect=failure):
                with self.assertRaises(type(failure)):
                    interrupt(run, finances(), "n01", "n03", Mock(return_value=observation()))
            run.veth.clear_scoped_impairment.assert_called_once_with("n02", "n01")
            self.assertFalse(run.evidence["phases"][0]["passed"])

    def test_local_alarm_restores_outer_remaining_deadline_even_on_error(self):
        with patch("sim.paid_payment_faults.signal.getsignal", return_value="outer") as handler, \
                patch("sim.paid_payment_faults.signal.getitimer", return_value=(100, 0)), \
                patch("sim.paid_payment_faults.signal.signal") as set_handler, \
                patch("sim.paid_payment_faults.signal.setitimer") as timer, \
                patch("sim.paid_payment_faults.time.monotonic", side_effect=[10, 15]):
            with self.assertRaisesRegex(RuntimeError, "failure"):
                with short_fault():
                    raise RuntimeError("failure")
        self.assertEqual(timer.call_args_list[0].args[1], 12)
        self.assertEqual(timer.call_args_list[-1].args[1], 95)
        self.assertEqual(set_handler.call_args_list[-1].args[1], "outer")
        handler.assert_called_once()

    def test_both_directions_use_automatic_recovery_and_healthy_burst(self):
        run = SimpleNamespace(evidence={"phases": [], "fault_scope": {}})
        before = finances()
        def wait(_description, predicate, _seconds):
            return predicate()
        with patch("sim.paid_payment_faults.interrupt", return_value=before) as fault, \
                patch("sim.paid_payment_faults.capture_probe") as probe, \
                patch("sim.paid_payment_faults.paid_progress", return_value=before) as paid:
            self.assertIs(exercise_payment_faults(run, before, wait), before)
        self.assertEqual([call.args[2:4] for call in fault.call_args_list],
                         [("n01", "n03"), ("n03", "n01")])
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(paid.call_count, 2)
        self.assertIn("do not distinguish", run.evidence["fault_scope"]["payment"])


if __name__ == "__main__":
    unittest.main()
