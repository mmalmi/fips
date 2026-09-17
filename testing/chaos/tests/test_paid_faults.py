"""Acceptance must reject configured-but-unobserved faults and lost authority."""

import copy
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sim.paid_faults import capture_probe, exercise_faults, in_fault_progress, paid_progress, sample_lost_stream, validate_effect, validate_finances, validate_probe


def reports(loss=False):
    count = 0 if loss else 8
    return {
        "sent": {"stream_id": "abc", "requested_packets": 8, "submitted_packets": 8,
                 "submitted_bytes": 2048, "stopped_reason": None},
        "received": {"source": "a", "stream_id": "abc", "expected_packets": 8, "payload_bytes": 256,
                     "unique_packets": count, "unique_bytes": count * 256,
                     "missing_packets": 8 - count, "invalid_packets": 0,
                     "duplicate_packets": 0, "out_of_order_packets": 0,
                     "latency": {"samples": count, "invalid_timestamps": 0,
                                 "min_us": 80_000 if count else None}},
    }


def snapshot(packets, drops, kind="delay"):
    options = {"gap": 2 if kind == "reorder" else 0}
    if kind in ("delay", "reorder"):
        options["delay"] = {"delay": 0.08, "jitter": 0, "correlation": 0}
    if kind == "loss":
        options["loss-random"] = {"loss": 1, "correlation": 0}
    if kind == "reorder":
        options["reorder"] = {"reorder": 1, "correlation": 0}
    return {"node": "n02", "peer": "n03", "container_id": "owned",
            "interface": "ve-n02-n03", "alias": "owned-link",
            "qdiscs": [{"kind": "netem", "root": True, "packets": packets, "drops": drops, "options": options}]}


def phase(loss=False, kind="delay"):
    kind = "loss" if loss else kind
    return {**reports(loss), "qdisc_before": snapshot(0, 0, kind),
            "qdisc_after": snapshot(0 if loss else 8, 8 if loss else 0, kind)}


def finances():
    result = {}
    for node in ("n01", "n02", "n03"):
        buyer = node != "n02"
        result[node] = {
            "funding": {node: (node, "wallet-operation")} if buyer else {},
            "budget": {"locked_sat": 32 if buyer else 0}, "wallet": [["UNSPENT", 1, 96]],
            "remaining": 61 if buyer else 64, "authorized": 3 if buyer else 0,
            "signed": {node: 3} if buyer else {},
            "signed_after": {node: 3} if buyer else {},
            "credited": {"n01": 3000, "n03": 3000} if not buyer else {},
            "seller_channels": {peer: {"submitted_msat": 2528, "reserved_msat": 2528,
                                        "lost_msat": 0, "paid_msat": 3000}
                                for peer in ("n01", "n03")} if not buyer else {},
            "buyer_units": {node: 2528} if buyer else {},
            "seller_units": {"n01": 2528, "n03": 2528} if not buyer else {},
        }
    return result


class PaidFaultTests(unittest.TestCase):
    def test_delivery_can_be_verified_without_synchronized_physical_clocks(self):
        evidence = reports()
        evidence["received"]["latency"] = None
        validate_probe(evidence["sent"], evidence["received"], measure_latency=False)
        with self.assertRaises(RuntimeError):
            validate_probe(evidence["sent"], evidence["received"])
        evidence["received"]["unique_packets"] -= 1
        with self.assertRaises(RuntimeError):
            validate_probe(evidence["sent"], evidence["received"], measure_latency=False)

    def test_loss_requires_submitted_missing_data_and_carrier_drops(self):
        evidence = phase(loss=True)
        validate_effect("loss", evidence)
        evidence["qdisc_after"] = snapshot(8, 0, "loss")
        with self.assertRaisesRegex(RuntimeError, "did not reach"):
            validate_effect("loss", evidence)
        evidence = phase(loss=True)
        evidence["sent"]["submitted_packets"] = 0
        with self.assertRaisesRegex(RuntimeError, "not fully submitted"):
            validate_effect("loss", evidence)

    def test_reorder_requires_actual_application_reordering(self):
        evidence = phase(kind="reorder")
        with self.assertRaisesRegex(RuntimeError, "reordering was not observed"):
            validate_effect("reorder", evidence)
        evidence["received"]["out_of_order_packets"] = 3
        validate_effect("reorder", evidence)

    def test_delay_requires_observed_latency_not_just_installed_qdisc(self):
        evidence = phase()
        validate_effect("delay", evidence)
        evidence["received"]["latency"]["min_us"] = 1
        with self.assertRaisesRegex(RuntimeError, "delay was not observed"):
            validate_effect("delay", evidence)

    def test_actual_qdisc_options_must_match_before_and_after(self):
        for kind, option in (("delay", "delay"), ("loss", "loss-random"), ("reorder", "gap")):
            for position in ("qdisc_before", "qdisc_after"):
                with self.subTest(kind=kind, position=position):
                    evidence = phase(loss=kind == "loss", kind=kind)
                    evidence["received"]["out_of_order_packets"] = 2
                    evidence[position]["qdiscs"][0]["options"][option] = 0
                    with self.assertRaisesRegex(RuntimeError, "netem fault options"):
                        validate_effect(kind, evidence)

    def test_in_fault_progress_requires_the_corresponding_original_route(self):
        before = finances()
        current = copy.deepcopy(before)
        run = SimpleNamespace(finances=Mock(return_value=current))
        current["n01"]["buyer_units"]["n01"] += 300
        current["n02"]["seller_units"]["n03"] += 300
        self.assertIsNone(in_fault_progress(run, before, "n01"))
        current["n02"]["seller_units"]["n01"] += 400
        self.assertIs(in_fault_progress(run, before, "n01"), current)
        current["n01"]["buyer_units"] = {"changed": 5000}
        with self.assertRaisesRegex(RuntimeError, "original route"):
            in_fault_progress(run, before, "n01")

    def test_original_loss_stream_rejects_late_delivery_after_clear(self):
        evidence = reports(loss=True)
        run = SimpleNamespace(nodes={"a": SimpleNamespace(npub="a")},
                              ctl=Mock(return_value={"probe": evidence["received"]}))
        sample_lost_stream(run, "a", "b", evidence)
        evidence["received"].update(unique_packets=1, unique_bytes=256, missing_packets=7)
        with self.assertRaisesRegex(RuntimeError, "delivery differs"):
            sample_lost_stream(run, "a", "b", evidence)

    def test_duplicate_invalid_and_unsubmitted_reports_cannot_pass(self):
        for key, value in (("duplicate_packets", 1), ("invalid_packets", 1),
                           ("stream_id", "stale"), ("unique_bytes", 0)):
            with self.subTest(key=key):
                evidence = reports()
                evidence["received"][key] = value
                with self.assertRaises(RuntimeError):
                    validate_probe(evidence["sent"], evidence["received"])

    def test_changed_carrier_or_missing_counter_cannot_pass(self):
        for key in ("node", "peer", "container_id", "interface", "alias"):
            with self.subTest(key=key):
                evidence = phase()
                evidence["qdisc_after"][key] = "changed"
                with self.assertRaisesRegex(RuntimeError, "owned interface"):
                    validate_effect("delay", evidence)
        evidence = phase()
        del evidence["qdisc_after"]["qdiscs"][0]["drops"]
        with self.assertRaisesRegex(RuntimeError, "numeric netem counters"):
            validate_effect("delay", evidence)

    def test_finances_preserve_channels_capital_lifetime_and_attempts(self):
        before = finances()
        after = copy.deepcopy(before)
        after["n01"].update(remaining=58, authorized=6, signed={"n01": 6}, buyer_units={"n01": 5056})
        after["n01"]["signed_after"] = {"n01": 6}
        after["n02"]["credited"]["n01"] = 6000
        after["n02"]["seller_channels"]["n01"].update(
            paid_msat=6000, submitted_msat=5056, reserved_msat=5056)
        after["n02"]["seller_units"]["n01"] = 5056
        validate_finances(before, after)
        for key, value in (("remaining", 64), ("wallet", []), ("funding", {}),
                           ("signed", {"replacement": 6}), ("buyer_units", {"n01": 1})):
            with self.subTest(key=key):
                changed = copy.deepcopy(after)
                changed["n01"][key] = value
                with self.assertRaises(RuntimeError):
                    validate_finances(before, changed)
        after["n02"]["credited"]["n01"] = 2000
        after["n02"]["seller_channels"]["n01"]["paid_msat"] = 2000
        with self.assertRaisesRegex(RuntimeError, "not reconciled"):
            validate_finances(before, after)

    def test_active_traffic_need_not_have_zero_outstanding_usage(self):
        before = finances()
        after = copy.deepcopy(before)
        after["n01"]["buyer_units"]["n01"] = 3094
        after["n02"]["seller_units"]["n01"] = 3094
        after["n02"]["seller_channels"]["n01"].update(submitted_msat=3094, reserved_msat=3094)
        validate_finances(before, after)
        after["n02"]["seller_channels"]["n01"]["reserved_msat"] = 11001
        with self.assertRaisesRegex(RuntimeError, "exposure"):
            validate_finances(before, after)

    def test_credit_may_advance_between_reads_but_needs_later_authorization(self):
        before = finances()
        after = copy.deepcopy(before)
        after["n02"]["credited"]["n01"] = 4000
        after["n02"]["seller_channels"]["n01"]["paid_msat"] = 4000
        after["n01"]["signed_after"]["n01"] = 4
        validate_finances(before, after)
        after["n01"]["signed_after"]["n01"] = 3
        with self.assertRaisesRegex(RuntimeError, "authorization"):
            validate_finances(before, after)

    def test_payment_target_is_fixed_while_new_background_usage_advances(self):
        before = finances()
        current = copy.deepcopy(before)
        current["n01"].update(remaining=59, authorized=5, signed={"n01": 5},
                              signed_after={"n01": 5}, buyer_units={"n01": 5094})
        current["n02"]["seller_units"]["n01"] = 5094
        current["n02"]["seller_channels"]["n01"].update(submitted_msat=5094, reserved_msat=5094)
        run = SimpleNamespace(finances=Mock(return_value=current))
        evidence = {}
        self.assertIsNone(paid_progress(run, before, "n01", evidence))
        self.assertEqual(evidence["payment_targets_sat"]["n01"], 6)
        current["n01"].update(remaining=57, authorized=7, signed={"n01": 7}, signed_after={"n01": 7})
        current["n01"]["buyer_units"]["n01"] = 7094
        current["n02"]["credited"]["n01"] = 6000
        current["n02"]["seller_units"]["n01"] = 7094
        current["n02"]["seller_channels"]["n01"].update(
            submitted_msat=7094, reserved_msat=7094, paid_msat=6000)
        self.assertIs(paid_progress(run, before, "n01", evidence), current)
        self.assertEqual(evidence["payment_targets_sat"]["n01"], 6)

    def test_payment_progress_does_not_substitute_reverse_route_usage(self):
        before = finances()
        current = copy.deepcopy(before)
        current["n01"]["buyer_units"]["n01"] += 2200
        current["n02"]["seller_units"]["n03"] += 2200
        run = SimpleNamespace(finances=Mock(return_value=current))
        evidence = {}
        self.assertIsNone(paid_progress(run, before, "n01", evidence))
        self.assertNotIn("payment_targets_sat", evidence)

    def test_sampling_race_retains_bounded_diagnostic(self):
        run = SimpleNamespace(finances=Mock(side_effect=RuntimeError(
            "financial observation changed during sampling")))
        evidence = {}
        with self.assertRaises(RuntimeError):
            paid_progress(run, finances(), "n01", evidence)
        self.assertEqual(evidence["last_financial_validation_error"],
                         "financial observation changed during sampling")
        self.assertEqual(evidence["financial_sample_attempts"], 1)

    def test_loss_observes_full_interval_and_records_both_reports(self):
        evidence = reports(loss=True)
        run = SimpleNamespace(nodes={"a": SimpleNamespace(npub="a"), "b": SimpleNamespace(npub="b")})
        run.ctl = Mock(side_effect=[{}, {"probe": evidence["sent"]},
                                   {"probe": evidence["received"]}, {"probe": evidence["received"]}])
        saved = {}
        with patch("sim.paid_faults.time.monotonic", side_effect=[0, 1, 3]), \
                patch("sim.paid_faults.secrets.token_hex", return_value="abc"), \
                patch("sim.paid_faults.time.sleep") as sleep:
            capture_probe(run, "a", "b", Mock(), saved, loss=True)
        self.assertEqual(saved, evidence)
        sleep.assert_called_once_with(0.25)
        self.assertTrue(run.ctl.call_args_list[0].kwargs["probe"]["measure_one_way_latency"])

    def test_fault_is_cleared_even_when_probe_fails(self):
        run = SimpleNamespace(evidence={"phases": []}, veth=Mock())
        with patch("sim.paid_faults.capture_probe", side_effect=RuntimeError("probe failed")):
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                exercise_faults(run, finances(), Mock())
        run.veth.clear_scoped_impairment.assert_called_once_with("n02", "n03")
        self.assertFalse(run.evidence["phases"][0]["passed"])


if __name__ == "__main__":
    unittest.main()
