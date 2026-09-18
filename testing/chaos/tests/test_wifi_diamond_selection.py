"""A cheap quote is insufficient without fresh delivery and reconciled credit."""

import copy
import unittest

from sim.wifi_diamond_selection import (
    FEES, FULL_QUOTA, POLICY, PRICE_CEILING, bounded_capital, paid_channel_progress,
    trial_ids, working_route,
)


PROVIDER = [1] * 16
DESTINATION = [3] * 16


def observation():
    purchase = {"provider": PROVIDER, "channel": {"id": "original", "capacity_sat": 64},
                "contract": {"id": "full", "destination": DESTINATION, "billing": "forwarding_data",
                             "price": {"msat": FEES["n01"], "per_bytes": 1024}, "max_units": FULL_QUOTA}}
    status = {"purchases": [purchase], "remaining_budget_sat": 120,
              "funding_budget": {"wallet_refunded_sat": 0, "wallet_debited_sat": 128,
                                 "locked_sat": 128, "pending_reserved_sat": 0, "exposure_sat": 128},
              "watched_routes": [{"destination": "dest", "billing": "forwarding_data",
                                  "max_rate_msat_per_kib": PRICE_CEILING, "paused": False, "pending": None}],
              "history": [{**purchase, "contract": {**purchase["contract"], "id": "trial",
                                                    "max_units": POLICY["trial_max_units"]}}]}
    quality = {"destination": "dest", "price_selection": POLICY.copy(),
               "feedback_window_ms": POLICY["feedback_timeout_ms"],
               "quality": {"next_hop": PROVIDER, "receiver_reports_enabled": True,
                           "has_recent_delivery_feedback": True, "delivery_feedback_timed_out": False,
                           "rtt_ms": 8.0, "loss_rate": 0.0, "goodput_bps": 8000,
                           "sent_packets": 16, "sent_bytes": 4160}}
    return {"before": copy.deepcopy(status), "after": copy.deepcopy(status), "quality": quality}


def accepted(value):
    return working_route(**value, destination=DESTINATION, destination_npub="dest",
                         provider=PROVIDER, fee=FEES["n01"])


class SelectionTests(unittest.TestCase):
    def test_one_full_agreement_has_actual_fresh_acceptable_native_quality(self):
        value = observation()
        self.assertEqual(accepted(value), value["after"]["purchases"][0])
        self.assertEqual(trial_ids(value["after"], PROVIDER), {"trial"})
        self.assertEqual(trial_ids(value["after"], [2] * 16), set())

    def test_missing_stale_invalid_or_wrong_carrier_feedback_cannot_pass(self):
        for field, changed in (("rtt_ms", None), ("rtt_ms", 5001), ("rtt_ms", float("nan")),
                               ("loss_rate", 0.26), ("loss_rate", -0.1), ("loss_rate", None),
                               ("goodput_bps", 0), ("goodput_bps", None), ("next_hop", [2] * 16),
                               ("has_recent_delivery_feedback", False), ("delivery_feedback_timed_out", True),
                               ("receiver_reports_enabled", False)):
            value = observation()
            value["quality"]["quality"][field] = changed
            with self.subTest(field=field, value=changed):
                self.assertIsNone(accepted(value))

    def test_pending_changed_or_unpromoted_agreement_cannot_pass(self):
        value = observation()
        value["after"]["watched_routes"][0]["pending"] = {"offer": "new"}
        self.assertIsNone(accepted(value))
        value = observation()
        value["after"]["purchases"][0]["contract"]["id"] = "replacement"
        self.assertIsNone(accepted(value))
        value = observation()
        for key in ("before", "after"):
            value[key]["purchases"][0]["contract"]["max_units"] = POLICY["trial_max_units"]
        self.assertIsNone(accepted(value))

    def test_broadened_watch_price_capital_and_quality_policy_fail(self):
        changes = (
            lambda v: v["after"]["watched_routes"][0].update(max_rate_msat_per_kib=8192),
            lambda v: v["after"]["funding_budget"].update(wallet_refunded_sat=1),
            lambda v: v["after"]["funding_budget"].update(pending_reserved_sat=1),
            lambda v: v["after"]["funding_budget"].update(wallet_debited_sat=129),
            lambda v: v["quality"]["price_selection"].update(feedback_timeout_ms=1000),
            lambda v: v["quality"]["quality"].update(sent_packets=0),
        )
        for change in changes:
            value = observation()
            change(value)
            with self.subTest(change=changes.index(change)), self.assertRaises(RuntimeError):
                accepted(value)
        value = observation()
        value["after"]["remaining_budget_sat"] = 129
        with self.assertRaises(RuntimeError):
            bounded_capital(value["after"])

    def test_payment_must_advance_evidence_and_be_acknowledged_on_same_channel(self):
        progress = {"authorized_sat": 7, "evidence_msat": 6100,
                    "acknowledged_msat": 7000, "in_flight": False}
        self.assertTrue(paid_channel_progress({"payment_progress": {"original": progress}}, "original", 6))
        for field, changed in (("authorized_sat", 6), ("evidence_msat", 6000),
                               ("acknowledged_msat", 6999), ("acknowledged_msat", None), ("in_flight", True)):
            with self.subTest(field=field):
                value = {"payment_progress": {"original": {**progress, field: changed}}}
                self.assertFalse(paid_channel_progress(value, "original", 6))
        self.assertFalse(paid_channel_progress({"payment_progress": {"replacement": progress}}, "original", 6))


if __name__ == "__main__":
    unittest.main()
