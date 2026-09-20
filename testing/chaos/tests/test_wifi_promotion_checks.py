"""Instrumented artifact, real commitment and native-quality boundaries."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.paid_relay import relay_config
from sim.paid_wifi import PaidWifiRun
from sim.wifi_promotion_checks import (
    HOLD_MS, FULL_QUOTA, POLICY, barrier, configure, held_boundary, options, purchase, quality,
)
from sim.wifi_remote import digest
from test_wifi_promotion_finances import Fixture, IDS, MINT, add_route


def held_fixture():
    f = Fixture().funded()
    full = add_route(f.raw, "n01", f.trial["channel"], "full")
    row = f.raw["n01"]["controller"]["outgoing"]["full"]
    row["accepted"] = False
    f.raw["n01"]["controller"]["watched_routes"]["n03"]["pending"] = row["offer"]
    f.raw["n02"]["controller"]["incoming"]["full"] = {
        "phase": "Active", "offer": row["offer"], "channel": full["channel"], "contract": full["contract"]}
    status = {"armed": True, "active": True, "buyer": "n01", "destination": "n03",
        "trial_max_units": POLICY["trial_max_units"], "hold_ms": HOLD_MS, "terminal_reason": None,
        "candidate_requests": 2, "waiting_responses": 0, "held_responses": 1,
        "captured": {"offer_id": "offer-full", "purchase": full}, "capacity_bypassed": 0,
        "response_timeouts": 0, "response_cancellations": 0, "forwarded_replies": 1, "closed_responders": 0}
    return f, status


def native_quality(*, working=True):
    return {"destination": "n03", "price_selection": dict(POLICY),
        "feedback_window_ms": POLICY["feedback_timeout_ms"], "quality": {
            "receiver_reports_enabled": True, "next_hop": IDS["n02"],
            "has_recent_delivery_feedback": working, "delivery_feedback_timed_out": False,
            "loss_rate": 0.0 if working else None, "rtt_ms": 5.0 if working else None,
            "sent_packets": 8, "sent_bytes": 1024}}


class PromotionChecksTests(unittest.TestCase):
    def test_configuration_keeps_default_authority_and_only_enables_source_selection(self):
        for source in (True, False):
            before = relay_config(["mesh0"], MINT)
            config = configure(copy.deepcopy(before), source)
            self.assertEqual(config["terms"]["controller"], before["terms"]["controller"])
            self.assertEqual(config["terms"]["buyer_budget_sat"], 64)
            self.assertEqual(config["terms"]["quote_max_units"], FULL_QUOTA)
            self.assertEqual(config.get("price_selection"), POLICY if source else None)
            self.assertFalse(config["return_allowance"])
            self.assertEqual(config["neighbors"], [])
            self.assertEqual(config["transports"], before["transports"])

    def test_paid_wifi_profile_wires_only_n01_to_default_price_selection(self):
        run = object.__new__(PaidWifiRun)
        run.args = SimpleNamespace(interrupted_promotion=True)
        run.mint_url = MINT
        run.nodes = {name: SimpleNamespace(interface="mesh0", state="/private/" + name)
                     for name in IDS}
        for name, node in run.nodes.items():
            config = run.profile_config(node)
            self.assertEqual(config.get("price_selection"), POLICY if name == "n01" else None)
            self.assertEqual(config["terms"]["quote_max_units"], FULL_QUOTA)
            self.assertEqual(config["state_directory"], node.state)

    def test_artifact_change_after_options_is_rejected_before_starting_mint(self):
        run = object.__new__(PaidWifiRun)
        run.evidence = {"promotion_artifact": {"binary_sha256": digest(b"original")}}
        run.args = SimpleNamespace(binary=Mock())
        run.args.binary.read_bytes.return_value = b"changed"
        run.mint = Mock()
        with self.assertRaisesRegex(RuntimeError, "changed before setup"):
            run.setup()
        run.mint.start.assert_not_called()

    def test_options_reject_wrong_modes_before_creating_any_run(self):
        for field in ("active_outage", "brief_outage", "outage_node", "recovery_timing", "beacon_interval_secs"):
            args = SimpleNamespace(interrupted_promotion=True, **{field: True})
            with self.subTest(field=field), patch("sim.paid_wifi.WifiRun.__init__") as setup, \
                    self.assertRaises(ValueError):
                PaidWifiRun(args)
            setup.assert_not_called()
        self.assertIsNone(options(SimpleNamespace()))
        with self.assertRaises(ValueError):
            options(SimpleNamespace(promotion_provenance=Path("unused")))
        with self.assertRaisesRegex(ValueError, "provenance"):
            options(SimpleNamespace(interrupted_promotion=True))

    def test_existing_build_provenance_binds_both_features_and_exact_payload(self):
        with tempfile.TemporaryDirectory() as root:
            binary, path = Path(root) / "relay", Path(root) / "provenance.json"
            binary.write_bytes(b"fixture executable")
            record = {"source": {"features": ["testbench", "measurements"]}, "verification": {
                "features": ["testbench", "measurements"], "target": "aarch64-unknown-linux-musl",
                "build": {"exit_code": 0}, "source_changes_during_build": [], "patch_unchanged": True,
                "portable_lock_restored": True, "source_commit": "a" * 40,
                "artifact": {"sha256": digest(binary.read_bytes()), "bytes": binary.stat().st_size}}}
            args = SimpleNamespace(interrupted_promotion=True, promotion_provenance=path, binary=binary)
            path.write_text(json.dumps(record))
            self.assertFalse(options(args)["performance_comparable"])
            for mutation in ("features", "hash", "build", "drift"):
                changed = copy.deepcopy(record)
                if mutation == "features":
                    changed["verification"]["features"] = ["measurements"]
                elif mutation == "hash":
                    changed["verification"]["artifact"]["sha256"] = "f" * 64
                elif mutation == "build":
                    changed["verification"]["build"]["exit_code"] = 1
                else:
                    changed["verification"]["source_changes_during_build"] = ["changed"]
                path.write_text(json.dumps(changed))
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                    options(args)

    def test_candidate_requests_cannot_substitute_for_held_commit(self):
        _, status = held_fixture()
        barrier(status, "n01", "n03", held=True)
        for change in ({"held_responses": 0}, {"captured": None}, {"active": False},
                       {"terminal_reason": "expired"}, {"capacity_bypassed": 1}, {"buyer": "other"}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                barrier({**status, **change}, "n01", "n03", held=True)

    def test_capture_needs_both_real_journal_states_and_retired_predecessor(self):
        for mutation in (None, "active", "retired", "accepted", "pending", "trial", "channel"):
            f, status = held_fixture()
            source, provider = f.raw["n01"]["controller"], f.raw["n02"]["controller"]
            if mutation == "active":
                provider["incoming"]["full"]["phase"] = "Prepared"
            elif mutation == "retired":
                source["outgoing"]["trial"]["retired"] = False
            elif mutation == "accepted":
                source["outgoing"]["full"]["accepted"] = True
            elif mutation == "pending":
                source["watched_routes"]["n03"]["pending"] = {"id": "other"}
            elif mutation == "trial":
                source["outgoing"]["full"]["offer"]["trial"] = True
            elif mutation == "channel":
                status["captured"]["purchase"]["channel"] = {"id": "other"}
            if mutation is None:
                self.assertEqual(held_boundary(status, source, provider, f.trial, "n03"), status["captured"])
            else:
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                    held_boundary(status, source, provider, f.trial, "n03")

    def test_recovered_trial_accepts_only_exact_retained_remainder(self):
        f = Fixture().funded().replacement()
        value = f.remaining
        for quota in (28672, 32768, 123, FULL_QUOTA):
            changed = copy.deepcopy(value)
            changed["contract"]["max_units"] = quota
            if quota in (28672, FULL_QUOTA):
                self.assertEqual(purchase({"purchases": [changed]}, IDS["n03"], IDS["n02"],
                                          trial_quota=28672), changed)
            else:
                with self.assertRaises(RuntimeError):
                    purchase({"purchases": [changed]}, IDS["n03"], IDS["n02"], trial_quota=28672)

    def test_native_quality_keeps_unknown_distinct_from_healthy_or_timed_out(self):
        self.assertTrue(quality(native_quality(), "n03", IDS["n02"], working=True))
        self.assertFalse(quality(native_quality(working=False), "n03", IDS["n02"], working=True))
        unknown = native_quality(working=False)
        quality(unknown, "n03", IDS["n02"], unknown=True)
        for change in ({"delivery_feedback_timed_out": True}, {"loss_rate": 0.0}):
            changed = copy.deepcopy(unknown)
            changed["quality"].update(change)
            with self.assertRaises(RuntimeError):
                quality(changed, "n03", IDS["n02"], unknown=True)
