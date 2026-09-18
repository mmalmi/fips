"""Lifecycle composition without devices, services or test-money mutations."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_phone import PaidPhoneRun
from sim.wifi_discovery import WifiRun


class PaidPhoneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = object.__new__(PaidPhoneRun)
        self.run.root = Path(self.temp.name)
        self.run.steps = self.run.root / "operations"
        self.run.steps.mkdir()
        self.run.evidence = {"passed": True}
        self.run.original_phone = b"fixture hashes"
        self.run.phone = Mock()
        self.run.ui = Mock(return_value={"customer": {"running": False}})
        self.run.mint_url = "http://198.51.100.10:41234"
        self.run.mint = Mock()
        self.run.mint.finish.return_value = {
            "url": self.run.mint_url, "retained_for_recovery": False, "stopped": True,
            "issued_sat": 512, "collected_sat": 512, "conserved": True, "test_only": True}
        self.run.access = Mock()
        self.run.access.release_mint.return_value = {"tcp_rule": False, "snat_rule": False}
        self.original = patch("sim.paid_phone.original_hashes", return_value=self.run.original_phone)
        self.hashes = self.original.start()
        self.addCleanup(self.original.stop)
        # Simulate the shared cleanup publishing its current provisional result.
        self.cleanup = patch.object(WifiRun, "finish", lambda run: run.save())
        self.cleanup.start()
        self.addCleanup(self.cleanup.stop)

    def stored(self):
        return json.loads((self.run.root / "result.json").read_text())

    def test_success_requires_terminal_mint_then_restoration_and_original_hashes(self):
        self.run.finish()
        self.run.access.release_mint.assert_called_once_with(self.run.mint.finish.return_value)
        self.assertTrue(self.stored()["passed"])
        self.assertTrue(self.stored()["original_phone_unchanged"])
        self.run.ui.assert_not_called()

    def test_final_hash_read_failure_cannot_leave_provisional_pass(self):
        self.hashes.side_effect = RuntimeError("ADB lost after router restoration")
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.run.finish()
        self.assertFalse(self.stored()["passed"])
        self.assertEqual(self.stored()["original_phone_check_error"], "RuntimeError")

    def test_changed_original_account_is_recorded_and_fails(self):
        self.hashes.return_value = b"changed fixture hashes"
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.run.finish()
        self.assertFalse(self.stored()["passed"])
        self.assertFalse(self.stored()["original_phone_unchanged"])

    def test_unknown_phone_action_is_never_replayed_during_failure_cleanup(self):
        self.run.evidence["passed"] = False
        self.run.phone.ensure_ready.side_effect = RuntimeError("pending click")
        self.run.mint.finish.return_value = {"retained_for_recovery": True, "stopped": False}
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.run.finish()
        self.run.ui.assert_not_called()
        self.run.access.release_mint.assert_not_called()
        self.assertTrue(self.stored()["phone_failure_cleanup"]["uncertain"])

    def test_resolved_running_phone_is_stopped_once_on_failed_run(self):
        self.run.evidence["passed"] = False
        self.run.ui.side_effect = [{"customer": {"running": True}}, {"customer": {"running": False}}]
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.run.finish()
        self.assertEqual([call.args for call in self.run.ui.call_args_list], [("status",), ("stop",)])
        self.assertTrue(self.stored()["phone_failure_cleanup"]["stopped"])

    def test_uncertain_mint_stop_keeps_customer_recovery_access(self):
        self.run.mint.finish.side_effect = RuntimeError("lost stop proof")
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.run.finish()
        self.run.access.release_mint.assert_not_called()
        self.assertFalse(self.stored()["passed"])
        self.assertIn("mint_cleanup_error", self.stored())

    def test_uncertain_mint_start_preserves_evidence_without_a_second_start(self):
        self.run.evidence["passed"] = False
        self.run.mint_url = None
        self.run.mint.attempted = True
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.run.finish()
        self.run.mint.start.assert_not_called()
        self.run.mint.finish.assert_not_called()
        self.run.access.release_mint.assert_not_called()
        self.assertTrue(self.stored()["mint_cleanup"]["startup_uncertain"])

    def test_unexpected_router_cleanup_failure_is_never_saved_as_pass(self):
        with patch.object(WifiRun, "finish", side_effect=RuntimeError("unexpected cleanup failure")):
            with self.assertRaises(RuntimeError):
                self.run.finish()
        self.assertFalse(self.stored()["passed"])

    def test_one_shot_intent_survives_lost_response_and_prevents_resubmission(self):
        operation = Mock(side_effect=RuntimeError("lost result"))
        with self.assertRaises(RuntimeError):
            self.run.once("import-fixture", operation)
        with self.assertRaises(FileExistsError):
            self.run.once("import-fixture", operation)
        operation.assert_called_once()
        self.assertTrue((self.run.steps / "import-fixture-intent.json").exists())

    def test_unknown_customer_reachability_prevents_any_grant_or_phone_setup(self):
        self.run.nodes = {name: Mock(interface="mesh0", state="/fixture/state", npub=name)
                          for name in ("n01", "n02", "n03")}
        self.run.customer = {"interface": "guest0", "cidr": "192.0.2.1/24", "entry_port": 41235}
        self.run.check_customer_access = Mock(side_effect=RuntimeError("probe completion uncertain"))
        with patch("sim.paid_phone.CustomerAccess") as access:
            access.return_value.enable.return_value = {"udp_rule": True}
            with self.assertRaisesRegex(RuntimeError, "probe completion uncertain"):
                self.run.before_launch()
        self.run.mint.grant.assert_not_called()
        self.run.phone.open_setup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
