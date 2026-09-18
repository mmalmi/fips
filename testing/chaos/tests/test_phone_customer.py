"""Acceptance UI boundaries with an observed, explicitly selected fake device."""

import base64
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.phone_customer import ACTIVITY, PACKAGE, PhoneCustomer


class PhoneCustomerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.adb = self.root / "adb"
        self.adb.write_text("unused test executable")
        self.adb.chmod(0o700)
        self.output = self.root / "evidence"
        self.phone = PhoneCustomer(self.adb, "authorized-fixture", self.output)
        self.calls = []
        self.serial = "authorized-fixture"
        self.connected = b"device"
        self.policy = b"showing=false inputRestricted=false"
        self.foreground = PACKAGE + "/" + ACTIVITY
        self.status_value = {"customer": {"configured": True, "running": False}, "balance_sat": 128}
        self.marker = {"action": "buy", "ok": True, "old": True}
        self.archived = []
        self.taps = []
        self.result = {"action": "buy", "ok": True}
        self.lose_tap_reply = False
        self.lose_launch_reply = False
        self.launches = []
        self.fail_archive = False
        self.after_archive_foreground = None
        self.button = {"text": "Buy forwarding", "enabled": "true", "clickable": "true",
                       "package": PACKAGE, "bounds": "[10,20][110,80]"}
        self.extra_buttons = []
        self.funding = None
        self.lose_funding_reply = False
        self.account = {"fixture": "private account"}
        self.runner = patch("sim.phone_customer.subprocess.run", side_effect=self.run_adb)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def run_adb(self, command, input=None, **_kwargs):
        self.calls.append((command, input))
        self.assertEqual(command[:3], [str(self.adb), "-s", "authorized-fixture"])
        args = command[3:]
        if args == ["get-serialno"]:
            data = self.serial.encode()
        elif args == ["get-state"]:
            data = self.connected
        elif args == ["exec-out", "screencap", "-p"]:
            data = b"\x89PNG\r\n\x1a\nfixture"
        elif len(args) == 2 and args[0] == "shell" and "cat > files/funding.json" in args[1]:
            self.assertIsNone(self.funding)
            self.assertTrue((self.output / "funding-intent.json").is_file())
            self.funding = json.loads(input)
            if self.lose_funding_reply:
                raise subprocess.TimeoutExpired(command, 25)
            data = b""
        else:
            self.assertEqual(args, ["shell", "sh"])
            shell = shlex.split(input.decode())
            if shell == ["dumpsys", "window", "policy"]:
                data = self.policy
            elif shell == ["dumpsys", "activity", "activities"]:
                data = ("topResumedActivity=ActivityRecord{fixture u0 " + self.foreground + " t1}").encode()
            elif shell == ["pm", "path", PACKAGE]:
                data = b"package:/data/app/acceptance/base.apk"
            elif shell == ["run-as", PACKAGE, "id", "-u"]:
                data = b"10123"
            elif shell[:4] == ["run-as", PACKAGE, "sh", "-c"]:
                script = shell[4]
                if script.startswith("test ! -e"):
                    # Intent must be durable before touching the old marker.
                    self.assertTrue((self.output / "pending.json").is_file())
                    if self.fail_archive:
                        raise subprocess.TimeoutExpired(command, 25)
                    self.archived.append(self.marker)
                    self.marker = None
                    if self.after_archive_foreground:
                        self.foreground = self.after_archive_foreground
                    data = b""
                elif "last-status.json" in script:
                    data = json.dumps(self.status_value).encode()
                elif "last-action.json" in script:
                    data = json.dumps(self.marker).encode()
                elif "files/funding.json" in script:
                    data = json.dumps(self.funding).encode()
                elif "files/client/state/" in script:
                    data = json.dumps(self.account).encode()
                else:
                    self.fail("unexpected private read")
            elif shell[:2] == ["uiautomator", "dump"]:
                data = b"UI hierarchy dumped"
            elif shell[0] == "cat":
                from xml.etree import ElementTree
                tree = ElementTree.Element("hierarchy")
                for button in [self.button, *self.extra_buttons]:
                    ElementTree.SubElement(tree, "node", button)
                data = ElementTree.tostring(tree)
            elif shell[:2] == ["rm", "-f"]:
                data = b""
            elif shell == ["wm", "size"]:
                data = b"Physical size: 1080x2400"
            elif shell[:2] == ["input", "tap"]:
                pending = json.loads((self.output / "pending.json").read_text())
                self.assertTrue((self.output / pending["id"] / "armed.json").is_file())
                self.taps.append(shell[2:])
                self.marker = self.result
                if self.lose_tap_reply:
                    raise subprocess.TimeoutExpired(command, 25)
                data = b""
            elif shell[:2] == ["am", "start"]:
                self.launches.append(shell)
                already_top = self.foreground == PACKAGE + "/" + ACTIVITY
                self.foreground = PACKAGE + "/" + ACTIVITY
                if not already_top or "--activity-single-top" in shell:
                    self.marker = {"action": "preview", "ok": True}
                self.setup_command = shell
                if self.lose_launch_reply:
                    raise subprocess.TimeoutExpired(command, 25)
                data = b"Status: ok"
            else:
                self.fail("unexpected phone command")
        return subprocess.CompletedProcess(command, 0, stdout=data, stderr=b"")

    def test_old_same_action_success_is_archived_and_cannot_complete_a_new_tap(self):
        old = dict(self.marker)
        self.result = None
        with self.assertRaises(TimeoutError):
            self.phone.click("Buy forwarding", "buy", timeout=0)
        self.assertEqual(self.archived, [old])
        pending = json.loads((self.output / "pending.json").read_text())
        saved = json.loads((self.output / pending["id"] / "intent.json").read_text())
        self.assertEqual(saved["previous_marker"], old)
        with self.assertRaisesRegex(RuntimeError, "unresolved"):
            self.phone.click("Buy forwarding", "buy", timeout=0)
        self.assertEqual(len(self.taps), 1)

    def test_lost_tap_reply_reopens_and_observes_success_without_retapping(self):
        self.lose_tap_reply = True
        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            self.phone.click("Buy forwarding", "buy", timeout=0)
        reopened = PhoneCustomer(self.adb, self.serial, self.output)
        self.assertEqual(reopened.reconcile(timeout=0), self.status_value)
        self.assertEqual(len(self.taps), 1)
        self.assertFalse((self.output / "pending.json").exists())
        completed = list(self.output.glob("*/completed.json"))
        self.assertEqual(len(completed), 1)
        self.assertEqual(json.loads(completed[0].read_text())["result"], self.result)

    def test_saved_completion_survives_interrupted_pending_cleanup(self):
        unlink = Path.unlink

        def interrupt(path, *args, **kwargs):
            if path == self.output / "pending.json":
                raise RuntimeError("interrupted pending cleanup")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", interrupt):
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                self.phone.click("Buy forwarding", "buy", timeout=0)
        self.marker = None
        reopened = PhoneCustomer(self.adb, self.serial, self.output)
        self.assertEqual(reopened.reconcile(timeout=0), self.status_value)
        self.assertEqual(len(self.taps), 1)
        self.assertFalse((self.output / "pending.json").exists())

    def test_uncertain_archive_never_taps_or_accepts_the_stale_marker(self):
        self.fail_archive = True
        with self.assertRaises(RuntimeError):
            self.phone.click("Buy forwarding", "buy", timeout=0)
        with self.assertRaisesRegex(RuntimeError, "preparation is uncertain"):
            self.phone.reconcile(timeout=0)
        self.assertEqual(self.taps, [])
        self.assertTrue((self.output / "pending.json").exists())

    def test_failed_or_different_action_preserves_unresolved_intent(self):
        for result in ({"action": "buy", "error": "may have partially completed"},
                       {"action": "status", "ok": True}):
            with self.subTest(result=result):
                directory = self.root / ("attempt-" + str(len(self.taps)))
                self.output = directory
                phone = PhoneCustomer(self.adb, self.serial, directory)
                self.result = result
                with self.assertRaisesRegex(RuntimeError, "pending attempt retained"):
                    phone.click("Buy forwarding", "buy", timeout=0)
                self.assertTrue((directory / "pending.json").exists())

    def test_rejects_changed_serial_locked_or_foreign_activity_before_mutation(self):
        for name, value in (("serial", "another-device"), ("connected", b"unauthorized"),
                            ("policy", b"showing=true inputRestricted=true"),
                            ("policy", b"unknown keyguard state"),
                            ("foreground", "org.fips.relaybench/org.fips.relaybench.MainActivity")):
            original = getattr(self, name)
            with self.subTest(name=name, value=value):
                setattr(self, name, value)
                with self.assertRaises(RuntimeError):
                    self.phone.click("Buy forwarding", "buy", timeout=0)
                setattr(self, name, original)
        self.assertEqual(self.taps, [])
        self.assertEqual(self.archived, [])

    def test_foreground_change_after_archiving_retains_intent_without_tap(self):
        self.after_archive_foreground = "other.app/other.app.MainActivity"
        with self.assertRaisesRegex(RuntimeError, "foreground"):
            self.phone.click("Buy forwarding", "buy", timeout=0)
        self.assertEqual(self.taps, [])
        self.assertTrue((self.output / "pending.json").exists())

    def test_enabled_unique_exact_package_and_on_screen_bounds_are_required(self):
        for change in ({"enabled": "false"}, {"clickable": "false"}, {"package": "other.app"},
                       {"text": "Buy forwarding now"}, {"bounds": "[0,0][9999,9999]"}):
            original = self.button
            self.button = {**original, **change}
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.phone.click("Buy forwarding", "buy", timeout=0)
            self.button = original
        self.extra_buttons = [dict(self.button)]
        with self.assertRaises(RuntimeError):
            self.phone.click("Buy forwarding", "buy", timeout=0)
        self.assertEqual(self.taps, [])

    def test_setup_uses_isolated_identity_and_stdin_preserving_all_profile_fields(self):
        self.foreground = "other.app/other.app.MainActivity"
        profile = {"billing": "forwarding_data", "private_fixture": "bearer-fixture"}
        self.phone.open_setup(profile, timeout=0)
        uri = self.setup_command[self.setup_command.index("-d") + 1]
        self.assertEqual(urlsplit(uri).scheme, "fipsbench-acceptance")
        encoded = parse_qs(urlsplit(uri).query)["profile"][0]
        self.assertEqual(json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))), profile)
        self.assertIn(PACKAGE + "/" + ACTIVITY, self.setup_command)
        self.assertIn("--activity-single-top", self.setup_command)
        self.assertEqual(self.setup_command[self.setup_command.index("-a") + 1], "android.intent.action.VIEW")
        self.assertFalse(any("profile=" in item for command, _ in self.calls for item in command))
        self.assertFalse(any("bearer-fixture" in path.read_text()
                             for path in self.output.rglob("*.json")))

    def test_launch_requests_a_fresh_preview_when_acceptance_is_already_top(self):
        self.marker = {"action": "preview", "ok": True, "old": True}
        old = dict(self.marker)
        self.assertEqual(self.phone.launch(timeout=0), self.status_value)
        self.assertEqual(self.archived, [old])
        self.assertEqual(len(self.launches), 1)
        command = self.launches[0]
        self.assertIn("--activity-single-top", command)
        self.assertEqual(command[command.index("-a") + 1], "android.intent.action.VIEW")
        self.assertNotIn("-d", command)
        self.assertEqual(self.taps, [])

    def test_uncertain_launch_blocks_launch_and_setup_until_observed_without_replay(self):
        self.lose_launch_reply = True
        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            self.phone.launch(timeout=0)
        pending = (self.output / "pending.json").read_bytes()
        for action in (lambda: self.phone.launch(timeout=0),
                       lambda: self.phone.open_setup({"billing": "forwarding_data"}, timeout=0)):
            with self.assertRaisesRegex(RuntimeError, "unresolved"):
                action()
            self.assertEqual((self.output / "pending.json").read_bytes(), pending)
        self.assertEqual(len(self.launches), 1)
        self.assertEqual(self.phone.reconcile(timeout=0), self.status_value)
        self.assertEqual(len(self.launches), 1)

    def test_evidence_cannot_be_reused_for_another_device(self):
        with self.assertRaisesRegex(RuntimeError, "another device"):
            PhoneCustomer(self.adb, "other-fixture", self.output)

    def test_concurrent_adapter_cannot_issue_a_second_action(self):
        with self.phone.locked():
            with self.assertRaises(BlockingIOError):
                self.phone.click("Buy forwarding", "buy", timeout=0)
        self.assertEqual(self.calls, [])

    def test_screenshot_is_private_and_never_overwrites_evidence(self):
        path = self.phone.screenshot("ready")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.phone.screenshot("ready")

    def test_timeouts_and_action_pairs_are_bounded_before_adb(self):
        for value in (-1, float("inf"), float("nan"), 121, True):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                self.phone.click("Buy forwarding", "buy", timeout=value)
        with self.assertRaises(ValueError):
            self.phone.click("Buy forwarding", "export", timeout=0)
        self.assertEqual(self.calls, [])

    def test_only_exact_candidate_account_files_can_be_read(self):
        for relative in ("buyer/buyer.json", "controller/controller.json", "seller/ledger.json",
                         "exports/fixture_123.json"):
            self.assertEqual(self.phone.account_file(relative), self.account)
        for relative in ("../profile.json", "wallet/secrets.json", "exports/../secret.json",
                         "exports/" + "a" * 33 + ".json", "/etc/passwd"):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                self.phone.account_file(relative)

    def test_staging_is_create_only_stopped_and_does_not_import_or_log_token(self):
        self.button["text"] = "Connect"
        self.phone.stage_funds("cashu-fixture-private")
        self.assertEqual(self.funding, {"token": "cashu-fixture-private"})
        self.assertEqual(self.taps, [])
        self.assertFalse(any("cashu-fixture-private" in arg for command, _ in self.calls for arg in command))
        self.assertFalse(any("cashu-fixture-private" in path.read_text() for path in self.output.rglob("*.json")))
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.phone.stage_funds("cashu-another-fixture")

    def test_running_or_pending_candidate_cannot_stage_funds(self):
        self.status_value["customer"]["running"] = True
        with self.assertRaisesRegex(RuntimeError, "stopped"):
            self.phone.stage_funds("cashu-fixture")
        self.status_value["customer"]["running"] = False
        self.result = None
        with self.assertRaises(TimeoutError):
            self.phone.click("Buy forwarding", "buy", timeout=0)
        with self.assertRaisesRegex(RuntimeError, "unresolved"):
            self.phone.stage_funds("cashu-fixture")
        self.assertIsNone(self.funding)

    def test_lost_staging_reply_blocks_replacement_and_ui_mutation(self):
        self.button["text"] = "Connect"
        self.lose_funding_reply = True
        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            self.phone.stage_funds("cashu-fixture")
        reopened = PhoneCustomer(self.adb, self.serial, self.output)
        with self.assertRaisesRegex(RuntimeError, "staging is uncertain"):
            reopened.stage_funds("cashu-replacement")
        with self.assertRaisesRegex(RuntimeError, "staging is uncertain"):
            reopened.click("Load test funds", "import", timeout=0)
        self.assertEqual(self.funding, {"token": "cashu-fixture"})
        self.assertEqual(self.taps, [])


if __name__ == "__main__":
    unittest.main()
