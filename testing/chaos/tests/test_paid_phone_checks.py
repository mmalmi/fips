"""Reject unknown probe outcomes and unverified account/application evidence."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_phone_checks import (check_customer_access, guest_source, installed_apk_hash,
                                   original_hashes, probe_result, scenario)


def profile():
    return {"version": 1, "phone": {"adb": "/fixture/adb", "serial": "authorized-fixture",
            "evidence_dir": "/fixture/evidence", "apk_sha256": "a" * 64},
            "customer": {"interface": "guest0", "cidr": "192.0.2.1/24", "entry_port": 41235,
            "ssid": "Fixture Guest", "denied_tcp": [{"label": "other_service",
            "address": "198.51.100.20", "port": 80}]},
            "mint": {"ssh_spec": {"host": "fixture-mint", "state_parent": "/fixture/mint"},
                     "address": "198.51.100.10"}}


def completed(adb_code=0, nc_code=0, error=b""):
    return subprocess.CompletedProcess([], adb_code,
                                       stdout=f"FIPS_PROBE_EXIT={nc_code}\n".encode(), stderr=error)


class PaidPhoneCheckTests(unittest.TestCase):
    def test_connection_and_explicit_network_denial(self):
        self.assertTrue(probe_result(completed()))
        for reason in (b"Connection refused", b"Connection timed out", b"Network is unreachable", b"No route to host"):
            self.assertFalse(probe_result(completed(nc_code=1, error=b"nc: " + reason)))

    def test_adb_missing_marker_bad_tool_and_bind_errors_are_not_denial(self):
        cases = [completed(adb_code=1, nc_code=1, error=b"device offline"),
                 completed(nc_code=127, error=b"nc: not found"),
                 completed(nc_code=1, error=b"nc: bind: Cannot assign requested address"),
                 completed(nc_code=1), completed()]
        cases[-1].stdout = b""
        for result in cases:
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                probe_result(result)

    def test_allowed_probes_bracket_only_explicit_denied_endpoints_on_exact_device(self):
        phone = Mock(adb_path=Path("/fixture/adb"), serial="authorized-fixture")
        phone.shell.return_value = b'SSID: "Fixture Guest", IP: /192.0.2.2'
        with tempfile.TemporaryDirectory() as root, patch("sim.paid_phone_checks.subprocess.run") as run:
            run.side_effect = [completed(), completed(nc_code=1, error=b"nc: Connection refused"), completed()]
            checks = check_customer_access(phone, profile()["customer"], "http://198.51.100.10:41234", Path(root))
        self.assertEqual([item["connected"] for item in checks], [True, False, True])
        for call in run.call_args_list:
            self.assertEqual(call.args[0][:3], ["/fixture/adb", "-s", "authorized-fixture"])
            self.assertIn("-s 192.0.2.2", call.args[0][-1])
            self.assertEqual(call.kwargs["timeout"], 8)

    def test_unknown_middle_probe_aborts_before_it_can_be_accepted(self):
        phone = Mock(adb_path=Path("/fixture/adb"), serial="authorized-fixture")
        phone.shell.return_value = b'SSID: "Fixture Guest", IP: /192.0.2.2'
        with tempfile.TemporaryDirectory() as root, patch("sim.paid_phone_checks.subprocess.run") as run:
            run.side_effect = [completed(), completed(adb_code=1, error=b"device offline")]
            with self.assertRaisesRegex(RuntimeError, "uncertain"):
                check_customer_access(phone, profile()["customer"], "http://198.51.100.10:41234", Path(root))
            self.assertEqual(run.call_count, 2)

    def test_guest_selection_is_observed_never_changed(self):
        phone = Mock()
        for status in (b'SSID: "Other", IP: /192.0.2.2', b'SSID: "Fixture Guest", IP: /198.51.100.2',
                       b'SSID: "Fixture Guest", IP: /192.0.2.1'):
            phone.shell.return_value = status
            with self.assertRaises(RuntimeError):
                guest_source(phone, profile()["customer"])
        self.assertTrue(all(call.args == ("cmd", "wifi", "status") for call in phone.shell.call_args_list))

    def test_original_hashes_are_nonempty_complete_lines_and_canonically_sorted(self):
        phone = Mock()
        first, second = b"a" * 64 + b"  files/first", b"b" * 64 + b"  files/second"
        phone.shell.return_value = second + b"\r\n" + first + b"\r\n"
        self.assertEqual(original_hashes(phone), first + b"\n" + second + b"\n")
        for invalid in (b"", b"find: permission denied", first + b"\n" + first):
            phone.shell.return_value = invalid
            with self.assertRaises(RuntimeError):
                original_hashes(phone)

    def test_only_the_exact_single_verified_apk_is_accepted(self):
        phone = Mock()
        path = "/data/app/fixture/base.apk"
        phone.shell.side_effect = [("package:" + path + "\n").encode(), ("a" * 64 + "  " + path).encode()]
        self.assertEqual(installed_apk_hash(phone, "a" * 64), "a" * 64)
        phone.shell.side_effect = [("package:" + path + "\n").encode(), ("b" * 64 + "  " + path).encode()]
        with self.assertRaises(RuntimeError):
            installed_apk_hash(phone, "a" * 64)

    def test_scenario_preserves_explicit_inputs_and_rejects_unbounded_or_ambiguous_targets(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "scenario.json"
            value = profile()
            path.write_text(json.dumps(value))
            self.assertEqual(scenario(path), value)
            for field, bad in (("entry_port", True), ("denied_tcp", []),
                               ("denied_tcp", value["customer"]["denied_tcp"] * 2),
                               ("ssid", "")):
                changed = profile()
                changed["customer"][field] = bad
                path.write_text(json.dumps(changed))
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    scenario(path)


if __name__ == "__main__":
    unittest.main()
