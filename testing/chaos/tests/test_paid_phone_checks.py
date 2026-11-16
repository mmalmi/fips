"""Reject unknown probe outcomes and unverified account/application evidence."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.phone_customer import PACKAGE
from sim.paid_phone_checks import (check_customer_access, guest_source, installed_apk_hash,
                                   original_hashes, probe_result, scenario)
from sim.paid_phone_transit import PhoneTransitRun


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
                 completed(nc_code=1, error=b"nc: -q < 1 (see nc --help)"),
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
            self.assertIn("-q 1", call.args[0][-1])
            self.assertEqual(call.kwargs["timeout"], 8)

    def test_probe_connects_without_scan_option_payload_or_banner_confusion(self):
        phone = Mock(adb_path=Path("/fixture/adb"), serial="authorized-fixture")
        phone.shell.return_value = b'SSID: "Fixture Guest", IP: /192.0.2.2'
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            toybox = root / 'toybox'
            toybox.write_text('''#!/bin/sh
for arg do
    test "$arg" != -z || { echo 'nc: Unknown option z' >&2; exit 1; }
    port=$arg
done
test -z "$(cat)" || { echo 'unexpected probe payload' >&2; exit 42; }
test "$port" != 80 || { echo 'nc: Connection refused' >&2; exit 1; }
echo 'server banner'
''')
            toybox.chmod(0o700)
            def shell(args, **kwargs):
                self.assertEqual(args[:4], ['/fixture/adb', '-s', 'authorized-fixture', 'shell'])
                return real_run(['sh', '-c', args[4]], input=b'must not reach the service',
                                env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH']},
                                **kwargs)
            with patch('sim.paid_phone_checks.subprocess.run', side_effect=shell):
                checks = check_customer_access(phone, profile()['customer'],
                                               'http://198.51.100.10:41234', root)
            self.assertEqual([item['connected'] for item in checks], [True, False, True])

    def test_transit_mint_probe_requires_confirmed_connection(self):
        run = object.__new__(PhoneTransitRun)
        run.phone = Mock(adb_path=Path('/fixture/adb'), serial='authorized-fixture')
        run.phone.shell.return_value = b'SSID: "Fixture Guest", IP: /192.0.2.2'
        run.customer, run.mint_url = profile()['customer'], 'http://198.51.100.10:41234'
        run.phase = Mock()
        with tempfile.TemporaryDirectory() as directory:
            run.root = Path(directory)
            with patch('sim.paid_phone_checks.subprocess.run') as command:
                for index, result in enumerate((completed(nc_code=1, error=b'nc: connect: Connection refused'),
                                                completed(nc_code=1, error=b'nc: Unknown option z'))):
                    run.root = Path(directory) / str(index)
                    run.root.mkdir()
                    command.return_value = result
                    with self.assertRaises(RuntimeError):
                        run.check_customer_access()
                    run.phase.assert_not_called()
                command.return_value = completed()
                run.root = Path(directory) / 'connected'
                run.root.mkdir()
                run.check_customer_access()
                run.phase.assert_called_once()
            self.assertEqual(json.loads((run.root / 'network-shared_mint.json').read_text())['adb_exit'], 0)

    def test_unknown_middle_probe_aborts_before_it_can_be_accepted(self):
        phone = Mock(adb_path=Path("/fixture/adb"), serial="authorized-fixture")
        phone.shell.return_value = b'SSID: "Fixture Guest", IP: /192.0.2.2'
        with tempfile.TemporaryDirectory() as root, patch("sim.paid_phone_checks.subprocess.run") as run:
            run.side_effect = [completed(), completed(adb_code=1, error=b"device offline")]
            with self.assertRaisesRegex(RuntimeError, "uncertain"):
                check_customer_access(phone, profile()["customer"], "http://198.51.100.10:41234", Path(root))
            self.assertEqual(run.call_count, 2)

    def test_guest_selection_is_observed_never_changed(self):
        phone = Mock(package=PACKAGE)
        for status in (b'SSID: "Other", IP: /192.0.2.2', b'SSID: "Fixture Guest", IP: /198.51.100.2',
                       b'SSID: "Fixture Guest", IP: /192.0.2.1'):
            phone.shell.return_value = status
            with self.assertRaises(RuntimeError):
                guest_source(phone, profile()["customer"])
        self.assertTrue(all(call.args == ("cmd", "wifi", "status") for call in phone.shell.call_args_list))

    def test_original_hashes_are_nonempty_complete_lines_and_canonically_sorted(self):
        phone = Mock(package=PACKAGE)
        first, second = b"a" * 64 + b"  files/first", b"b" * 64 + b"  files/second"
        inventory = b"package:org.fips.relaybench\npackage:org.fips.relaybench.acceptance\n"
        phone.shell.side_effect = [inventory, second + b"\r\n" + first + b"\r\n"]
        self.assertEqual(original_hashes(phone), b"org.fips.relaybench\n" + first + b"\n" + second + b"\n")
        for invalid in (b"", b"find: permission denied", first + b"\n" + first):
            phone.shell.side_effect = [inventory, invalid]
            with self.assertRaises(RuntimeError):
                original_hashes(phone)

    def test_named_run_verifies_all_existing_accounts(self):
        phone = Mock(package=PACKAGE + ".trial2")
        first, second = b"a" * 64 + b"  files/account", b"b" * 64 + b"  files/account"
        inventory = ("package:org.fips.relaybench\npackage:" + PACKAGE + "\npackage:" + PACKAGE + ".trial1\npackage:" + phone.package + "\n").encode()
        phone.shell.side_effect = [inventory, first, second, first]
        self.assertEqual(original_hashes(phone),
                         b"org.fips.relaybench\n" + first + b"\n" +
                         PACKAGE.encode() + b"\n" + second + b"\n" +
                         (PACKAGE + ".trial1").encode() + b"\n" + first + b"\n")
        self.assertEqual([call.args[1] for call in phone.shell.call_args_list[1:]],
                         ["org.fips.relaybench", PACKAGE, PACKAGE + ".trial1"])

    def test_explicit_empty_original_inventory_accepts_only_the_candidate(self):
        phone = Mock(package=PACKAGE + ".fresh", original_packages=[])
        for inventory in (b"", ("package:" + phone.package + "\n").encode()):
            phone.shell.return_value = inventory
            self.assertEqual(original_hashes(phone), b"")
        for package in ("org.fips.relaybench", PACKAGE + ".other", "org.fips.relaybench.unexpected"):
            phone.shell.return_value = ("package:" + package + "\n").encode()
            with self.subTest(package=package), self.assertRaises(RuntimeError):
                original_hashes(phone)
        phone.original_packages = None
        phone.shell.return_value = b""
        with self.assertRaisesRegex(RuntimeError, "original bench account"):
            original_hashes(phone)

    def test_only_the_exact_single_verified_apk_is_accepted(self):
        phone = Mock(package=PACKAGE)
        path = "/data/app/fixture/base.apk"
        phone.shell.side_effect = [("package:" + path + "\n").encode(), ("a" * 64 + "  " + path).encode()]
        self.assertEqual(installed_apk_hash(phone, "a" * 64), "a" * 64)
        phone.shell.side_effect = [("package:" + path + "\n").encode(), ("b" * 64 + "  " + path).encode()]
        with self.assertRaises(RuntimeError):
            installed_apk_hash(phone, "a" * 64)

    def test_transit_scenario_is_explicit_and_cannot_claim_customer_isolation(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'scenario.json'
            value = profile()
            value['customer'].pop('denied_tcp')
            value['router_addresses'] = dict(n01='192.0.2.1', n02='192.0.2.3', n03='192.0.2.4')
            path.write_text(json.dumps(value))
            self.assertEqual(scenario(path, transit=True), value)
            with self.assertRaises(RuntimeError):
                scenario(path)
            value['router_addresses']['n02'] = '198.51.100.2'
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                scenario(path, transit=True)

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
