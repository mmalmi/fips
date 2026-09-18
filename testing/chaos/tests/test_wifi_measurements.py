"""Process identity and counter failures without SSH, devices or live accounts."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.wifi_measurements import COUNTERS, IO_COUNTERS, OPERATIONS, process_identity, snapshot


def stat(pid=123, start=456, name="fips relay (worker)"):
    fields = ["S", *(["0"] * 18), str(start), "0", "0"]
    return f"{pid} ({name}) " + " ".join(fields)


def status():
    return {"npub": "test-node", "purchases": [], "last_error": None,
            "measurements": {"version": 1, "process_id": 123, "process_cpu_ns": 123456,
                             "operations": {name: dict.fromkeys(COUNTERS, 0) for name in OPERATIONS}}}


def frame(**changes):
    values = {"pid": "123", "before": stat(), "after": stat(),
              "memory": "Name:\tfips-relay\nVmRSS:\t100 kB\nVmHWM:\t120 kB\n",
              "io": "\n".join(f"{name}: {index}" for index, name in enumerate(IO_COUNTERS)),
              "relay": json.dumps(status())}
    values.update(changes)
    return ("\0".join(values.values()) + "\0").encode()


def node(raw=None):
    return SimpleNamespace(temporary="/tmp/owned", binary="/tmp/owned/fips-relay",
                           config="/etc/owned/config.json", npub="test-node",
                           remote=Mock(return_value=frame() if raw is None else raw))


class MeasurementTests(unittest.TestCase):
    def test_stat_parser_preserves_spaces_and_parentheses_in_comm(self):
        for name in ("fips relay", "fips (worker)", "fips ) (worker) name"):
            self.assertEqual(process_identity(stat(name=name)), (123, 456))
        for bad in ("123 (relay) S 0", stat(start=0), stat(pid=0), stat(start=-1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                process_identity(bad)

    def test_single_read_preserves_status_and_adds_exact_host_fields(self):
        router = node()
        with patch("sim.wifi_measurements.time.monotonic_ns", side_effect=[10, 20]):
            value = snapshot(router, "n02")
        for key, original in status().items():
            self.assertEqual(value[key], original)
        self.assertEqual(value["host_process"], {"host": "n02", "pid": 123, "start_ticks": 456,
                         "rss_kib": 100, "peak_rss_kib": 120,
                         **{name: index for index, name in enumerate(IO_COUNTERS)}})
        self.assertEqual(value["sample_timing"], {"started_monotonic_ns": 10, "finished_monotonic_ns": 20})
        router.remote.assert_called_once()
        self.assertEqual(router.remote.call_args.kwargs, {"timeout": 45})

    def test_reused_or_different_pid_is_rejected(self):
        for changed in ({"after": stat(start=457)}, {"after": stat(pid=124)}, {"pid": "124"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                snapshot(node(frame(**changed)), "n01")

    def test_missing_duplicate_negative_or_wrong_unit_resources_fail(self):
        for name in IO_COUNTERS:
            io = "\n".join(f"{field}: 0" for field in IO_COUNTERS if field != name)
            with self.subTest(missing=name), self.assertRaises(ValueError):
                snapshot(node(frame(io=io)), "n01")
        for changed in ({"io": frame().decode().split("\0")[4] + "\nread_bytes: 0"},
                        {"io": "\n".join(f"{name}: -1" for name in IO_COUNTERS)},
                        {"memory": "VmRSS: 100 bytes\nVmHWM: 120 kB"},
                        {"memory": "VmRSS: 121 kB\nVmHWM: 120 kB"},
                        {"memory": "VmRSS: 100 kB"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                snapshot(node(frame(**changed)), "n01")

    def test_missing_disabled_or_invalid_measurements_fail(self):
        base = status()["measurements"]
        invalid = [None, {}, {**base, "version": 2}, {**base, "version": True},
                   {**base, "process_id": 124}, {**base, "process_id": True},
                   {**base, "process_cpu_ns": None}, {**base, "process_cpu_ns": -1},
                   {**base, "operations": {}}]
        for kind in (None, -1, True, "0"):
            changed = copy.deepcopy(base)
            changed["operations"]["payment_sign"]["journal_writes"] = kind
            invalid.append(changed)
        missing = copy.deepcopy(base)
        del missing["operations"]["payment_sign"]["journal_writes"]
        invalid.append(missing)
        for measurements in invalid:
            with self.subTest(measurements=measurements), self.assertRaises(ValueError):
                snapshot(node(frame(relay=json.dumps({**status(), "measurements": measurements}))), "n01")

    def test_wrong_node_bad_framing_and_invalid_host_fail(self):
        for raw in (frame(relay=json.dumps({**status(), "npub": "other"})), frame()[:-1], b"{}"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                snapshot(node(raw), "n01")
        router = node()
        with self.assertRaises(ValueError):
            snapshot(router, "private-host")
        router.remote.assert_not_called()


class ShellSamplerTests(unittest.TestCase):
    """Execute the generated POSIX shell against a private modeled proc tree."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.proc = self.root / "proc"
        self.record = self.proc / "123"
        self.record.mkdir(parents=True)
        self.router = node()
        self.router.temporary = str(self.root)
        self.router.binary = str(self.root / "fips-relay")
        self.router.config = str(self.root / "config.json")
        (self.root / "process.pid").write_text("123\n")
        (self.root / "response.json").write_text(json.dumps(status()))
        (self.record / "exe").symlink_to(self.router.binary)
        (self.record / "cmdline").write_bytes(
            "\0".join([self.router.binary, "run", self.router.config, ""]).encode())
        self.write_stat()
        (self.record / "status").write_text("VmRSS: 100 kB\nVmHWM: 120 kB\n")
        (self.record / "io").write_text("\n".join(f"{name}: 0" for name in IO_COUNTERS))
        self.write_binary()
        self.router.remote = Mock(side_effect=self.local)
        self.addCleanup(patch.stopall)
        patch("sim.wifi_measurements.PROC", str(self.proc)).start()

    def write_stat(self, start=456):
        (self.record / "stat").write_text(stat(start=start))

    def write_binary(self, action=""):
        path = Path(self.router.binary)
        path.write_text(f"#!/bin/sh\nset -eu\ntest \"$1\" = ctl\ntest \"$2\" = '{self.router.config}'\n"
                        "test \"$(cat)\" = '{\"type\":\"status\"}'\n"
                        f"{action}\ncat '{self.root}/response.json'\n")
        path.chmod(0o700)

    def local(self, command, timeout):
        return subprocess.check_output(["sh", "-c", command], timeout=timeout, stderr=subprocess.PIPE)

    def test_shell_uses_one_status_call_and_returns_validated_sample(self):
        self.write_binary(f"echo called >> '{self.root}/calls'")
        value = snapshot(self.router, "n01")
        self.assertEqual(value["host_process"]["start_ticks"], 456)
        self.assertEqual((self.root / "calls").read_text(), "called\n")

    def test_wrong_executable_or_additional_argument_fails_before_status(self):
        self.write_binary(f"touch '{self.root}/called'")
        arguments = (self.record / "cmdline").read_bytes()
        for field, content in (("exe", "/bin/sh"), ("cmdline", b"unexpected\0"),
                               ("cmdline", arguments + b"extra\0"), ("cmdline", arguments + b"\0")):
            path = self.record / field
            original = os.readlink(path) if path.is_symlink() else path.read_bytes()
            path.unlink()
            path.symlink_to(content) if field == "exe" else path.write_bytes(content)
            with self.subTest(field=field), self.assertRaises(subprocess.CalledProcessError):
                snapshot(self.router, "n01")
            self.assertFalse((self.root / "called").exists())
            path.unlink()
            path.symlink_to(original) if field == "exe" else path.write_bytes(original)

    def test_process_restart_during_control_is_rejected(self):
        self.write_binary(f"printf '%s' '{stat(start=999)}' > '{self.record}/stat'")
        with self.assertRaises(ValueError):
            snapshot(self.router, "n01")

    def test_changed_cmdline_or_pid_file_after_control_is_rejected(self):
        for action in (f"printf other > '{self.record}/cmdline'",
                       f"printf 124 > '{self.root}/process.pid'"):
            self.write_binary(action)
            with self.subTest(action=action), self.assertRaises(subprocess.CalledProcessError) as error:
                snapshot(self.router, "n01")
            self.assertEqual(error.exception.output, b"")
            (self.root / "process.pid").write_text("123\n")
            (self.record / "cmdline").write_bytes(
                "\0".join([self.router.binary, "run", self.router.config, ""]).encode())


if __name__ == "__main__":
    unittest.main()
