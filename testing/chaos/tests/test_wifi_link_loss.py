"""Optional link observations use modeled files/tools, never live interfaces."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import wifi_link_loss as link
from sim.wifi_measurements import snapshot
from test_wifi_measurements import frame, node, stat


STATION = ("Station 02:00:00:00:00:02 (on mesh0)\n"
           "\tmesh llid: 1\n\tmesh plid: 2\n\tmesh plink: ESTAB\n"
           "\tauthorized: yes\n\tauthenticated: yes\n\tassociated: yes\n"
           "\ttx packets: 12\n\ttx retries: 3\n"
           "\ttx failed: 1\n\trx packets: 8\n\tconnected time: 20 seconds\n"
           "\tassociated at [boottime]: 10.100s\n"
           "\tassociated at: 2026-01-01 00:00:10\n"
           "\tcurrent time: 2026-01-01 00:00:30\n")


def observation():
    return dict(zip(link.FIELDS, [
        "30.00", "7\n02:00:00:00:00:01",
        "\n".join(f"{name}\tavailable\t{index}" for index, name in enumerate(link.COUNTERS)),
        "available", "0", STATION, "missing", "", "",
        "7\n02:00:00:00:00:01", "30.02",
    ]))


def router(raw=None):
    result = node(raw)
    result.interface = "mesh0"
    result.mesh = {"ifindex": 7, "mac": "02:00:00:00:00:01"}
    return result


class LinkObservationTests(unittest.TestCase):
    def test_snapshot_retains_observations_inside_process_and_host_brackets(self):
        raw = frame(**observation())
        device = router(raw)
        with patch("sim.wifi_measurements.time.monotonic_ns", side_effect=[10, 20]):
            value = snapshot(device, "n02", link_loss=True)
        observed = value["link_loss"]
        self.assertEqual(value["sample_timing"], {"started_monotonic_ns": 10, "finished_monotonic_ns": 20})
        self.assertEqual(observed["timing"], {"clock": "router_uptime_seconds", "started": 30, "finished": 30.02})
        self.assertEqual(observed["stations"]["raw"], STATION)
        peer = observed["stations"]["records"][0]
        self.assertEqual(peer["association"], {
            "associated_at_boottime": "10.100s", "connected_time": "20 seconds",
            "mesh_plink": "ESTAB",
        })
        self.assertEqual(peer["counters"]["tx failed"], 1)
        self.assertIsNone(peer["counters"]["rx drop misc"])
        self.assertEqual(observed["qdisc"], {"availability": "missing", "exit_code": None, "raw": None})
        device.remote.assert_called_once()
        command = device.remote.call_args.args[0]
        self.assertLess(command.index('relay=$(printf'), command.index('link_started='))
        self.assertIn('link_finished=', command)
        self.assertLess(command.index('link_finished='), command.rindex('\nowned'))
        with self.assertRaises(ValueError):
            snapshot(router(frame(after=stat(start=999), **observation())), "n02", link_loss=True)

    def test_link_fields_follow_native_and_log_fields_without_changing_them(self):
        from sim.wifi_measurements import DATAPLANE_DROP_LOG_FILTER
        native = {"status": "ok", "data": {"pid": 123, "npub": "test-node",
                  "exe_path": "/tmp/owned/fips-relay"}}
        transports = {"status": "ok", "data": {"transports": []}}
        raw = frame(native_status=json.dumps(native), native_routing=json.dumps(native),
                    native_transports=json.dumps(transports), log_filter=DATAPLANE_DROP_LOG_FILTER,
                    log_bytes="123", **observation())
        value = snapshot(router(raw), "n02", native_counters=True, drop_logs=True, link_loss=True)
        self.assertEqual(value["native"]["transports"], transports)
        self.assertEqual(value["dataplane_log"]["bytes"], 123)
        self.assertEqual(value["link_loss"]["stations"]["records"][0]["counters"]["tx failed"], 1)

    def test_opt_out_has_no_link_reads_and_rejects_unannounced_extra_fields(self):
        device = router()
        self.assertNotIn("link_loss", snapshot(device, "n02"))
        command = device.remote.call_args.args[0]
        self.assertNotIn("station dump", command)
        self.assertNotIn("qdisc", command)
        with self.assertRaises(ValueError):
            snapshot(router(frame(**observation())), "n02")

    def test_missing_and_failed_observations_never_become_zero(self):
        value = observation()
        value["link_counters"] = "\n".join(f"{name}\tmissing\t" for name in link.COUNTERS)
        value.update(link_stations_status="error", link_stations_rc="1", link_stations="driver unavailable")
        parsed = link.parse(router(), list(value.values()))
        self.assertTrue(all(v == {"availability": "missing", "value": None} for v in parsed["sysfs"].values()))
        self.assertEqual(parsed["stations"]["availability"], "error")
        self.assertIsNone(parsed["stations"]["records"])
        value.update(link_stations_status="missing", link_stations_rc="", link_stations="")
        self.assertIsNone(link.parse(router(), list(value.values()))["stations"]["raw"])

    def test_identity_clock_size_and_malformed_counters_fail(self):
        for mutation in (
            {"link_identity_after": "8\n02:00:00:00:00:01"},
            {"link_identity_before": "8\n02:00:00:00:00:01", "link_identity_after": "8\n02:00:00:00:00:01"},
            {"link_finished": "29.9"}, {"link_started": "nan"},
            {"link_qdisc_status": "available", "link_qdisc_rc": "1"},
            {"link_stations": "x" * (link.MAX_STATION_BYTES + 1)},
            {"link_counters": "tx_packets\tavailable\t-1"},
            {"link_counters": "tx_packets\tmissing\t0"},
            {"link_stations": STATION + STATION},
        ):
            value = {**observation(), **mutation}
            with self.subTest(fields=list(mutation)), self.assertRaises(ValueError):
                link.parse(router(), list(value.values()))


class LinkShellTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.net = self.root / "net" / "mesh0"
        (self.net / "statistics").mkdir(parents=True)
        (self.net / "ifindex").write_text("7\n")
        (self.net / "address").write_text("02:00:00:00:00:01\n")
        for name in link.COUNTERS:
            (self.net / "statistics" / name).write_text("4\n")
        self.proc = self.root / "proc"
        self.proc.mkdir()
        (self.proc / "uptime").write_text("30.00 1.0\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for command in ("cat", "cut", "head"):
            (self.bin / command).symlink_to(shutil.which(command))
        self.tool("iw", f"printf '%s' {shlex.quote(STATION)}")
        self.addCleanup(patch.stopall)
        patch("sim.wifi_link_loss.SYS_NET", str(self.net.parent)).start()

    def tool(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o700)

    def read(self):
        command = link.command(router(), str(self.proc))
        command += "printf '%s\\0' " + " ".join(f'"${field}"' for field in link.FIELDS)
        # Bash models OpenWrt ash's pipefail support; the modeled tools use no network.
        raw = subprocess.check_output(["/bin/bash", "-eu", "-c", command],
                                      env={**os.environ, "PATH": str(self.bin)}, timeout=5)
        fields = raw.decode().split("\0")
        self.assertEqual(fields[-1], "")
        return link.parse(router(), fields[:-1])

    def test_shell_reads_existing_counters_and_only_an_installed_tc(self):
        missing = self.net / "statistics" / "rx_dropped"
        missing.unlink()
        (self.net / "statistics" / "tx_errors").unlink()
        (self.net / "statistics" / "tx_errors").symlink_to(self.root / "missing-target")
        value = self.read()
        self.assertEqual(value["sysfs"]["rx_dropped"], {"availability": "missing", "value": None})
        self.assertEqual(value["sysfs"]["tx_errors"], {"availability": "error", "value": None})
        self.assertEqual(value["qdisc"]["availability"], "missing")
        self.tool("tc", "printf '%s' 'qdisc fq_codel 0: root Sent 200 bytes 2 pkt (dropped 1)' ")
        value = self.read()
        self.assertIn("dropped 1", value["qdisc"]["raw"])
        self.assertEqual(value["stations"]["records"][0]["counters"]["tx retries"], 3)

    def test_shell_errors_and_interface_replacement_are_visible(self):
        self.tool("tc", "printf '%s' 'not supported'; exit 1")
        self.assertEqual(self.read()["qdisc"]["availability"], "error")
        self.tool("iw", f"printf 8 > {shlex.quote(str(self.net / 'ifindex'))}; printf '%s' {shlex.quote(STATION)}")
        with self.assertRaisesRegex(ValueError, "interface changed"):
            self.read()


if __name__ == "__main__":
    unittest.main()
