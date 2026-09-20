"""Bounded raw AQM reads and identity checks using local fixtures only."""

import json
import shlex
import unittest
from unittest.mock import patch

from sim import wifi_link_loss as link
from sim.wifi_measurements import snapshot
import test_wifi_link_loss as fixtures
from test_wifi_measurements import frame, stat


PEER = "02:00:00:00:00:02"
AQM = ("tid ac backlog-bytes backlog-packets new-flows drops marks overlimit "
       "collisions tx-bytes tx-packets flags\n0 2 0 0 0 7 0 0 0 2000 2 0x0(RUN)\n")


def observation():
    return {**fixtures.observation(), **dict(zip(link.AQM_FIELDS, [
        "30.00", "phy7", "available", "0", AQM, "phy7",
        "available", "0", fixtures.STATION, "30.01",
    ]))}


class AqmTests(unittest.TestCase):
    def test_capture_stays_in_process_interface_and_station_brackets(self):
        device = fixtures.router(frame(**observation()))
        result = snapshot(device, "n02", link_loss=True, aqm_peer=PEER)
        aqm = result["link_loss"]["aqm"]
        self.assertEqual(aqm["raw"], AQM)
        self.assertEqual(aqm["availability"], "available")
        self.assertFalse(aqm["truncated"])
        self.assertEqual(aqm["association"]["status"], "stable")
        self.assertEqual(aqm["peer"], PEER)
        self.assertEqual(aqm["phy"], "phy7")
        self.assertEqual(aqm["station_after"]["raw"], fixtures.STATION)
        device.remote.assert_called_once()
        command = device.remote.call_args.args[0]
        self.assertLess(command.index("link_stations="), command.index("link_aqm_started="))
        self.assertLess(command.index("link_aqm_path="), command.index("link_aqm_station="))
        self.assertLess(command.index("link_aqm_finished="), command.index("link_identity_after="))
        self.assertLess(command.index("link_identity_after="), command.rindex("\nowned"))
        for changes in ({"after": stat(start=999)}, {"link_identity_after": "8\n02:00:00:00:00:01"},
                        {"link_aqm_phy_after": "phy8"}, {"link_aqm_finished": "31"},
                        {"link_aqm_started": "nan"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                snapshot(fixtures.router(frame(**{**observation(), **changes})), "n02", link_loss=True, aqm_peer=PEER)

    def test_missing_failed_and_truncated_reads_remain_explicit(self):
        for status, code, raw in (("missing", "", ""), ("error", "1", "unavailable"),
                                  ("available", "0", "x" * link.MAX_AQM_BYTES + "\n")):
            value = {**observation(), "link_aqm_status": status, "link_aqm_rc": code, "link_aqm": raw}
            aqm = link.parse(fixtures.router(), list(value.values()), PEER)["aqm"]
            self.assertEqual(aqm["truncated"], len(raw) > link.MAX_AQM_BYTES)
            self.assertEqual(aqm["availability"], "truncated" if aqm["truncated"] else status)
            self.assertLessEqual(len((aqm["raw"] or "").encode()), link.MAX_AQM_BYTES)
            if status == "missing":
                self.assertIsNone(aqm["raw"])
                self.assertIsNone(aqm["exit_code"])

    def test_station_changes_and_unknown_epochs_are_not_stable(self):
        for old, new, expected in (("10.100s", "11.100s", "changed"),
                                   ("20 seconds", "19 seconds", "changed"),
                                   ("mesh plink: ESTAB", "mesh plink: HOLDING", "not_established"),
                                   ("associated at [boottime]: 10.100s", "other: unknown", "unknown")):
            value = observation()
            value["link_aqm_station"] = fixtures.STATION.replace(old, new)
            self.assertEqual(link.parse(fixtures.router(), list(value.values()), PEER)["aqm"]["association"]["status"], expected)
        value.update(link_aqm_station_status="error", link_aqm_station_rc="1", link_aqm_station="gone")
        self.assertEqual(link.parse(fixtures.router(), list(value.values()), PEER)["aqm"]["association"]["status"], "unknown")

    def test_optional_framing_preserves_native_and_log_fields(self):
        from sim.wifi_measurements import DATAPLANE_DROP_LOG_FILTER
        native = {"status": "ok", "data": {"pid": 123, "npub": "test-node", "exe_path": "/tmp/owned/fips-relay"}}
        transports = {"status": "ok", "data": {"transports": []}}
        raw = frame(native_status=json.dumps(native), native_routing=json.dumps(native),
                    native_transports=json.dumps(transports), log_filter=DATAPLANE_DROP_LOG_FILTER,
                    log_bytes="20", **observation())
        result = snapshot(fixtures.router(raw), "n02", True, True, True, aqm_peer=PEER)
        self.assertEqual(result["native"]["transports"], transports)
        self.assertEqual(result["dataplane_log"]["bytes"], 20)
        ordinary = fixtures.router(frame(**fixtures.observation()))
        self.assertNotIn("aqm", snapshot(ordinary, "n02", link_loss=True)["link_loss"])
        self.assertNotIn("link_aqm", ordinary.remote.call_args.args[0])
        for role, enabled, peer in (("n01", True, PEER), ("n02", False, PEER),
                                     ("n02", True, "../../bad")):
            device = fixtures.router()
            with self.assertRaises(ValueError):
                snapshot(device, role, link_loss=enabled, aqm_peer=peer)
            device.remote.assert_not_called()
        with self.assertRaises(ValueError):
            snapshot(fixtures.router(frame(**observation())), "n02", link_loss=True)


class AqmShellTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.LinkShellTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        (self.fixture.net / "phy80211").mkdir()
        (self.fixture.net / "phy80211" / "name").write_text("phy7\n")
        debug = self.fixture.root / "debug"
        self.aqm = debug / "phy7" / "netdev:mesh0" / "stations" / PEER / "aqm"
        self.aqm.parent.mkdir(parents=True)
        self.aqm.write_text(AQM)
        patch("sim.wifi_link_loss.DEBUGFS", str(debug)).start()

    def test_shell_keeps_exact_raw_and_detects_truncation_even_at_newline(self):
        self.assertEqual(self.fixture.read(PEER)["aqm"]["raw"], AQM)
        self.aqm.write_text("x" * link.MAX_AQM_BYTES + "\nmore")
        aqm = self.fixture.read(PEER)["aqm"]
        self.assertEqual(aqm["availability"], "truncated")
        self.assertTrue(aqm["truncated"])
        self.assertEqual(aqm["raw"], "x" * link.MAX_AQM_BYTES)

    def test_shell_missing_failed_and_reassociated_station_are_explicit(self):
        self.aqm.unlink()
        self.assertEqual(self.fixture.read(PEER)["aqm"]["availability"], "missing")
        self.aqm.symlink_to(self.fixture.root / "missing-aqm")
        self.assertEqual(self.fixture.read(PEER)["aqm"]["availability"], "error")
        changed = fixtures.STATION.replace("10.100s", "11.100s")
        self.fixture.tool("iw", f"if test \"$4\" = get; then printf '%s' {shlex.quote(changed)}; "
                               f"else printf '%s' {shlex.quote(fixtures.STATION)}; fi")
        self.assertEqual(self.fixture.read(PEER)["aqm"]["association"]["status"], "changed")


if __name__ == "__main__":
    unittest.main()
