"""Native diagnostics preserve process epochs, real counter resets and losses."""
import copy
import unittest

from analyze import analyze_rows, diagnose_rows
from native_counters import GROUPS
from test_analyze import workload
from test_hardware import hardware_report, nodes


def native_report():
    rows = hardware_report()
    rows[0]["native_counters"] = True
    for node in nodes(rows):
        tick = node["measurements"]["process_cpu_ns"] // 100000
        counters = {group: dict.fromkeys(fields, tick) for group, fields in GROUPS.items()}
        node["native"] = {
            "status": {"status": "ok", "data": {
                "npub": node["npub"], "pid": node["host_process"]["pid"],
                "exe_path": "/synthetic/relay", "forwarding": counters["forwarding"].copy(),
            }},
            "routing": {"status": "ok", "data": counters},
        }
    return rows


class NativeTests(unittest.TestCase):
    def reject(self, change):
        rows = native_report()
        change(rows)
        for analyzer in (analyze_rows, diagnose_rows):
            with self.assertRaises((ValueError, KeyError, TypeError)):
                analyzer(rows)

    def test_counter_deltas_and_guard_gaps_preserve_raw_evidence(self):
        rows = native_report()
        original = copy.deepcopy(rows)
        _, trials, _ = analyze_rows(rows)
        steady = next(r for r in trials if r["workload"] == "steady")
        expected = {group: dict.fromkeys(fields, 1) for group, fields in GROUPS.items()}
        self.assertEqual(steady["nodes"]["n02"]["native_counters"], expected)
        self.assertEqual(set(steady["native_gap_counters"]), {
            "previous_after_guard_to_before_guard", "before_guard_to_before", "after_to_after_guard",
        })
        self.assertEqual(rows, original)

    def test_identity_groups_and_success_are_required(self):
        for field, value in (("npub", "wrong"), ("pid", 999), ("pid", True),
                             ("exe_path", "/changed/relay")):
            with self.subTest(field=field):
                self.reject(lambda rows: workload(rows)["after"][0]["native"]["status"]["data"]
                            .__setitem__(field, value))
        self.reject(lambda rows: workload(rows)["before"][1]["native"]["routing"]
                    .__setitem__("status", "error"))
        self.reject(lambda rows: workload(rows)["after"][0]["native"]["routing"]["data"].pop("congestion"))
        for value in (None, -1, True, "0"):
            with self.subTest(value=value):
                self.reject(lambda rows: workload(rows)["after"][0]["native"]["routing"]["data"]
                            ["forwarding"].__setitem__("drop_policy_denied_packets", value))

    def test_counters_cannot_reset_at_any_boundary_or_between_native_queries(self):
        for boundary in ("before_guard", "before", "after", "after_guard"):
            with self.subTest(boundary=boundary):
                self.reject(lambda rows: workload(rows)[boundary][0]["native"]["routing"]["data"]
                            ["forwarding"].__setitem__("drop_send_error_packets", 0))
        self.reject(lambda rows: workload(rows)["before"][0]["native"]["status"]["data"]
                    ["forwarding"].__setitem__("received_packets", 999))
        self.reject(lambda rows: workload(rows, "bursty")["before_guard"][0]["native"]["routing"]
                    ["data"]["congestion"].__setitem__("kernel_drop_events", 0))

    def test_presence_matches_explicit_metadata(self):
        for value in (False, None, 1, "true"):
            with self.subTest(value=value):
                self.reject(lambda rows: rows[0].__setitem__("native_counters", value))
        self.reject(lambda rows: workload(rows)["after_guard"][2].pop("native"))

    def test_nondefault_pilot_retains_delivery_rejection(self):
        rows = native_report()[:6]
        rows[0].update(pilot=True, pilot_delay_ms=2000)
        for row in rows[1:]:
            row["max_delay_ms"] = 2000
        _, trials, _ = analyze_rows(rows, pilot=True)
        self.assertEqual({r["max_delay_ms"] for r in trials}, {2000})
        receiver = workload(rows, "high_rate")["probes"][0]["receiver"]
        receiver.update(unique_packets=7998, unique_bytes=7998000, missing_packets=2)
        with self.assertRaises(ValueError):
            analyze_rows(rows, pilot=True)
        self.assertIs(diagnose_rows(rows, pilot=True)["accepted"], False)
        for delay in (None, True, 10, "2000"):
            rows[0]["pilot_delay_ms"] = delay
            with self.subTest(delay=delay), self.assertRaises(ValueError):
                diagnose_rows(rows, pilot=True)
        self.reject(lambda rows: rows[0].__setitem__("pilot_delay_ms", 2000))


if __name__ == "__main__":
    unittest.main()
