"""Native diagnostics preserve process epochs, real counter resets and losses."""
import copy
import unittest

from analyze import analyze_rows, diagnose_rows
from native_counters import GROUPS
from test_analyze import workload
from test_hardware import hardware_report, nodes


def native_report(background=False, transports=False):
    rows = hardware_report()
    rows[0]["native_counters"] = True
    for node in nodes(rows):
        tick = node["measurements"]["process_cpu_ns"] // 100000
        counters = {group: dict.fromkeys(fields, tick) for group, fields in GROUPS.items()}
        if background:
            counters["forwarding"].update(drop_background_full_packets=tick,
                                           drop_background_full_bytes=tick * 1000)
        node["native"] = {
            "status": {"status": "ok", "data": {
                "npub": node["npub"], "pid": node["host_process"]["pid"],
                "exe_path": "/synthetic/relay", "forwarding": counters["forwarding"].copy(),
            }},
            "routing": {"status": "ok", "data": counters},
        }
        if transports:
            node["native"]["transports"] = {"status": "ok", "data": {"transports": [{
                "transport_id": 1, "type": "ethernet", "name": "mesh-test", "mtu": 1497,
                "stats": {"kernel_drops": tick, "recv_buffer_bytes": 4194304},
            }]}}
    return rows


class NativeTests(unittest.TestCase):
    def test_transport_reply_is_preserved_and_legacy_evidence_still_works(self):
        for enabled in (False, True):
            rows = native_report(transports=enabled)
            original = copy.deepcopy(rows)
            analyze_rows(rows)
            self.assertEqual(rows, original)
        for node in nodes(rows):
            node["native"]["transports"]["data"]["transports"][0]["stats"].update(
                kernel_drops=None, recv_buffer_bytes=None)
        analyze_rows(rows)
        receiver = workload(rows, "bursty")["probes"][0]["receiver"]
        receiver.update(unique_packets=63, unique_bytes=63000, missing_packets=1)
        with self.assertRaises(ValueError):
            analyze_rows(rows)
        self.assertFalse(diagnose_rows(rows)["accepted"])

    def test_transport_layout_and_kernel_counter_resets_are_rejected(self):
        for mutation in ("missing_reply", "failed_reply", "missing_list", "duplicate", "changed_id",
                         "changed_type", "missing_counter", "negative", "bool", "zero_buffer", "reset"):
            rows = native_report(transports=True)
            native = workload(rows)["after"][0]["native"]
            reply = native["transports"]
            adapters = reply["data"]["transports"]
            stats = adapters[0]["stats"]
            if mutation == "missing_reply":
                native.pop("transports")
            elif mutation == "failed_reply":
                reply["status"] = "error"
            elif mutation == "missing_list":
                reply["data"].pop("transports")
            elif mutation == "duplicate":
                adapters.append(copy.deepcopy(adapters[0]))
            elif mutation == "changed_id":
                adapters[0]["transport_id"] = 2
            elif mutation == "changed_type":
                adapters[0]["type"] = "udp"
            elif mutation == "missing_counter":
                stats.pop("kernel_drops")
            elif mutation == "zero_buffer":
                stats["recv_buffer_bytes"] = 0
            else:
                stats["kernel_drops"] = {"negative": -1, "bool": True, "reset": 0}[mutation]
            for analyzer in (analyze_rows, diagnose_rows):
                with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError, TypeError)):
                    analyzer(rows)

    def test_background_queue_drops_are_preserved_as_observed_counters(self):
        rows = native_report(background=True)
        original = copy.deepcopy(rows)
        _, trials, _ = analyze_rows(rows)
        steady = next(r for r in trials if r["workload"] == "steady")
        counters = steady["nodes"]["n02"]["native_counters"]["forwarding"]
        self.assertEqual(counters["drop_background_full_packets"], 1)
        self.assertEqual(counters["drop_background_full_bytes"], 1000)
        self.assertEqual(rows, original)

    def test_background_schema_cannot_change_or_reset_between_observations(self):
        for location in ("status", "routing"):
            for boundary in ("before_guard", "before", "after", "after_guard"):
                for mutation in ("partial", "legacy", "unknown", "reset", "invalid"):
                    rows = native_report(background=True)
                    counters = workload(rows)[boundary][0]["native"][location]["data"]["forwarding"]
                    if mutation == "partial":
                        counters.pop("drop_background_full_bytes")
                    elif mutation == "legacy":
                        counters.pop("drop_background_full_bytes")
                        counters.pop("drop_background_full_packets")
                    elif mutation == "unknown":
                        counters["unrecognized_packets"] = 0
                    else:
                        counters["drop_background_full_packets"] = (
                            (999 if location == "status" else 0) if mutation == "reset" else True)
                    for analyzer in (analyze_rows, diagnose_rows):
                        with self.subTest(location=location, boundary=boundary, mutation=mutation), \
                                self.assertRaises((ValueError, KeyError, TypeError)):
                            analyzer(rows)

    def test_log_offsets_require_the_declared_filter_and_monotonic_process_history(self):
        rows = native_report()
        expected = "warn,fips_core::node::handlers::rx_loop::dataplane=debug"
        rows[0]["dataplane_drop_log_filter"] = expected
        for node in nodes(rows):
            node["dataplane_log"] = {"filter": expected,
                                     "bytes": node["measurements"]["process_cpu_ns"] // 100000}
        original = copy.deepcopy(rows)
        _, trials, _ = analyze_rows(rows)
        self.assertEqual(trials[0]["dataplane_log_ranges"]["n01"], {
            "before_guard": 10, "before": 10, "after": 11, "after_guard": 11,
        })
        self.assertEqual(trials[1]["dataplane_log_ranges"]["n01"]["previous_after_guard"], 11)
        for field, value in (("filter", "warn"), ("bytes", 0), ("bytes", True), ("bytes", None)):
            changed = copy.deepcopy(original)
            workload(changed)["after_guard"][0]["dataplane_log"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, TypeError)):
                diagnose_rows(changed)
        changed = copy.deepcopy(original)
        workload(changed)["before"][0].pop("dataplane_log")
        with self.assertRaises(ValueError):
            analyze_rows(changed)
        changed = copy.deepcopy(original)
        changed[0].pop("dataplane_drop_log_filter")
        with self.assertRaises(ValueError):
            analyze_rows(changed)
        self.assertEqual(rows, original)

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
