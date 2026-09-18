"""Hardware schema acceptance: host identity and measured-window boundaries."""
import copy
import unittest

from analyze import analyze_rows, markdown
from test_analyze import complete_report, workload


def hardware_report():
    rows = complete_report()
    rows[0].update(
        schema=3, nodes=3, paid_relays=1, active_channels=2,
        channel_capacity_sat=32, billing="forwarding_data",
        quote_max_units=16777216, transport="native Ethernet over 802.11s",
        one_way_latency=False, common_tail_ms=3000,
        workload_schedule={
            "idle": {"duration_ms": 4000},
            "bursty": {"packet_counts": [64] * 8, "payload_bytes": 1000,
                       "packets_per_second": 1000, "after_each_sleep_ms": 800},
            "steady": {"packet_counts": [3200], "payload_bytes": 1000,
                       "packets_per_second": 400},
            "high_rate": {"packet_counts": [8000], "payload_bytes": 1000,
                          "packets_per_second": 4000},
        },
    )
    for row in rows[1:]:
        if "data" not in row:
            row.update(issued_sat=384, collected_sat=384, settled_channels=2)
            continue
        data = row["data"]
        if data["workload"] == "bursty":
            data.update(offered_elapsed_ms=15000, observation_elapsed_ms=18000)
        for boundary in ("before_guard", "before", "after", "after_guard"):
            nodes = []
            for index in range(3):
                node = copy.deepcopy(data[boundary][index])
                tick = node["measurements"]["process_cpu_ns"] // 100000
                node["npub"] = f"synthetic-hardware-node-{index}"
                # Real routers may use identical PIDs; host and start time matter.
                node["measurements"]["process_id"] = 100
                node["host_process"] = {
                    "host": f"n0{index + 1}", "pid": 100,
                    "start_ticks": 1000 + index, "rss_kib": 100 + tick,
                    "peak_rss_kib": 200 + tick, "read_bytes": 10 * tick,
                    "write_bytes": 20 * tick, "rchar": 30 * tick,
                    "wchar": 40 * tick, "syscr": 2 * tick, "syscw": 3 * tick,
                }
                if index == 1:
                    node["payment_progress"] = {}
                else:
                    progress = next(iter(node["payment_progress"].values()))
                    node["payment_progress"] = {f"direction-{index}": progress}
                node["peers"] = [p for p in node["peers"]
                                 if p["npub"] != "synthetic-peer-3"]
                nodes.append(node)
            data[boundary] = nodes
        for probe in data["probes"]:
            schedule = rows[0]["workload_schedule"][data["workload"]]
            probe["packets_per_second"] = schedule["packets_per_second"]
            probe["after_sleep_ms"] = schedule.get("after_each_sleep_ms", 0)
            probe["receiver"]["latency"] = None
            if data["workload"] == "high_rate":
                probe["sender"].update(requested_packets=8000, submitted_packets=8000,
                                       submitted_bytes=8000000)
                probe["receiver"].update(expected_packets=8000, unique_packets=8000,
                                         unique_bytes=8000000)
    return rows


def nodes(rows):
    for row in rows:
        if "data" in row:
            for boundary in ("before_guard", "before", "after", "after_guard"):
                yield from row["data"][boundary]


class HardwareTests(unittest.TestCase):
    def reject(self, mutate):
        rows = hardware_report()
        mutate(rows)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            analyze_rows(rows)

    def test_complete_hardware_matrix_reports_costs_without_fabricating_latency(self):
        metadata, trials, grouped = analyze_rows(hardware_report())
        self.assertEqual(len(trials), 32)
        steady = grouped[("steady", 250)][0]
        self.assertEqual(steady["delivered_bytes"], 3200000)
        self.assertIsNone(steady["mean_latency_us"])
        self.assertIsNone(steady["p95_upper_us"])
        self.assertEqual(steady["latency_samples"], 0)
        self.assertEqual(steady["journal_commits"], 21)
        self.assertEqual(set(steady["nodes"]), {"n01", "n02", "n03"})
        self.assertAlmostEqual(
            steady["process_cpu_seconds_per_mib"], 0.0003 * 2**20 / 3200000,
        )
        node = steady["nodes"]["n01"]
        self.assertEqual(node["rss_before_kib"], 112)
        self.assertEqual(node["rss_after_kib"], 113)
        self.assertEqual(node["process_lifetime_peak_rss_kib"], 213)
        self.assertEqual(node["os_io"]["write_bytes"], 20)
        self.assertEqual(steady["os_io"]["write_bytes"], 60)
        self.assertIn("not payment-attributed", markdown(metadata, grouped))
        self.assertEqual(grouped[("high_rate", 250)][0]["delivered_packets"], 8000)

    def test_measured_radio_idle_payment_work_is_reported(self):
        rows = hardware_report()
        for row in rows:
            if "data" not in row:
                continue
            data = row["data"]
            for boundary in ("before_guard", "before", "after", "after_guard"):
                if data["workload"] == "idle" and boundary in ("before_guard", "before"):
                    continue
                for node in data[boundary]:
                    for op in node["measurements"]["operations"].values():
                        op["spans"] += 1
                        op["cpu_samples"] += 1
                        op["thread_cpu_ns"] += 1000
                    for control in node["control_traffic"]:
                        control["counters"]["requests_started"] += 1
        _, _, grouped = analyze_rows(rows)
        self.assertEqual(grouped[("idle", 250)][0]["updates"], 3)
        self.assertEqual(grouped[("idle", 250)][0]["payment_requests"], 3)

    def test_pid_start_or_npub_change_rejects_the_measurement(self):
        for boundary in ("before_guard", "before", "after", "after_guard"):
            for section, field, value in (
                ("host_process", "pid", 101),
                ("host_process", "start_ticks", 999),
                (None, "npub", "replacement-node"),
            ):
                with self.subTest(boundary=boundary, field=field):
                    def mutate(rows):
                        node = workload(rows)[boundary][0]
                        (node[section] if section else node)[field] = value
                    self.reject(mutate)

    def test_hosts_are_exactly_three_distinct_scopes(self):
        for field, value in (("host", "n04"), ("host", "n02"),
                             ("pid", 0), ("start_ticks", True),
                             ("rss_kib", -1), ("wchar", None)):
            with self.subTest(field=field, value=value):
                self.reject(lambda rows: workload(rows)["before"][0]
                            ["host_process"].__setitem__(field, value))
        self.reject(lambda rows: workload(rows)["after"][0].pop("host_process"))
        self.reject(lambda rows: workload(rows)["after"][0].pop("npub"))
        self.reject(lambda rows: workload(rows)["after"][0]
                    ["host_process"].__setitem__("peak_rss_kib", 1))

    def test_latency_must_be_explicitly_unmeasured(self):
        for value in ({}, {"samples": 0}, False):
            with self.subTest(value=value):
                self.reject(lambda rows: workload(rows)["probes"][0]["receiver"]
                            .__setitem__("latency", value))
        self.reject(lambda rows: workload(rows)["probes"][0]["receiver"].pop("latency"))
        self.reject(lambda rows: rows[0].__setitem__("one_way_latency", True))

    def test_os_counters_and_lifetime_peak_cannot_reset(self):
        for key in ("read_bytes", "write_bytes", "rchar", "wchar", "syscr", "syscw",
                    "peak_rss_kib"):
            with self.subTest(counter=key):
                self.reject(lambda rows: workload(rows)["after"][0]
                            ["host_process"].__setitem__(key, 0))

    def test_rss_may_fall_and_os_io_does_not_masquerade_as_payment_io(self):
        rows = hardware_report()
        for node in nodes(rows):
            if node["host_process"]["host"] == "n01":
                node["host_process"]["rss_kib"] = 200 - node["host_process"]["rss_kib"]
                node["host_process"]["write_bytes"] *= 100
        _, _, grouped = analyze_rows(rows)
        result = grouped[("steady", 250)][0]
        self.assertLess(result["nodes"]["n01"]["rss_after_kib"],
                        result["nodes"]["n01"]["rss_before_kib"])
        self.assertEqual(result["payment_journal_bytes"], 9 * 128)
        self.assertEqual(result["os_io"]["write_bytes"], 2040)

    def test_idle_permission_does_not_allow_unmeasured_payment_or_durability(self):
        for section, field in (("payment_update", "spans"),
                               ("window_checkpoint", "journal_commits")):
            with self.subTest(section=section):
                self.reject(lambda rows: workload(rows, "high_rate")["after_guard"][1]
                            ["measurements"]["operations"][section].__setitem__(field, 999))
        self.reject(lambda rows: workload(rows)["before_guard"][0]
                    ["control_traffic"][2]["counters"].__setitem__("requests_started", 999))

    def test_two_channels_must_be_known_acknowledged_and_unchanged(self):
        for value in (None, 0, True):
            with self.subTest(acknowledged=value):
                self.reject(lambda rows: workload(rows)["after"][0]
                            ["payment_progress"]["direction-0"]
                            .__setitem__("acknowledged_msat", value))
        self.reject(lambda rows: workload(rows)["after"][2]["payment_progress"].clear())
        self.reject(lambda rows: workload(rows)["after"][0]
                    ["payment_progress"]["direction-0"].__setitem__("in_flight", True))

    def test_schedule_and_all_eight_burst_sleeps_are_required(self):
        for field, value in (("packets_per_second", 999), ("after_sleep_ms", 0)):
            with self.subTest(field=field):
                self.reject(lambda rows: workload(rows, "bursty")["probes"][-1]
                            .__setitem__(field, value))
        self.reject(lambda rows: rows[0]["workload_schedule"]["steady"]
                    .__setitem__("packets_per_second", 401))
        self.reject(lambda rows: rows[0].__setitem__("common_tail_ms", 2000))
        self.reject(lambda rows: workload(rows, "bursty")
                    .__setitem__("offered_elapsed_ms", 14000))
        self.reject(lambda rows: workload(rows, "idle")
                    .__setitem__("offered_elapsed_ms", 3999))
        self.reject(lambda rows: workload(rows)
                    .__setitem__("observation_elapsed_ms", 10999))

    def test_fixed_accounting_capacity_and_workload_cannot_drift(self):
        for field, value in (("channel_capacity_sat", 256), ("billing", "forwarding_attempt"),
                             ("quote_max_units", 16777217), ("active_channels", 6)):
            with self.subTest(field=field):
                self.reject(lambda rows: rows[0].__setitem__(field, value))
        self.reject(lambda rows: rows[5].__setitem__("issued_sat", 5120))
        self.reject(lambda rows: rows[5].__setitem__("collected_sat", 383))
        self.reject(lambda rows: rows[5].__setitem__("settled_channels", 6))
        def reorder_accounting(rows):
            rows[5], rows[10] = rows[10], rows[5]
        self.reject(reorder_accounting)
        self.reject(lambda rows: workload(rows, "high_rate")["probes"][0]["sender"]
                    .__setitem__("requested_packets", 32000))


if __name__ == "__main__":
    unittest.main()
