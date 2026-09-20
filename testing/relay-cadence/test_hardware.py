"""Hardware schema acceptance: host identity and measured-window boundaries."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from analyze import analyze, analyze_rows, diagnose, diagnose_rows, markdown
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
                    "peak_rss_kib": 200 + tick, "io_available": True,
                    "read_bytes": 10 * tick,
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


IO_FIELDS = ("read_bytes", "write_bytes", "rchar", "wchar", "syscr", "syscw")


def unavailable_io(node):
    node["host_process"].update(io_available=False, **{key: None for key in IO_FIELDS})


def delivery_loss_report():
    rows = hardware_report()
    for trial, name, missing in ((4, "high_rate", 2), (5, "steady", 1)):
        data = next(row["data"] for row in rows if row.get("trial") == trial
                    and row.get("data", {}).get("workload") == name)
        receiver = data["probes"][0]["receiver"]
        receiver["unique_packets"] -= missing
        receiver["unique_bytes"] -= missing * 1000
        receiver["missing_packets"] = missing
    return rows


class DiagnosticTests(unittest.TestCase):
    def post_gap_report(self):
        rows = hardware_report()
        rows[0]["post_gap_probes"] = True
        for row in rows:
            if row.get("data", {}).get("workload") != "bursty":
                continue
            for index, probe in enumerate(row["data"]["probes"]):
                start = index * 2_000_000_000
                probe["receiver_observed_ns"] = [start, start + 100_000_000]
                probe["post_gap_observation"] = {
                    "observed_ns": [start + 900_000_000, start + 1_000_000_000],
                    "receiver": copy.deepcopy(probe["receiver"]),
                }
        return rows

    def test_post_gap_arrivals_never_repair_the_strict_delivery_result(self):
        rows = self.post_gap_report()
        probe = workload(rows, "bursty")["probes"][0]
        probe["receiver"].update(unique_packets=62, unique_bytes=62000, missing_packets=2)
        with self.assertRaisesRegex(ValueError, "delivery loss"):
            analyze_rows(rows)
        diagnostic = diagnose_rows(rows)
        self.assertFalse(diagnostic["accepted"])
        result = next(v for v in diagnostic["trials"] if v["workload"] == "bursty")
        self.assertEqual(result["delivered_packets"], 510)
        self.assertEqual(result["post_gap_probes"][0]["additional_packets"], 2)
        self.assertEqual(result["post_gap_probes"][0]["still_missing_packets"], 0)
        self.assertEqual(result["post_gap_probes"][0]["read_elapsed_ms"], 100)

    def test_post_gap_evidence_requires_explicit_mode_identity_and_ordered_clock(self):
        changes = (
            lambda rows, p: rows[0].update(post_gap_probes=False),
            lambda rows, p: rows[0].update(post_gap_probes=1),
            lambda rows, p: p.pop("post_gap_observation"),
            lambda rows, p: p["post_gap_observation"]["receiver"].update(source="another-source"),
            lambda rows, p: p["post_gap_observation"]["receiver"].update(stream_id="b" * 32),
            lambda rows, p: p["post_gap_observation"]["receiver"].update(
                unique_packets=63, unique_bytes=63000, missing_packets=1),
            lambda rows, p: p["post_gap_observation"].update(observed_ns=[899_999_999, 1_000_000_000]),
            lambda rows, p: p["post_gap_observation"].update(observed_ns=[1_000_000_001, 1_000_000_000]),
            lambda rows, p: p.update(receiver_observed_ns=[True, 100_000_000]),
        )
        for change in changes:
            rows = self.post_gap_report()
            change(rows, workload(rows, "bursty")["probes"][0])
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError)):
                diagnose_rows(rows)

    def test_post_gap_observations_must_fit_the_offered_window(self):
        rows = self.post_gap_report()
        last = workload(rows, "bursty")["probes"][-1]
        last["receiver_observed_ns"] = [v + 3_600_000_000_000 for v in last["receiver_observed_ns"]]
        last["post_gap_observation"]["observed_ns"] = [
            v + 3_600_000_000_000 for v in last["post_gap_observation"]["observed_ns"]]
        with self.assertRaisesRegex(ValueError, "offered window"):
            diagnose_rows(rows)

    def test_post_gap_diagnostic_cannot_hide_its_extra_work_in_markdown(self):
        metadata, _, grouped = analyze_rows(self.post_gap_report())
        with self.assertRaisesRegex(ValueError, "post-gap"):
            markdown(metadata, grouped)

    def test_loss_diagnostic_emits_all_costs_but_fails_acceptance(self):
        rows = delivery_loss_report()
        with self.assertRaises(ValueError):
            analyze_rows(rows)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("analyze.py")),
                                     str(path), "--diagnostics"], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 1, result.stderr)
        diagnostic = json.loads(result.stdout)
        self.assertIs(diagnostic["accepted"], False)
        self.assertIs(diagnostic["diagnostic"], True)
        self.assertEqual(len(diagnostic["trials"]), 32)
        self.assertEqual([(r["trial"], r["workload"], r["missing_packets"])
                          for r in diagnostic["rejections"]], [(4, "high_rate", 2), (5, "steady", 1)])
        self.assertEqual(sum(r["submitted_packets"] for r in diagnostic["trials"]), 93696)
        self.assertEqual(sum(r["delivered_packets"] for r in diagnostic["trials"]), 93693)
        self.assertTrue(all(r["mean_latency_us"] is None for r in diagnostic["trials"]))
        affected = next(r for r in diagnostic["trials"] if r["trial"] == 4 and r["workload"] == "high_rate")
        self.assertEqual(affected["delivered_bytes"], 7998000)
        self.assertGreater(affected["process_cpu_seconds_per_mib"], 0)
        self.assertEqual(set(affected["nodes"]), {"n01", "n02", "n03"})

    def test_clean_diagnostics_match_strict_costs_and_have_no_rejections(self):
        rows = hardware_report()
        metadata, trials, _ = analyze_rows(rows)
        diagnostic = diagnose_rows(rows)
        self.assertIs(diagnostic["accepted"], True)
        self.assertEqual(diagnostic["rejections"], [])
        self.assertEqual(diagnostic["metadata"], metadata)
        self.assertEqual(diagnostic["trials"], trials)

    def test_diagnostics_still_reject_invalid_loss_and_other_probe_failures(self):
        for side, field, value in (
            ("receiver", "missing_packets", 3), ("receiver", "missing_packets", True),
            ("receiver", "unique_packets", 8001), ("receiver", "unique_bytes", 7997999),
            ("receiver", "expected_packets", 7998), ("receiver", "duplicate_packets", 1),
            ("receiver", "invalid_packets", 1), ("receiver", "latency", {}),
            ("receiver", "stream_id", "other-stream"),
            ("sender", "submitted_packets", 7998), ("sender", "submitted_bytes", 7998000),
            ("sender", "stopped_reason", "no route"),
        ):
            with self.subTest(side=side, field=field, value=value):
                rows = delivery_loss_report()
                row = next(r for r in rows if r.get("trial") == 4
                           and r.get("data", {}).get("workload") == "high_rate")
                row["data"]["probes"][0][side][field] = value
                with self.assertRaises(ValueError):
                    diagnose_rows(rows)

    def test_diagnostics_do_not_hide_invalid_process_payment_gap_or_finances(self):
        def process(rows):
            workload(rows)["after"][0]["host_process"]["start_ticks"] += 1
        def counter(rows):
            workload(rows)["after"][0]["measurements"]["process_cpu_ns"] = 0
        def payment(rows):
            workload(rows)["after"][0]["payment_progress"]["direction-0"]["in_flight"] = True
        def gap(rows):
            workload(rows)["after_guard"][0]["measurements"]["operations"]["payment_update"]["spans"] += 1
        def durable(rows):
            workload(rows)["after_guard"][0]["measurements"]["operations"]["other"]["journal_writes"] += 1
        def finances(rows):
            rows[-1]["collected_sat"] = 383
        def schedule(rows):
            workload(rows)["probes"][0]["packets_per_second"] = 401
        for mutate in (process, counter, payment, gap, durable, finances, schedule):
            with self.subTest(failure=mutate.__name__):
                rows = delivery_loss_report()
                mutate(rows)
                with self.assertRaises(ValueError):
                    diagnose_rows(rows)

    def test_diagnostic_file_api_and_default_cli_preserve_strict_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in delivery_loss_report()) + "\n")
            self.assertIs(diagnose(path)["accepted"], False)
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("analyze.py")),
                                     str(path)], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("delivery loss", result.stderr)


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
        self.assertEqual(node["reported_vmhwm_after_kib"], 213)
        self.assertEqual(node["os_io"]["write_bytes"], 20)
        self.assertEqual(steady["os_io"]["write_bytes"], 60)
        self.assertIn("not payment-attributed", markdown(metadata, grouped))
        self.assertEqual(grouped[("high_rate", 250)][0]["delivered_packets"], 8000)

    def test_reported_vmhwm_decrease_is_preserved_with_exact_process_epoch(self):
        rows = hardware_report()
        for row in rows:
            if row.get("trial") != 7 or "data" not in row:
                continue
            for boundary in ("before_guard", "before", "after", "after_guard"):
                node = row["data"][boundary][1]
                node["measurements"]["process_id"] = 15290
                value = 24592 if row["data"]["workload"] == "idle" and boundary == "before_guard" else 24576
                node["host_process"].update(pid=15290, start_ticks=20167614,
                                            rss_kib=value, peak_rss_kib=value)
        original = copy.deepcopy(rows)
        _, trials, _ = analyze_rows(rows)
        idle = next(row for row in trials if row["trial"] == 7 and row["workload"] == "idle")
        self.assertEqual(idle["vmhwm_decreases"], [{
            "host": "n02", "before_boundary": "before_guard", "after_boundary": "before",
            "before_kib": 24592, "after_kib": 24576, "decrease_kib": 16,
        }])
        node = idle["nodes"]["n02"]
        self.assertEqual(node["vmhwm_samples_kib"], {
            "before_guard": 24592, "before": 24576, "after": 24576, "after_guard": 24576,
        })
        self.assertEqual(node["maximum_observed_vmhwm_kib"], 24592)
        self.assertEqual(node["reported_vmhwm_after_kib"], 24576)
        self.assertEqual(rows, original)

    def test_vmhwm_decreases_are_recorded_inside_and_between_windows(self):
        rows = hardware_report()
        idle = workload(rows, "idle")
        for boundary, value in zip(("before_guard", "before", "after", "after_guard"),
                                   (500, 480, 470, 460)):
            idle[boundary][1]["host_process"]["peak_rss_kib"] = value
        bursty = workload(rows, "bursty")
        for boundary in ("before_guard", "before", "after", "after_guard"):
            bursty[boundary][1]["host_process"]["peak_rss_kib"] = 450
        _, trials, _ = analyze_rows(rows)
        self.assertEqual([event["decrease_kib"] for event in trials[0]["vmhwm_decreases"]], [20, 10, 10])
        self.assertEqual(trials[1]["vmhwm_decreases"], [{
            "host": "n02", "before_boundary": "previous_after_guard", "after_boundary": "before_guard",
            "before_kib": 460, "after_kib": 450, "decrease_kib": 10,
        }])
        self.assertEqual(trials[1]["nodes"]["n02"]["maximum_observed_vmhwm_kib"], 460)

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
                             ("rss_kib", -1), ("peak_rss_kib", -1),
                             ("peak_rss_kib", True), ("peak_rss_kib", None), ("wchar", None)):
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

    def test_os_counters_cannot_reset(self):
        for key in ("read_bytes", "write_bytes", "rchar", "wchar", "syscr", "syscw"):
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

    def test_absent_os_io_is_null_instead_of_zero_or_partial_total(self):
        for absent_hosts in ({"n01", "n02", "n03"}, {"n02"}):
            with self.subTest(absent_hosts=absent_hosts):
                rows = hardware_report()
                for node in nodes(rows):
                    if node["host_process"]["host"] in absent_hosts:
                        unavailable_io(node)
                _, _, grouped = analyze_rows(rows)
                result = grouped[("steady", 250)][0]
                self.assertIsNone(result["os_io"])
                self.assertEqual(result["os_io_observed_nodes"], 3 - len(absent_hosts))
                self.assertEqual(result["journal_commits"], 21)
                self.assertGreater(result["process_cpu_ms"], 0)
                for host, node in result["nodes"].items():
                    if host in absent_hosts:
                        self.assertIsNone(node["os_io"])
                    else:
                        self.assertEqual(node["os_io"]["write_bytes"], 20)
                    self.assertEqual(node["rss_after_kib"], 113)

    def test_io_availability_is_explicit_and_cannot_mask_malformed_counters(self):
        for value in (None, 0, 1, "false"):
            with self.subTest(io_available=value):
                self.reject(lambda rows: workload(rows)["after"][0]
                            ["host_process"].__setitem__("io_available", value))
        self.reject(lambda rows: workload(rows)["after"][0]
                    ["host_process"].pop("io_available"))
        for key in IO_FIELDS:
            with self.subTest(field=key):
                def invented_zero(rows):
                    for node in nodes(rows):
                        unavailable_io(node)
                    workload(rows)["after"][0]["host_process"][key] = 0
                self.reject(invented_zero)
                self.reject(lambda rows: workload(rows)["after"][0]
                            ["host_process"].__setitem__(key, None))
                self.reject(lambda rows: workload(rows)["after"][0]
                            ["host_process"].__setitem__(key, True))

    def test_io_availability_cannot_change_across_measurements_or_guards(self):
        for boundary in ("before_guard", "before", "after", "after_guard"):
            with self.subTest(boundary=boundary):
                self.reject(lambda rows: unavailable_io(workload(rows)[boundary][0]))
        def between_workloads(rows):
            for row in rows:
                if "data" in row and row["data"]["workload"] != "idle":
                    for boundary in ("before_guard", "before", "after", "after_guard"):
                        unavailable_io(row["data"][boundary][0])
        self.reject(between_workloads)

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

    def test_explicit_pilot_validates_one_complete_trial(self):
        rows = hardware_report()[:6]
        rows[0]["pilot"] = True
        metadata, trials, grouped = analyze_rows(rows, pilot=True)
        self.assertIs(metadata["pilot"], True)
        self.assertEqual(len(trials), 4)
        self.assertEqual({row["max_delay_ms"] for row in trials}, {250})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pilot.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            self.assertEqual(analyze(path, pilot=True)[1], trials)
        with self.assertRaises(ValueError):
            markdown(metadata, grouped)

    def test_pilot_requires_explicit_mode_and_cannot_claim_full_comparison(self):
        rows = hardware_report()[:6]
        rows[0]["pilot"] = True
        with self.assertRaises(ValueError):
            analyze_rows(rows)
        for flag in (None, False, 1, "true"):
            with self.subTest(pilot=flag):
                rows[0]["pilot"] = flag
                with self.assertRaises(ValueError):
                    analyze_rows(rows, pilot=True)
        with self.assertRaises(ValueError):
            analyze_rows(complete_report(), pilot=True)
        rows = hardware_report()
        rows[0]["pilot"] = True
        with self.assertRaises(ValueError):
            analyze_rows(rows, pilot=True)
        with self.assertRaises(ValueError):
            analyze_rows(rows)

    def test_pilot_reuses_payment_boundary_and_financial_acceptance(self):
        for kind in ("missing_conservation", "partial_collection", "missing_guard",
                     "unmeasured_work", "unknown_acknowledgment"):
            with self.subTest(failure=kind):
                rows = hardware_report()[:6]
                rows[0]["pilot"] = True
                if kind == "missing_conservation":
                    rows.pop()
                elif kind == "partial_collection":
                    rows[-1]["collected_sat"] = 383
                elif kind == "missing_guard":
                    workload(rows).pop("after_guard")
                elif kind == "unmeasured_work":
                    operation = workload(rows)["after_guard"][0]
                    operation["measurements"]["operations"]["payment_update"]["spans"] += 1
                else:
                    workload(rows)["after_guard"][0]["payment_progress"]["direction-0"][
                        "acknowledged_msat"] = None
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    analyze_rows(rows, pilot=True)

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
