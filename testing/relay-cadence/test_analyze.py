"""Acceptance boundaries for complete synthetic cadence reports; no live accounts."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from analyze import analyze
from validation import validate_latency


DELAYS = [250, 500, 1000, 2000, 2000, 1000, 500, 250]
WORKLOADS = {"idle": [], "bursty": [64] * 8, "steady": [3200], "high_rate": [32000]}
OPERATIONS = ("other", "payment_sign", "payment_usage", "payment_update",
              "payment_open", "payment_stop", "window_checkpoint")
BOUNDS = [100, 250, 500, 1000, 2000, 5000, 10000, 20000, 50000,
          100000, 250000, 500000, 1000000]
CHANNELS = (("forward-0",), ("forward-1",), ("forward-2", "reverse-2"),
            ("reverse-1",), ("reverse-0",))


def snapshot(node, tick, payment_tick):
    operations = {}
    for name in OPERATIONS:
        value = payment_tick
        operations[name] = {
            "spans": value, "cpu_samples": value, "thread_cpu_ns": value * 1000,
            "elapsed_ns": value * 2000, "journal_bytes_written": value * 128,
            "journal_writes": value, "journal_syncs": value * 2,
            "journal_commits": value,
        }
    return {
        "measurements": {"version": 1, "process_id": 100 + node,
                         "process_cpu_ns": tick * 100000, "operations": operations},
        "control_traffic": [
            {"service_port": port, "counters": {
                "stream_bytes_sent": payment_tick * 100,
                "stream_bytes_received": payment_tick * 100,
                "requests_started": payment_tick, "requests_received": payment_tick,
            }} for port in (44741, 44742, 44743)
        ],
        "peers": [{"npub": f"synthetic-peer-{peer}", "connected": True,
                   "link_id": 10 + peer, "sent_bytes": tick * 1000}
                  for peer in range(5) if abs(peer - node) == 1],
        "last_error": None,
        "payment_progress": {
            channel: {"evidence_msat": payment_tick * 1000 - 1,
                      "authorized_sat": payment_tick,
                      "acknowledged_msat": payment_tick * 1000,
                      "in_flight": False}
            for channel in CHANNELS[node]
        },
    }


def probe(count, stream):
    return {
        "sender": {"stream_id": f"{stream:032x}", "requested_packets": count,
                   "submitted_packets": count, "submitted_bytes": count * 1000,
                   "elapsed_us": 1000000, "stopped_reason": None},
        "receiver": {"source": "synthetic-peer-0", "stream_id": f"{stream:032x}",
                     "expected_packets": count, "payload_bytes": 1000,
                     "unique_packets": count, "unique_bytes": count * 1000,
                     "missing_packets": 0, "duplicate_packets": 0,
                     "out_of_order_packets": 0, "ignored_packets": 0,
                     "invalid_packets": 0, "receive_span_us": 1000000,
                     "latency": {"samples": count, "invalid_timestamps": 0,
                                 "min_us": 80, "max_us": 80, "sum_us": count * 80,
                                 "bucket_upper_bounds_us": BOUNDS.copy(),
                                 "bucket_counts": [count] + [0] * len(BOUNDS)}},
    }


def complete_report():
    rows = [{"schema": 2, "optimized": True, "platform": "synthetic",
             "architecture": "synthetic", "nodes": 5, "paid_relays": 3,
             "funded_directions": 2, "transport": "UDP loopback", "repeats": 2,
             "unpaid_percent": 50, "window_msat": 4000, "grace_msat": 8000,
             "channel_capacity_sat": 256, "fee_msat_per_kib": 1}]
    for trial, delay in enumerate(DELAYS):
        tick = 10
        payment_tick = 10
        for index, (workload, counts) in enumerate(WORKLOADS.items()):
            before = [snapshot(node, tick, payment_tick) for node in range(5)]
            tick += 1
            payment_tick += bool(counts)
            after = [snapshot(node, tick, payment_tick) for node in range(5)]
            rows.append({"trial": trial, "max_delay_ms": delay, "data": {
                "workload": workload, "offered_elapsed_ms": 8000,
                "observation_elapsed_ms": 11000, "before": before, "after": after,
                "before_guard": copy.deepcopy(before), "after_guard": copy.deepcopy(after),
                "probes": [probe(count, (trial * 4 + index) * 100 + burst)
                           for burst, count in enumerate(counts)],
            }})
        rows.append({"trial": trial, "max_delay_ms": delay, "conserved": True,
                     "settled_channels": 6, "issued_sat": 5120, "collected_sat": 5120})
    return rows


def workload(rows, name="steady"):
    return next(row["data"] for row in rows if row.get("data", {}).get("workload") == name)


def all_snapshots(rows):
    for row in rows:
        if "data" in row:
            for boundary in ("before_guard", "before", "after", "after_guard"):
                yield from row["data"][boundary]


class AnalyzeTests(unittest.TestCase):
    def run_report(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            return analyze(path)

    def reject(self, mutate):
        rows = complete_report()
        mutate(rows)
        with self.assertRaises(ValueError):
            self.run_report(rows)

    def test_complete_settled_matrix_is_accepted(self):
        metadata, trials, grouped = self.run_report(complete_report())
        self.assertEqual(metadata["schema"], 2)
        self.assertEqual(len(trials), 32)
        self.assertEqual(len(grouped), 16)
        self.assertTrue(all(len(values) == 2 for values in grouped.values()))
        steady = grouped[("steady", 250)][0]
        self.assertEqual(steady["delivered_packets"], 3200)
        self.assertEqual(steady["delivered_bytes"], 3200000)
        self.assertEqual(steady["missing_submitted_packets"], 0)
        self.assertEqual(steady["mean_latency_us"], 80)

    def test_reordering_is_recorded_without_rejecting_complete_delivery(self):
        rows = complete_report()
        workload(rows)["probes"][0]["receiver"]["out_of_order_packets"] = 7
        _, _, grouped = self.run_report(rows)
        self.assertEqual(grouped[("steady", 250)][0]["out_of_order_packets"], 7)

    def test_both_boundaries_require_complete_acknowledgment(self):
        for boundary in ("before", "after"):
            for field in ("evidence_msat", "authorized_sat"):
                with self.subTest(boundary=boundary, outstanding=field):
                    def mutate(rows):
                        progress = workload(rows)[boundary][0]["payment_progress"]["forward-0"]
                        progress[field] += 1000
                    self.reject(mutate)

    def test_both_boundaries_reject_in_flight_or_unknown_progress(self):
        for boundary in ("before", "after"):
            for value in (True, None, 0, "false"):
                with self.subTest(boundary=boundary, value=value):
                    self.reject(lambda rows: workload(rows)[boundary][0]["payment_progress"]
                                ["forward-0"].__setitem__("in_flight", value))

    def test_progress_counters_require_nonnegative_integers(self):
        for field in ("evidence_msat", "authorized_sat", "acknowledged_msat"):
            for value in (None, -1, True, 1.5, "10000"):
                with self.subTest(field=field, value=value):
                    self.reject(lambda rows: workload(rows)["after"][0]["payment_progress"]
                                ["forward-0"].__setitem__(field, value))

    def test_progress_requires_every_field(self):
        for field in ("evidence_msat", "authorized_sat", "acknowledged_msat", "in_flight"):
            with self.subTest(field=field):
                self.reject(lambda rows: workload(rows)["after"][0]["payment_progress"]
                            ["forward-0"].pop(field))

    def test_missing_or_unknown_progress_maps_are_rejected(self):
        self.reject(lambda rows: workload(rows)["before"][0].pop("payment_progress"))
        for value in (None, [], {}):
            with self.subTest(value=value):
                self.reject(lambda rows: workload(rows)["after"][0]
                            .__setitem__("payment_progress", value))

    def test_channel_membership_cannot_change_at_a_boundary(self):
        def replace(rows):
            progress = workload(rows)["after"][0]["payment_progress"]
            progress["replacement"] = progress.pop("forward-0")
        self.reject(replace)

    def test_duplicate_channel_across_processes_is_not_six_distinct_channels(self):
        def duplicate(rows):
            for boundary in ("before", "after"):
                progress = workload(rows)[boundary][1]["payment_progress"]
                progress["forward-0"] = progress.pop("forward-1")
        self.reject(duplicate)

    def test_channel_count_cannot_be_reduced_or_increased(self):
        for extra in (False, True):
            with self.subTest(extra=extra):
                def mutate(rows):
                    for boundary in ("before", "after"):
                        progress = workload(rows)[boundary][0]["payment_progress"]
                        if extra:
                            progress["extra"] = copy.deepcopy(progress["forward-0"])
                        else:
                            progress.clear()
                self.reject(mutate)

    def test_clean_link_loss_and_partial_submission_are_rejected(self):
        def loss(rows):
            receiver = workload(rows)["probes"][0]["receiver"]
            receiver.update(unique_packets=3199, unique_bytes=3199000, missing_packets=1)
            receiver["latency"].update(samples=3199, sum_us=3199 * 80)
            receiver["latency"]["bucket_counts"][0] = 3199
        self.reject(loss)

        def partial(rows):
            loss(rows)
            workload(rows)["probes"][0]["sender"].update(
                submitted_packets=3199, submitted_bytes=3199000)
        self.reject(partial)

    def test_stopped_sender_and_controller_error_are_rejected(self):
        self.reject(lambda rows: workload(rows)["probes"][0]["sender"]
                    .__setitem__("stopped_reason", "duration limit reached"))
        for boundary in ("before", "after"):
            with self.subTest(boundary=boundary):
                self.reject(lambda rows: workload(rows)[boundary][0]
                            .__setitem__("last_error", "payment not acknowledged"))

    def test_invalid_timestamps_are_not_accepted_as_complete_timing(self):
        def invalid(rows):
            latency = workload(rows)["probes"][0]["receiver"]["latency"]
            latency.update(samples=3199, invalid_timestamps=1, sum_us=3199 * 80)
            latency["bucket_counts"][0] = 3199
        self.reject(invalid)

    def test_negative_latency_mean_is_rejected(self):
        self.reject(lambda rows: workload(rows)["probes"][0]["receiver"]["latency"]
                    .__setitem__("sum_us", -256000))

    def test_latency_fields_require_nonnegative_integers(self):
        for field in ("samples", "invalid_timestamps", "sum_us", "min_us", "max_us",
                      "bucket_upper_bounds_us", "bucket_counts"):
            for invalid in (-1, True, None, 1.5, "80"):
                with self.subTest(field=field, invalid=invalid):
                    def mutate(rows):
                        latency = workload(rows)["probes"][0]["receiver"]["latency"]
                        if field.startswith("bucket_"):
                            latency[field][0] = invalid
                        else:
                            latency[field] = invalid
                    self.reject(mutate)

    def test_latency_histogram_shape_and_order_are_required(self):
        for field, value in (("bucket_counts", None),
                             ("bucket_counts", [3200]),
                             ("bucket_upper_bounds_us", None),
                             ("bucket_upper_bounds_us", [250, 100] + BOUNDS[2:]),
                             ("bucket_upper_bounds_us", [100, 100] + BOUNDS[2:])):
            with self.subTest(field=field, value=value):
                self.reject(lambda rows: workload(rows)["probes"][0]["receiver"]["latency"]
                            .__setitem__(field, value))

    def test_latency_extrema_and_sum_must_fit_occupied_buckets(self):
        cases = ({"min_us": 81}, {"max_us": 79},
                 {"min_us": 101, "max_us": 101, "sum_us": 3200 * 101},
                 {"sum_us": 3200 * 80 - 1}, {"sum_us": 3200 * 80 + 1})
        for changes in cases:
            with self.subTest(changes=changes):
                self.reject(lambda rows: workload(rows)["probes"][0]["receiver"]["latency"]
                            .update(changes))
        # These sums fit samples * min/max, but cannot fit the actual occupied
        # inclusive bins (one at 10, 3198 in 101..200, and one at 250).
        for total in (320000, 700000):
            def mutate(rows):
                workload(rows)["probes"][0]["receiver"]["latency"].update(
                    min_us=10, max_us=250, sum_us=total,
                    bucket_upper_bounds_us=[100, 200], bucket_counts=[1, 3198, 1])
            with self.subTest(total=total):
                self.reject(mutate)

    def test_latency_inclusive_boundaries_and_overflow_remain_valid(self):
        for delay, bucket in ((0, 0), (100, 0), (101, 1),
                              (1000000, 12), (1000001, 13)):
            with self.subTest(delay=delay):
                rows = complete_report()
                latency = workload(rows)["probes"][0]["receiver"]["latency"]
                counts = [0] * (len(BOUNDS) + 1)
                counts[bucket] = 3200
                latency.update(min_us=delay, max_us=delay, sum_us=3200 * delay,
                               bucket_counts=counts)
                _, _, grouped = self.run_report(rows)
                self.assertEqual(grouped[("steady", 250)][0]["mean_latency_us"], delay)

    def test_self_described_histogram_accepts_feasible_sum_endpoints(self):
        for total in (10 + 3198 * 101 + 250, 10 + 3198 * 200 + 250):
            rows = complete_report()
            workload(rows)["probes"][0]["receiver"]["latency"].update(
                min_us=10, max_us=250, sum_us=total,
                bucket_upper_bounds_us=[100, 200], bucket_counts=[1, 3198, 1])
            _, _, grouped = self.run_report(rows)
            self.assertEqual(grouped[("steady", 250)][0]["mean_latency_us"], total / 3200)

    def test_zero_and_single_sample_latency_match_reporter_extrema(self):
        empty = {"samples": 0, "invalid_timestamps": 0, "min_us": None,
                 "max_us": None, "sum_us": 0, "bucket_upper_bounds_us": BOUNDS,
                 "bucket_counts": [0] * (len(BOUNDS) + 1)}
        validate_latency(empty, 0)
        for changes in ({"min_us": 0}, {"max_us": 0}, {"sum_us": 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_latency({**empty, **changes}, 0)
        single = probe(1, 0)["receiver"]["latency"]
        validate_latency(single, 1)
        with self.assertRaises(ValueError):
            validate_latency({**single, "max_us": 81}, 1)
        # Both extrema must be actual samples, even within one broad bin.
        pair = probe(2, 0)["receiver"]["latency"]
        pair.update(min_us=10, max_us=80, sum_us=90)
        validate_latency(pair, 2)
        for total in (89, 91):
            with self.subTest(total=total), self.assertRaises(ValueError):
                validate_latency({**pair, "sum_us": total}, 2)

    def test_mismatched_workload_and_payload_sizes_are_rejected(self):
        for side, field, value in (("sender", "requested_packets", 3201),
                                   ("sender", "submitted_bytes", 3199999),
                                   ("receiver", "expected_packets", 3201),
                                   ("receiver", "payload_bytes", 999),
                                   ("receiver", "unique_bytes", 3199999)):
            with self.subTest(side=side, field=field):
                self.reject(lambda rows: workload(rows)["probes"][0][side]
                            .__setitem__(field, value))

    def test_idle_payment_activity_invalidates_the_boundary(self):
        for name in ("payment_sign", "payment_usage", "payment_update"):
            with self.subTest(operation=name):
                def mutate(rows):
                    operation = workload(rows, "idle")["after"][0]["measurements"]["operations"][name]
                    operation["spans"] += 1
                    operation["cpu_samples"] += 1
                self.reject(mutate)
        for field in ("stream_bytes_sent", "stream_bytes_received", "requests_started", "requests_received"):
            with self.subTest(counter=field):
                def mutate(rows):
                    counters = workload(rows, "idle")["after"][0]["control_traffic"][2]["counters"]
                    counters[field] += 1
                self.reject(mutate)

    def test_process_counter_and_epoch_resets_are_rejected(self):
        for field, value in (("process_id", 999), ("process_cpu_ns", 0)):
            with self.subTest(field=field):
                self.reject(lambda rows: workload(rows)["after"][0]["measurements"]
                            .__setitem__(field, value))
        self.reject(lambda rows: workload(rows)["after"][0]["peers"][0]
                    .__setitem__("link_id", 999))
        self.reject(lambda rows: workload(rows)["after"][0]["peers"].clear())

    def test_payment_or_durability_work_cannot_escape_between_windows(self):
        def progress(rows):
            # Remains fully acknowledged: the failure is the unmeasured change.
            for boundary in ("before", "after"):
                state = workload(rows)[boundary][0]["payment_progress"]["forward-0"]
                state["acknowledged_msat"] += 1000
        self.reject(progress)

        def traffic(rows):
            for boundary in ("before", "after"):
                counters = workload(rows)[boundary][0]["control_traffic"][2]["counters"]
                counters["stream_bytes_sent"] += 1
        self.reject(traffic)
        for operation in ("payment_update", "window_checkpoint"):
            with self.subTest(operation=operation):
                def durability(rows):
                    for boundary in ("before", "after"):
                        counters = workload(rows)[boundary][0]["measurements"]["operations"][operation]
                        counters["journal_writes"] += 1
                self.reject(durability)

    def test_final_provider_work_cannot_escape_after_the_measured_snapshot(self):
        for operation, fields in (("payment_update", ("spans", "cpu_samples")),
                                  ("window_checkpoint", ("journal_writes",))):
            with self.subTest(operation=operation):
                def late_work(rows):
                    counters = workload(rows, "high_rate")["after_guard"][1]
                    counters = counters["measurements"]["operations"][operation]
                    for field in fields:
                        counters[field] += 1
                self.reject(late_work)

    def test_guard_passes_must_also_show_acknowledged_idle_channels(self):
        for boundary in ("before_guard", "after_guard"):
            for field, value in (("in_flight", True), ("acknowledged_msat", None)):
                with self.subTest(boundary=boundary, field=field):
                    self.reject(lambda rows: workload(rows, "high_rate")[boundary][1]
                                ["payment_progress"]["forward-1"].__setitem__(field, value))

    def test_both_guard_passes_are_required(self):
        for boundary in ("before_guard", "after_guard"):
            with self.subTest(boundary=boundary):
                self.reject(lambda rows: workload(rows).pop(boundary))

    def test_operation_counter_reset_or_missing_cpu_samples_is_rejected(self):
        for field in ("spans", "cpu_samples", "thread_cpu_ns", "journal_writes",
                      "journal_bytes_written", "journal_syncs"):
            with self.subTest(field=field):
                self.reject(lambda rows: workload(rows)["after"][0]["measurements"]["operations"]
                            ["payment_update"].__setitem__(field, 0))

    def test_nonpayment_operations_cannot_be_omitted_everywhere(self):
        for operation in ("other", "window_checkpoint", "payment_open", "payment_stop"):
            with self.subTest(operation=operation):
                def omit(rows):
                    for node in all_snapshots(rows):
                        node["measurements"]["operations"].pop(operation)
                self.reject(omit)

    def test_previously_unused_operation_counters_cannot_reset(self):
        for operation in ("other", "window_checkpoint", "payment_open", "payment_stop"):
            for field in ("elapsed_ns", "journal_commits", "thread_cpu_ns"):
                with self.subTest(operation=operation, field=field):
                    # The final window has no following gap check to mask a
                    # missing counter validation inside the measured interval.
                    self.reject(lambda rows: workload(rows, "high_rate")["after"][0]
                                ["measurements"]["operations"][operation].__setitem__(field, 0))

    def test_every_operation_counter_is_required_even_when_unused_in_summary(self):
        for field in ("spans", "cpu_samples", "thread_cpu_ns", "elapsed_ns",
                      "journal_bytes_written", "journal_writes", "journal_syncs", "journal_commits"):
            with self.subTest(field=field):
                def omit(rows):
                    for node in all_snapshots(rows):
                        node["measurements"]["operations"]["other"].pop(field)
                self.reject(omit)

    def test_process_ids_must_be_distinct_and_nonzero(self):
        for invalid in (0, 100):
            with self.subTest(process_id=invalid):
                def replace(rows):
                    for node in all_snapshots(rows):
                        if node["measurements"]["process_id"] == 101:
                            node["measurements"]["process_id"] = invalid
                self.reject(replace)

    def test_invalid_elapsed_time_or_histogram_is_rejected(self):
        for field in ("offered_elapsed_ms", "observation_elapsed_ms"):
            for value in (0, -1, None, True):
                with self.subTest(field=field, value=value):
                    self.reject(lambda rows: workload(rows).__setitem__(field, value))
        self.reject(lambda rows: workload(rows)["probes"][0]["receiver"]["latency"]
                    .__setitem__("bucket_counts", [0] * (len(BOUNDS) + 1)))

    def test_old_schema_or_unoptimized_measurement_is_rejected(self):
        for field, value in (("schema", 1), ("optimized", False), ("optimized", 1)):
            with self.subTest(field=field, value=value):
                self.reject(lambda rows: rows[0].__setitem__(field, value))

    def test_missing_or_duplicate_matrix_rows_are_rejected(self):
        self.reject(lambda rows: rows.pop(1))
        self.reject(lambda rows: rows.append(copy.deepcopy(rows[1])))
        self.reject(lambda rows: rows[1].__setitem__("max_delay_ms", 500))

    def test_conservation_requires_unique_complete_matching_trials(self):
        self.reject(lambda rows: rows.append(copy.deepcopy(rows[5])))
        self.reject(lambda rows: rows.pop(5))
        for field, value in (("trial", 99), ("conserved", False), ("collected_sat", 5119),
                             ("settled_channels", 5)):
            with self.subTest(field=field):
                self.reject(lambda rows: rows[5].__setitem__(field, value))


if __name__ == "__main__":
    unittest.main()
