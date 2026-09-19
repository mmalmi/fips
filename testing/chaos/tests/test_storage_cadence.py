"""Matched storage evidence must reject lost traffic, moving boundaries and debt."""

import argparse
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from sim.paid_storage import storage_paths
from sim.storage_cadence import DURABILITY, StorageCadenceRun, run, summarize_window
from storage_trace import analyze
from validation import COUNTERS, OPERATIONS, PAYMENT_OPERATIONS


def boundary():
    result = {}
    for i, name in enumerate(("n01", "n02", "n03"), 1):
        result[name] = {
            "process_id": i,
            "control": dict.fromkeys(("stream_bytes_sent", "stream_bytes_received",
                                      "requests_started", "requests_received"), 0),
            "operations": {kind: dict.fromkeys(COUNTERS, 0) for kind in PAYMENT_OPERATIONS},
            "durability": {kind: dict.fromkeys(DURABILITY, 0) for kind in OPERATIONS},
            "progress": None if name == "n02" else {
                "evidence_msat": 100, "authorized_sat": 32,
                "acknowledged_msat": 32000, "in_flight": False},
        }
    return {"guard": copy.deepcopy(result), "sample": result}


def window(name="idle"):
    before = boundary()
    probes = []
    if name == "steady":
        probes.append({
            "sender": {"stream_id": "a" * 32, "requested_packets": 3200,
                       "submitted_packets": 3200, "submitted_bytes": 3200000,
                       "stopped_reason": None, "elapsed_us": 8000000},
            "receiver": {"stream_id": "a" * 32, "source": "source",
                         "expected_packets": 3200, "payload_bytes": 1000,
                         "unique_packets": 3200, "unique_bytes": 3200000,
                         "missing_packets": 0, "duplicate_packets": 0,
                         "invalid_packets": 0, "latency": None},
            "packets_per_second": 400, "after_sleep_ms": 0,
        })
    # A harmless socket syscall makes this fixture valid for the legacy parser too.
    empty = analyze(['10 write(5, ""..., 16) = 16\n'], storage_paths())
    after = copy.deepcopy(before)
    if probes:
        for key in ("guard", "sample"):
            after[key]["n01"]["progress"]["evidence_msat"] += 3200000 // 1024
    return {
        "workload": name, "probes": probes, "source": "source",
        "offered_elapsed_ms": 8000 if probes else 4000,
        "observation_elapsed_ms": 11000 if probes else 7000,
        "tail_elapsed_ms": 3000, "sampling_elapsed_ms": 0,
        "payment_before": before, "payment_after": after,
        "payment_after_detach": copy.deepcopy(after),
        "trace_lifecycle": {node: {"accepted": True} for node in before["sample"]},
        "storage": {node: copy.deepcopy(empty) for node in before["sample"]},
    }


class StorageWindowTests(unittest.TestCase):
    def test_idle_and_prepaid_delivery_allow_zero_storage_work(self):
        for name, delivered in (("idle", 0), ("steady", 3200000)):
            result = summarize_window(window(name))
            self.assertEqual(result["delivered_bytes"], delivered)
            self.assertEqual(result["file_write_bytes"], 0)
            self.assertEqual(result["payment_updates"], 0)
            self.assertEqual(result["source_usage_msat"], delivered // 1024)
            self.assertFalse(result["timing_comparison"])

    def test_all_attributed_file_categories_are_counted(self):
        record = window("steady")
        paths = ("/tmp/bench-state/wallet/.cashu-private-example",
                 "/tmp/bench-state/receiver/spilman-receiver.sqlite-wal",
                 "/tmp/bench-state/seller/.ledger.tmp")
        record["storage"]["n01"] = analyze(
            [f'10 write(5<{path}>, ""..., 12) = 12\n' for path in paths], storage_paths())
        self.assertEqual(summarize_window(record)["file_write_bytes"], 36)

    def test_lost_data_unpaid_boundary_restart_and_extra_writes_reject(self):
        edits = (
            lambda r: r["probes"][0]["receiver"].update(unique_packets=3199, unique_bytes=3199000, missing_packets=1),
            lambda r: r["probes"][0]["receiver"].update(source="another-source"),
            lambda r: r["probes"][0].update(packets_per_second=100),
            lambda r: r.update(observation_elapsed_ms=10000),
            lambda r: r.update(observation_elapsed_ms=71000),
            lambda r: r.update(sampling_elapsed_ms=60000, observation_elapsed_ms=71000),
            lambda r: r.update(tail_elapsed_ms=60000, observation_elapsed_ms=68000),
            lambda r: r["trace_lifecycle"]["n01"].update(accepted=False),
            lambda r: r["payment_after"]["sample"]["n01"].update(process_id=9),
            lambda r: r["payment_after"]["sample"]["n01"]["progress"].update(in_flight=True),
            lambda r: r["payment_after_detach"]["sample"]["n01"]["control"].update(requests_started=1),
            lambda r: r["storage"]["n01"]["categories"]["wallet_sqlite"].update(write_calls=1),
        )
        for edit in edits:
            record = window("steady")
            edit(record)
            with self.subTest(edit=edit), self.assertRaises((RuntimeError, ValueError)):
                summarize_window(record)

    def test_prepaid_delivery_still_requires_usage_evidence(self):
        record = window("steady")
        record["payment_after"] = copy.deepcopy(record["payment_before"])
        record["payment_after_detach"] = copy.deepcopy(record["payment_before"])
        with self.assertRaisesRegex(RuntimeError, "metered paid usage"):
            summarize_window(record)

    def test_failed_unmatched_file_operation_is_rejected(self):
        record = window("steady")
        record["storage"]["n01"] = analyze(
            ['10 write(5</tmp/unexpected>, ""..., 12) = -1 EIO (Input/output error)\n'], storage_paths())
        with self.assertRaisesRegex(RuntimeError, "unmatched paths"):
            summarize_window(record)

    def test_timing_and_usage_limits_are_inclusive_and_exact(self):
        record = window("steady")
        record.update(tail_elapsed_ms=3250, sampling_elapsed_ms=2000, observation_elapsed_ms=13250)
        self.assertEqual(summarize_window(record)["source_usage_msat"], 3125)
        for field in ("tail_elapsed_ms", "sampling_elapsed_ms"):
            invalid = copy.deepcopy(record)
            invalid[field] += 1
            invalid["observation_elapsed_ms"] += 1
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                summarize_window(invalid)
        for section in ("payment_after", "payment_after_detach"):
            for key in ("guard", "sample"):
                record[section][key]["n01"]["progress"]["evidence_msat"] -= 1
        with self.assertRaisesRegex(RuntimeError, "metered paid usage"):
            summarize_window(record)

    def test_other_durability_work_cannot_escape_capture(self):
        record = window("steady")
        for key in ("guard", "sample"):
            record["payment_after_detach"][key]["n01"]["durability"]["other"]["journal_writes"] = 1
        with self.assertRaisesRegex(RuntimeError, "escaped"):
            summarize_window(record)

    def test_cpu_sample_and_counter_resets_are_rejected(self):
        for key in ("cpu_samples", "journal_writes"):
            record = window("steady")
            for section in ("payment_after", "payment_after_detach"):
                for copy_name in ("guard", "sample"):
                    node = record[section][copy_name]["n01"]
                    node["operations"]["payment_sign"][key] = 1
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                summarize_window(record)
        record = window("steady")
        for copy_name in ("guard", "sample"):
            record["payment_before"][copy_name]["n01"]["durability"]["other"]["journal_writes"] = 1
        with self.assertRaisesRegex(RuntimeError, "counter reset"):
            summarize_window(record)

    def test_idle_file_writes_cannot_be_subtracted_as_background(self):
        record = window()
        record["storage"]["n02"]["categories"]["receiver_sqlite"].update(write_calls=1, write_bytes=16)
        with self.assertRaises((RuntimeError, ValueError)):
            summarize_window(record)

    def test_idle_usage_is_reported_without_payment_or_storage_subtraction(self):
        record = window()
        for section in ("payment_after", "payment_after_detach"):
            for key in ("guard", "sample"):
                record[section][key]["n01"]["progress"]["evidence_msat"] += 1
        result = summarize_window(record)
        self.assertEqual(result["source_usage_msat"], 1)
        self.assertEqual(result["payment_updates"], 0)
        self.assertEqual(result["file_write_bytes"], 0)
        for section in ("payment_after", "payment_after_detach"):
            for key in ("guard", "sample"):
                record[section][key]["n01"]["control"]["requests_started"] = 1
        with self.assertRaisesRegex(RuntimeError, "idle payment/storage work"):
            summarize_window(record)


class StorageMatrixTests(unittest.TestCase):
    def test_configuration_changes_only_cadence_and_matched_tariff(self):
        service = StorageCadenceRun.__new__(StorageCadenceRun)
        service.delay = 2000
        service.topology = Mock(ethernet_interfaces=Mock(return_value=["eth-test"]))
        config = service.profile_config("n01", "http://127.0.0.1:1234")
        self.assertEqual(config["payment_cadence"], {"max_delay_ms": 2000, "unpaid_percent": 50})
        self.assertEqual(config["terms"]["controller"]["channel_capacity_sat"], 32)
        self.assertEqual(config["terms"]["controller"]["max_wallet_spend_sat"], 128)
        self.assertIsNone(config["terms"]["controller"]["renewal"])
        self.assertEqual(config["terms"]["fee_msat_per_kib"], 1)
        self.assertEqual(config["terms"]["quote_max_units"], 16 * 1024 * 1024)

    def test_failed_trial_stops_before_new_accounts_or_funding(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(output=Path(temporary) / "matrix", pilot=False)
            with patch("sim.storage_cadence.StorageCadenceRun") as runner, \
                    patch("sim.storage_cadence.signal.alarm"), self.assertRaises(RuntimeError):
                runner.return_value.run.side_effect = RuntimeError("uncertain collection")
                run(args)
            self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
