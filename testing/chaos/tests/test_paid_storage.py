"""Capture acceptance and retention of accounts after an uncertain failure."""

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_relay import PaidRelayRun
from sim.paid_storage import StorageRun, storage_paths, validate_storage
from storage_trace import analyze


def captures():
    summaries = {}
    for node in ("n01", "n02", "n03"):
        path = ("/tmp/bench-state/receiver/spilman-receiver.sqlite-wal" if node == "n02"
                else "/tmp/bench-state/wallet/.cashu-private-example")
        summaries[node] = analyze([f'10 write(4<{path}>, ""..., 16) = 16\n'], storage_paths())
    lifecycles = {node: {"accepted": True} for node in summaries}
    return summaries, lifecycles


class StorageAcceptanceTests(unittest.TestCase):
    def test_both_senders_and_receiver_are_observed_without_funding_writes(self):
        summaries, lifecycles = captures()
        validate_storage(summaries, lifecycles)
        self.assertTrue(all(value["capture_complete"] is None for value in summaries.values()))

    def test_missing_capture_or_storage_failure_rejects(self):
        edits = (
            lambda s, l: s.pop("n03"),
            lambda s, l: l.pop("n02"),
            lambda s, l: l["n01"].update(accepted=False),
            lambda s, l: s["n03"]["categories"]["sdk_private_snapshot"].update(write_bytes=0),
            lambda s, l: s["n02"]["categories"]["receiver_sqlite"].update(write_bytes=0),
            lambda s, l: s["n01"]["categories"]["sdk_private_snapshot"].update(write_errors=1),
            lambda s, l: s["n02"]["categories"]["receiver_sqlite"].update(sync_errors=1),
            lambda s, l: s["n01"]["categories"]["directory_syncs"].update(sync_errors=1),
            lambda s, l: s["n03"]["categories"]["wallet_sqlite"].update(write_calls=1),
        )
        for edit in edits:
            with self.subTest(edit=edit):
                summaries, lifecycles = captures()
                edit(summaries, lifecycles)
                with self.assertRaises(RuntimeError):
                    validate_storage(summaries, lifecycles)

    def test_file_categories_do_not_hide_logs_directories_or_unmatched_paths(self):
        paths = ("/tmp/bench-state/wallet", "/tmp/bench-state/seller/.ledger.tmp",
                 "/run/bench/process.log", "/tmp/unexpected")
        lines = [f'10 write(4<{path}>, ""..., 2) = 2\n' for path in paths]
        result = analyze(lines, storage_paths())["categories"]
        for category in ("directory_syncs", "relay_journals", "process_log", "unmatched"):
            self.assertEqual(result[category]["write_bytes"], 2)


class PaymentBoundaryTests(unittest.TestCase):
    def fixture(self):
        run = StorageRun.__new__(StorageRun)
        run.nodes = dict.fromkeys(("n01", "n02", "n03"))
        statuses, finances = {}, {}
        for index, node in enumerate(run.nodes, 1):
            channels = {} if node == "n02" else {
                node: {"evidence_msat": 999, "authorized_sat": 1,
                       "acknowledged_msat": 1000, "in_flight": False}}
            finances[node] = {"signed": dict.fromkeys(channels, 1)}
            statuses[node] = {
                "last_error": None, "payment_progress": channels,
                "measurements": {"version": 1, "process_id": index, "operations": {
                    name: {"spans": 1, "journal_commits": 1}
                    for name in ("payment_usage", "payment_update", "payment_sign")}},
                "control_traffic": [{"service_port": 44743, "counters": dict.fromkeys((
                    "stream_bytes_sent", "stream_bytes_received", "requests_started", "requests_received"), 1)}],
            }
        run.ctl = lambda node, _kind: statuses[node]
        return run, statuses, finances

    def test_reconciled_credit_and_stable_double_sample_are_retained(self):
        run, _, finances = self.fixture()
        result = run.boundary(finances)
        self.assertEqual(result["guard"], result["sample"])
        self.assertEqual(result["sample"]["n01"]["progress"]["acknowledged_msat"], 1000)

    def test_pending_unacknowledged_or_underpaid_usage_cannot_end_capture(self):
        for change in ({"in_flight": True}, {"acknowledged_msat": None},
                       {"evidence_msat": 1001}, {"authorized_sat": 2}):
            run, statuses, finances = self.fixture()
            statuses["n03"]["payment_progress"]["n03"].update(change)
            with patch("sim.paid_storage.eventually", side_effect=lambda _d, f, _s: f()):
                self.assertIsNone(run.boundary(finances))

    def test_payment_change_between_passes_does_not_count_as_quiet(self):
        run, statuses, finances = self.fixture()
        calls = 0

        def status(node, _kind):
            nonlocal calls
            calls += 1
            result = copy.deepcopy(statuses[node])
            if calls > 3:
                result["measurements"]["operations"]["payment_update"]["spans"] += 1
            return result

        run.ctl = status
        with patch("sim.paid_storage.eventually", side_effect=lambda _d, f, _s: f()):
            self.assertIsNone(run.boundary(finances))


class AccountRetentionTests(unittest.TestCase):
    def run_failure(self, root, funded, mint=None, completed=False):
        run = PaidRelayRun.__new__(PaidRelayRun)
        run.root = root
        run.output_created = True
        run.funding_started = funded
        run.evidence = {"phases": [], "mint": copy.deepcopy(mint or {})}
        run.resources = Mock(created=[], cleanup=Mock(return_value=[]))
        run.veth = Mock()
        run.setup = Mock()
        run.exercise = Mock(side_effect=None if completed else RuntimeError("injected capture failure"))
        with patch("sim.paid_relay.signal.alarm"), self.assertRaises(RuntimeError):
            run.run()
        self.assertFalse(run.evidence["passed"])
        self.assertTrue((root / "result.json").is_file())
        return run

    def test_uncertain_funding_retains_exact_original_resources(self):
        for mint in ({}, {"conserved": True, "issued_sat": 384, "collected_sat": 383},
                     {"conserved": False, "issued_sat": 384, "collected_sat": 384}):
            with tempfile.TemporaryDirectory() as directory:
                run = self.run_failure(Path(directory), True, mint)
                self.assertTrue(run.evidence["resources_retained"])
                run.resources.cleanup.assert_not_called()
                run.veth.teardown_all.assert_not_called()

    def test_failed_capture_can_clean_after_proven_collection(self):
        mint = {"conserved": True, "issued_sat": 384, "collected_sat": 384}
        with tempfile.TemporaryDirectory() as directory:
            run = self.run_failure(Path(directory), True, mint)
            self.assertFalse(run.evidence["resources_retained"])
            run.resources.cleanup.assert_called_once()
            run.veth.teardown_all.assert_called_once()

    def test_failure_before_issuance_cleans_unfunded_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.run_failure(Path(directory), False)
            self.assertFalse(run.evidence["resources_retained"])
            run.resources.cleanup.assert_called_once()

    def test_returning_without_collection_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.run_failure(Path(directory), True, completed=True)
            self.assertTrue(run.evidence["resources_retained"])
            run.resources.cleanup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
