"""Capture acceptance and retention of accounts after an uncertain failure."""

import copy
from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_relay import PaidRelayRun
from sim.paid_storage import StorageRun, storage_paths, validate_storage
from storage_trace import analyze
from validation import COUNTERS, OPERATIONS


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

    def test_optional_activity_still_requires_complete_successful_lifecycles(self):
        summaries = {node: analyze([], storage_paths(), allow_empty=True)
                     for node in ("n01", "n02", "n03")}
        lifecycles = {node: {"accepted": True} for node in summaries}
        validate_storage(summaries, lifecycles, require_activity=False)
        with self.assertRaises(RuntimeError):
            validate_storage(summaries, lifecycles)
        edits = (
            lambda s, l: l.pop("n03"),
            lambda s, l: l["n01"].update(accepted=False),
            lambda s, l: s["n01"]["categories"]["sdk_private_snapshot"].update(write_errors=1),
            lambda s, l: s["n02"]["categories"]["receiver_sqlite"].update(sync_errors=1),
            lambda s, l: s["n03"]["categories"]["wallet_sqlite"].update(write_calls=1),
        )
        for edit in edits:
            with self.subTest(edit=edit):
                current, receipts = copy.deepcopy(summaries), copy.deepcopy(lifecycles)
                edit(current, receipts)
                with self.assertRaises(RuntimeError):
                    validate_storage(current, receipts, require_activity=False)


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
                    name: dict.fromkeys(COUNTERS, 1) for name in OPERATIONS}},
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

    def test_strict_boundary_samples_each_node_twice_without_retry(self):
        run, statuses, finances = self.fixture()
        run.ctl = Mock(side_effect=lambda node, _kind: statuses[node])
        with patch("sim.paid_storage.eventually") as retry:
            result = run.boundary(finances, wait=False)
        retry.assert_not_called()
        self.assertEqual(run.ctl.call_count, 6)
        self.assertEqual(result["guard"], result["sample"])

    def test_strict_boundary_retains_background_usage_with_unchanged_credit(self):
        run, statuses, finances = self.fixture()
        calls = []
        def status(node, _kind):
            calls.append(node)
            result = copy.deepcopy(statuses[node])
            if len(calls) > 3 and node == "n01":
                result["payment_progress"][node]["evidence_msat"] += 1
            return result
        run.ctl = status
        result = run.boundary(finances, wait=False)
        self.assertEqual(result["guard"]["n01"]["progress"]["evidence_msat"], 999)
        self.assertEqual(result["sample"]["n01"]["progress"]["evidence_msat"], 1000)
        self.assertEqual(calls, list(run.nodes) * 2)

    def test_strict_boundary_rejects_unreconciled_or_changed_double_sample(self):
        for pending in (False, True):
            with self.subTest(pending=pending):
                run, statuses, finances = self.fixture()
                calls = []

                def status(node, _kind):
                    calls.append(node)
                    result = copy.deepcopy(statuses[node])
                    if pending and node == "n01":
                        result["payment_progress"][node]["in_flight"] = True
                    elif not pending and len(calls) > 3:
                        result["measurements"]["operations"]["payment_update"]["spans"] += 1
                    return result

                run.ctl = status
                with patch("sim.paid_storage.eventually") as retry, self.assertRaises(RuntimeError):
                    run.boundary(finances, wait=False)
                retry.assert_not_called()
                self.assertEqual(calls, list(run.nodes) * 2)

    def test_strict_boundary_includes_durable_work_in_every_operation_bucket(self):
        for operation in ("other", "window_checkpoint"):
            with self.subTest(operation=operation):
                run, statuses, finances = self.fixture()
                calls = []

                def status(node, _kind):
                    calls.append(node)
                    result = copy.deepcopy(statuses[node])
                    if len(calls) > 3:
                        result["measurements"]["operations"][operation]["journal_writes"] += 1
                    return result

                run.ctl = status
                with self.assertRaises(RuntimeError):
                    run.boundary(finances, wait=False)
                self.assertEqual(calls, list(run.nodes) * 2)

    def test_durability_requires_all_original_operation_buckets_and_natural_counters(self):
        run, _, finances = self.fixture()
        boundary = run.boundary(finances, wait=False)
        for value in boundary["sample"].values():
            self.assertEqual(set(value["durability"]), OPERATIONS)
            for counters in value["durability"].values():
                self.assertEqual(set(counters), {"journal_bytes_written", "journal_writes",
                                                 "journal_syncs", "journal_commits"})
        edits = (
            lambda ops: ops.pop("other"),
            lambda ops: ops.update(unknown=dict(ops["other"])),
            lambda ops: ops["other"].pop("journal_bytes_written"),
            lambda ops: ops["window_checkpoint"].update(journal_writes=-1),
            lambda ops: ops["window_checkpoint"].update(journal_syncs=True),
            lambda ops: ops["other"].update(journal_commits=None),
        )
        for edit in edits:
            with self.subTest(edit=edit):
                run, statuses, finances = self.fixture()
                edit(statuses["n02"]["measurements"]["operations"])
                with self.assertRaises(ValueError):
                    run.boundary(finances, wait=False)


class TraceContextTests(unittest.TestCase):
    @contextmanager
    def fixture(self, empty=False, fail_attach=None, failed_lifecycle=None):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            run = StorageRun.__new__(StorageRun)
            run.root = Path(directory)
            run.nodes = dict.fromkeys(("n01", "n02", "n03"))
            run.containers = {node: node for node in run.nodes}
            run.name = "storage-context-test"
            launched = []
            for node in run.nodes:
                (run.root / node).mkdir()

            def launch(args):
                node = args[2]
                output = run.root / node
                if len(args) == 6:
                    output /= "storage-" + args[-1]
                launched.append(output)
                if node == fail_attach:
                    raise RuntimeError("injected uncertain worker launch")
                path = ("/tmp/bench-state/receiver/spilman-receiver.sqlite-wal" if node == "n02"
                        else "/tmp/bench-state/wallet/.cashu-private-example")
                (output / "storage.trace").write_text(
                    "" if empty else f'10 write(4<{path}>, ""..., 16) = 16\n')
                (output / "storage.ready.json").write_text(json.dumps({"threads_attached": 2}))

            def wait(description, condition, _seconds):
                if description == "bounded tracer detach":
                    self.assertTrue(all((output / "storage.stop").exists() for output in launched))
                    for output in launched:
                        accepted = output.relative_to(run.root).parts[0] != failed_lifecycle
                        (output / "storage.done.json").write_text(json.dumps({"accepted": accepted}))
                return condition()

            stack.enter_context(patch("sim.paid_storage.inspect_owned", side_effect=
                                      lambda _kind, node, _name: {"Id": node}))
            stack.enter_context(patch("sim.paid_storage.docker", side_effect=launch))
            stack.enter_context(patch("sim.paid_storage.eventually", side_effect=wait))
            yield run, launched

    def test_default_capture_attaches_all_before_yield_and_detaches_after_body_failure(self):
        with self.fixture() as (run, launched):
            record = {}
            with self.assertRaisesRegex(RuntimeError, "workload failed"):
                with run.trace(record):
                    self.assertEqual(len(launched), 3)
                    self.assertEqual(set(record["trace_ready"]), set(run.nodes))
                    self.assertFalse(any((path / "storage.stop").exists() for path in launched))
                    raise RuntimeError("workload failed")
            self.assertEqual(launched, [run.root / node for node in run.nodes])
            self.assertTrue(record["storage_accepted"])
            self.assertEqual(set(record["storage"]), set(run.nodes))

    def test_named_captures_are_separate_and_allow_complete_idle_evidence(self):
        with self.fixture(empty=True) as (run, _):
            for capture in ("idle", "bursty", "steady", "high_rate"):
                record = {}
                with run.trace(record, capture=capture, require_activity=False):
                    pass
                self.assertTrue(record["storage_accepted"])
                self.assertEqual([value["syscalls_observed"] for value in record["storage"].values()],
                                 [0, 0, 0])
                self.assertTrue(all((run.root / node / f"storage-{capture}" / "storage.stop").exists()
                                    for node in run.nodes))

    def test_legacy_empty_capture_still_rejects_when_activity_is_optional(self):
        with self.fixture(empty=True) as (run, _), self.assertRaises(ValueError):
            with run.trace({}, require_activity=False):
                pass

    def test_eventfd_detach_is_allowed_only_after_every_worker_lifecycle_passes(self):
        for failed in (None, "n02"):
            with self.subTest(failed=failed), self.fixture(failed_lifecycle=failed) as (run, launched):
                record = {}
                with patch("sim.paid_storage.analyze", wraps=analyze) as parser:
                    def workload():
                        with run.trace(record, capture="steady"):
                            for output in launched:
                                with (output / "storage.trace").open("a") as stream:
                                    stream.write('20 write(4<anon_inode:[eventfd]>, ""..., 8 <detached ...>\n')
                    if failed:
                        with self.assertRaisesRegex(RuntimeError, "tracer lifecycle failed"):
                            workload()
                        parser.assert_not_called()
                        self.assertFalse(record["storage_accepted"])
                    else:
                        workload()
                        self.assertEqual(parser.call_count, 3)
                        self.assertTrue(record["storage_accepted"])
                        for value in record["storage"].values():
                            self.assertEqual(value["detached_eventfd_calls"], 1)
                            self.assertEqual(value["syscalls_observed"], 1)

    def test_uncertain_attachment_still_requests_stop_for_every_started_worker(self):
        with self.fixture(fail_attach="n02") as (run, launched):
            with self.assertRaises((RuntimeError, OSError)):
                with run.trace({}):
                    self.fail("workload must not start after an uncertain attachment")
            self.assertEqual(len(launched), 2)
            self.assertTrue(all((output / "storage.stop").exists() for output in launched))

    def test_stop_request_failure_still_detaches_the_other_workers(self):
        with self.fixture() as (run, launched):
            record = {}
            with self.assertRaisesRegex(RuntimeError, "tracer lifecycle failed"):
                with run.trace(record):
                    # A duplicate request must reject without skipping the other workers.
                    (launched[0] / "storage.stop").touch()
            self.assertTrue(all((output / "storage.stop").exists() for output in launched))
            self.assertEqual(set(record["trace_lifecycle"]), set(run.nodes))
            self.assertFalse(record["storage_accepted"])

    def test_active_capture_cannot_be_replaced_by_a_nested_one(self):
        with self.fixture() as (run, launched):
            outer = {}
            with run.trace(outer, capture="steady"):
                with self.assertRaisesRegex(RuntimeError, "already active"):
                    with run.trace({}, capture="idle"):
                        self.fail("nested capture cannot launch")
                self.assertEqual(len(launched), 3)
            self.assertTrue(outer["storage_accepted"])

    def test_capture_names_are_bounded_and_reuse_does_not_overwrite_evidence(self):
        with self.fixture() as (run, launched):
            for capture in ("../escape", "idle/extra", "", "storage", "IDLE"):
                with self.subTest(capture=capture), self.assertRaises(ValueError):
                    with run.trace({}, capture=capture):
                        self.fail("invalid name must reject before attachment")
            self.assertEqual(launched, [])
            with run.trace({}, capture="bursty"):
                pass
            trace = run.root / "n01" / "storage-bursty" / "storage.trace"
            original = trace.read_bytes()
            with self.assertRaises(FileExistsError):
                with run.trace({}, capture="bursty"):
                    self.fail("existing capture must not be reused")
            self.assertEqual(trace.read_bytes(), original)


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
