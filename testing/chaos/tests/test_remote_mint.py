"""Mint ownership, terminal exit proof, and uncertain monetary controls."""

import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import mint_host
from sim.remote_mint import RemoteMint


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "requires Linux pidfds")
class MintHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "mint.json"
        self.state = self.root / "state"
        mint_host.save(self.config, {"state_directory": str(self.state),
                                   "bind": "192.0.2.10:0", "max_issued_sat": 512})
        binary = Path(sys.executable).resolve()
        self.owner = self.root / "owner.json"
        mint_host.save(self.owner, {"binary": str(binary), "config": str(self.config),
                                  "binary_sha256": mint_host.digest(binary),
                                  "config_sha256": mint_host.digest(self.config),
                                  "address": "192.0.2.10"})
        self.host = mint_host.MintHost(self.owner)
        self.report = {"test_only": True, "url": "http://192.0.2.10:45678",
                       "issued_sat": 0, "collected_sat": 0, "external_funding_sat": 0,
                       "total_accounted_sat": 0, "conserved": True}
        self.host.control = Mock(side_effect=lambda _body: dict(self.report))
        self.thread = None
        self.info = None
        self.errors = []

    def start(self, exit_code=0):
        # A real supervised Linux child exercises pidfd, identity, signal and
        # clean-exit checks; only the separate mint wallet CLI is substituted.
        child_ready = self.root / "child-ready"
        code = ("import signal,sys,time; from pathlib import Path; "
                f"signal.signal(signal.SIGTERM,lambda *_:sys.exit({exit_code})); "
                f"Path({str(child_ready)!r}).touch(); time.sleep(300)")
        self.host.argv = [str(self.host.binary), "-c", code]

        def serve():
            try:
                self.host.serve()
            except BaseException as error:
                self.errors.append(error)

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 5
        while not (child_ready.exists() and (self.root / "process.json").exists()):
            if self.errors or time.monotonic() >= deadline:
                self.fail(f"test child failed to start: {self.errors}")
            time.sleep(0.01)
        self.info = mint_host.read(self.root / "process.json")
        self.state.mkdir()
        mint_host.save(self.state / "ready.json", {"test_only": True,
                       "url": self.report["url"], "max_issued_sat": 512})

    def tearDown(self):
        if self.info:
            try:
                if mint_host.process_start(self.info["pid"]) == self.info["start_ticks"]:
                    os.kill(self.info["pid"], signal.SIGTERM)
            except FileNotFoundError:
                pass
        if self.thread:
            self.thread.join(5)
            self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.errors, [])
        self.temp.cleanup()

    def test_terminal_report_requires_fresh_accounting_and_clean_process_exit(self):
        self.start()
        self.assertFalse((self.root / "stopped.json").exists())
        report = self.host.finish()
        self.assertTrue(report["stopped"])
        self.assertTrue(report["conserved"])
        self.assertEqual(mint_host.read(self.root / "exit.json")["exit_code"], 0)
        self.assertEqual(self.host.finish(), report)
        self.assertEqual(self.host.control.call_count, 1)
        with self.assertRaisesRegex(RuntimeError, "fenced"):
            self.host.request({"type": "issue", "id": "late", "amount_sat": 128})
        with self.assertRaisesRegex(RuntimeError, "never restart"):
            self.host.serve()

    def test_outstanding_or_unconserved_funds_leave_process_and_controls_available(self):
        self.start()
        self.report.update(issued_sat=128, external_funding_sat=128, total_accounted_sat=128)
        for collected, conserved in ((0, True), (128, False)):
            self.report.update(collected_sat=collected, conserved=conserved)
            self.assertTrue(self.host.finish()["retained_for_recovery"])
            self.assertFalse((self.root / "closing.json").exists())
            self.assertEqual(self.host.request({"type": "report"}), self.report)

    def test_uncertain_issue_has_one_submission_and_retains_attempt(self):
        self.start()
        self.host.control.side_effect = RuntimeError("lost response")
        body = {"type": "issue", "id": "phone", "amount_sat": 128}
        with self.assertRaisesRegex(RuntimeError, "lost response"):
            self.host.request(body)
        with self.assertRaises(FileExistsError):
            self.host.request(body)
        self.assertEqual(self.host.control.call_count, 1)
        self.assertTrue((self.root / "issue-phone.json").exists())

    def test_uncertain_collection_is_not_resubmitted_or_written_to_intent(self):
        self.start()
        self.host.control.side_effect = RuntimeError("lost response")
        body = {"type": "collect", "token": "private-test-token"}
        with self.assertRaises(RuntimeError):
            self.host.request(body)
        with self.assertRaises(FileExistsError):
            self.host.request(body)
        self.assertEqual(self.host.control.call_count, 1)
        intent = next(self.root.glob("collect-*.json"))
        self.assertNotIn(body["token"], intent.read_text())
        self.assertEqual(intent.stat().st_mode & 0o777, 0o600)

    def test_changed_pid_start_or_command_is_never_signalled(self):
        self.start()
        for change in ("start", "argv"):
            with self.subTest(change=change):
                if change == "start":
                    (self.root / "process.json").write_text(json.dumps({**self.info, "start_ticks": "0"}))
                else:
                    (self.root / "process.json").write_text(json.dumps(self.info))
                    self.host.argv.append("foreign")
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    self.host.finish()
                self.assertEqual(mint_host.process_start(self.info["pid"]), self.info["start_ticks"])
        self.host.control.assert_not_called()

    def test_changed_config_is_rejected_before_mint_control(self):
        self.start()
        self.config.write_text('{}')
        with self.assertRaisesRegex(RuntimeError, "configuration changed"):
            self.host.request({"type": "report"})
        self.host.control.assert_not_called()

    def test_wrong_endpoint_or_invalid_accounting_cannot_authorize_stop(self):
        self.start()
        original = dict(self.report)
        for mutation in ({"url": "http://192.0.2.11:45678"}, {"issued_sat": True},
                         {"issued_sat": 513}, {"collected_sat": 1}, {"test_only": False}):
            self.report.clear()
            self.report.update(original, **mutation)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                self.host.finish()
            self.assertFalse((self.root / "closing.json").exists())

    def test_unclean_child_exit_never_produces_terminal_proof(self):
        self.start(exit_code=7)
        with self.assertRaisesRegex(RuntimeError, "did not exit cleanly"):
            self.host.finish()
        self.assertTrue((self.root / "closing.json").exists())
        self.assertFalse((self.root / "stopped.json").exists())

    def test_timed_out_stop_fences_new_money_controls_and_retains_evidence(self):
        self.start()
        from unittest.mock import patch
        with patch.object(signal, "pidfd_send_signal"), self.assertRaisesRegex(RuntimeError, "uncertain"):
            self.host.finish(stop_seconds=0)
        self.assertTrue((self.root / "closing.json").exists())
        self.assertFalse((self.root / "stopped.json").exists())
        with self.assertRaisesRegex(RuntimeError, "fenced"):
            self.host.request({"type": "collect", "token": "fixture"})

    def test_lost_completion_after_clean_exit_recovers_without_controlling_a_pid(self):
        self.start()
        from unittest.mock import patch
        save = mint_host.save

        def interrupted(path, value):
            if path.name == "stopped.json":
                raise RuntimeError("lost completion checkpoint")
            return save(path, value)

        with patch.object(mint_host, "save", side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, "lost completion"):
                self.host.finish()
        self.assertEqual(mint_host.read(self.root / "exit.json")["exit_code"], 0)
        with patch.object(signal, "pidfd_send_signal") as send:
            recovered = self.host.finish()
            send.assert_not_called()
        self.assertTrue(recovered["stopped"])
        self.assertEqual(self.host.control.call_count, 1)


class RemoteMintTests(unittest.TestCase):
    def test_refuses_wrong_architecture_and_excessive_test_funding(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            binary = root / "mint"
            binary.write_bytes(b"not an ARM64 ELF")
            args = ({"host": "lab", "state_parent": "/tmp/bench"}, binary,
                    "123456789abc", root, "192.0.2.10")
            with self.assertRaisesRegex(ValueError, "ELF64"):
                RemoteMint(*args)
            with self.assertRaisesRegex(ValueError, "capped"):
                RemoteMint(*args, max_issued_sat=513)

    def test_start_failure_does_not_retry_or_start_another_mint(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            binary = root / "mint"
            binary.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\xb7\x00")
            mint = RemoteMint({"host": "lab", "state_parent": "/tmp/bench"}, binary,
                              "123456789abc", root, "192.0.2.10")
            mint.remote = Mock(side_effect=RuntimeError("lost SSH"))
            with self.assertRaisesRegex(RuntimeError, "lost SSH"):
                mint.start()
            with self.assertRaisesRegex(RuntimeError, "already attempted"):
                mint.start()
            self.assertEqual(mint.remote.call_count, 1)


if __name__ == "__main__":
    unittest.main()
