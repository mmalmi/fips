"""Exercise the bounded worker without attaching to a host process."""

from contextlib import ExitStack, contextmanager
import io
import json
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import storage_worker as worker


TRACE = '11 write(3</tmp/bench-state/wallet/.cashu-private-test>, ""..., 2) = 2\n'


class WorkerTests(unittest.TestCase):
    @contextmanager
    def fixture(self, capture=None, payload=TRACE):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            (root / "process.pid").write_text("200")
            output = worker.trace_directory(root, capture)
            if capture is not None:
                output.mkdir()
                # A capture directory must never select the target process.
                (output / "process.pid").write_text("999")
            process = Mock(pid=300, returncode=None)
            process.poll.side_effect = lambda: process.returncode

            def finish(timeout):
                process.returncode = -signal.SIGINT
                return process.returncode

            process.wait.side_effect = finish

            def launch(args, stderr):
                Path(args[args.index("-o") + 1]).write_text(payload)
                return process

            case = SimpleNamespace(root=root, output=output, process=process)
            stack.enter_context(patch.object(worker, "ROOT", root))
            stack.enter_context(patch.object(worker, "os", SimpleNamespace(
                umask=None, pidfd_open=None, close=None)))
            for name, target, options in (
                    ("umask", "os.umask", {}),
                    ("pidfd", "os.pidfd_open", {"return_value": 7, "create": True}),
                    ("close", "os.close", {}),
                    ("alive", "target_alive", {"return_value": True}),
                    ("threads", "tracers", {"side_effect": [[0, 0], [300, 300], [0, 0]]}),
                    ("launch", "subprocess.Popen", {"side_effect": launch}),
                    ("clock", "time.monotonic", {"side_effect": [0, 1, 2]}),
                    ("sleep", "time.sleep", {"side_effect": lambda _delay:
                                             (output / "storage.stop").touch()})):
                setattr(case, name, stack.enter_context(patch("storage_worker." + target, **options)))
            case.run = lambda: worker.main([] if capture is None else [capture])
            case.receipt = lambda: json.loads((output / "storage.done.json").read_text())
            yield case

    def test_legacy_capture_checks_target_and_detaches_without_changing_paths(self):
        with self.fixture() as case:
            self.assertEqual(case.run(), 0)
            receipt = case.receipt()
            self.assertTrue(receipt["accepted"])
            self.assertTrue(receipt["requested_stop"])
            self.assertTrue(receipt["target_alive"])
            self.assertTrue(receipt["detached"])
            case.pidfd.assert_called_once_with(200)
            case.close.assert_called_once_with(7)
            case.process.send_signal.assert_called_once_with(signal.SIGINT)
            command = case.launch.call_args[0][0]
            self.assertEqual(command[-2:], ["-p", "200"])
            self.assertEqual(Path(command[command.index("-o") + 1]), case.root / "storage.trace")
            self.assertIn("--string-limit=0", command)
            self.assertFalse(any(arg.startswith(("--read=", "--write=")) for arg in command))

    def test_named_empty_capture_keeps_original_process_target_and_lifecycle_checks(self):
        for capture in worker.CAPTURES:
            with self.subTest(capture=capture), self.fixture(capture, payload="") as case:
                self.assertEqual(case.run(), 0)
                self.assertEqual(case.receipt()["trace_bytes"], 0)
                case.pidfd.assert_called_once_with(200)
                self.assertTrue(all(call.args == (200, 7) for call in case.alive.call_args_list))
                self.assertFalse((case.root / "storage.trace").exists())
                ready = json.loads((case.output / "storage.ready.json").read_text())
                self.assertEqual(ready, {"target_pid": 200, "tracer_pid": 300, "threads_attached": 2})

    def test_legacy_empty_capture_remains_rejected(self):
        with self.fixture(payload="") as case:
            self.assertEqual(case.run(), 1)
            self.assertFalse(case.receipt()["accepted"])

    def test_bad_capture_name_rejects_before_inspecting_or_tracing_a_process(self):
        with self.fixture() as case, patch("sys.stderr", new=io.StringIO()):
            for name in ("../outside", "idle/child", "", "IDLE", "unknown"):
                with self.subTest(name=name), self.assertRaises(SystemExit):
                    worker.main([name])
            case.pidfd.assert_not_called()
            case.launch.assert_not_called()
            self.assertFalse((case.output / "storage.done.json").exists())

    def test_existing_trace_or_stderr_is_never_truncated(self):
        for filename in ("storage.trace", "storage.stderr"):
            with self.subTest(filename=filename), self.fixture("steady") as case:
                original = case.output / filename
                original.write_text("prior evidence")
                self.assertEqual(case.run(), 1)
                case.launch.assert_not_called()
                self.assertEqual(original.read_text(), "prior evidence")
                self.assertFalse(case.receipt()["accepted"])

    def test_empty_named_capture_cannot_hide_attachment_continuity_or_detach_failure(self):
        for stage in ("identity", "preexisting_tracer", "attachment", "continuity", "detach",
                      "stderr", "exit"):
            with self.subTest(stage=stage), self.fixture("idle", payload="") as case:
                if stage == "identity":
                    case.alive.return_value = False
                elif stage == "preexisting_tracer":
                    case.threads.side_effect = [[88]]
                elif stage == "attachment":
                    case.threads.side_effect = [[0, 0], [300, 0]]
                    case.clock.side_effect = [0, 10]
                elif stage == "continuity":
                    case.alive.side_effect = [True, True, False]
                elif stage == "detach":
                    case.threads.side_effect = [[0, 0], [300, 300], [300, 0]]
                elif stage == "stderr":
                    def noisy(args, stderr):
                        stderr.write("tracer error")
                        return case.process
                    case.launch.side_effect = noisy
                else:
                    def failed_exit(timeout):
                        case.process.returncode = 1
                        return 1
                    case.process.wait.side_effect = failed_exit
                self.assertEqual(case.run(), 1)
                self.assertFalse(case.receipt()["accepted"])
                case.close.assert_called_once_with(7)

    def test_capture_deadline_and_size_limit_still_detach_and_reject(self):
        for bound in ("deadline", "bytes"):
            with self.subTest(bound=bound), self.fixture("high_rate") as case:
                if bound == "deadline":
                    case.clock.side_effect = [0, 1, 91]
                else:
                    original_launch = case.launch.side_effect

                    def oversized(args, stderr):
                        process = original_launch(args, stderr)
                        with (case.output / "storage.trace").open("r+b") as stream:
                            stream.truncate(64 * 1024 * 1024 + 1)
                        return process

                    case.launch.side_effect = oversized
                self.assertEqual(case.run(), 1)
                self.assertFalse(case.receipt()["accepted"])
                case.process.send_signal.assert_called_once_with(signal.SIGINT)
                case.process.wait.assert_called_once_with(timeout=10)

    def test_process_identity_requires_exact_executable_command_and_live_pidfd(self):
        for change in (None, "exe", "cmdline", "pidfd"):
            with self.subTest(change=change), ExitStack() as stack:
                stack.enter_context(patch.object(worker.select, "select", return_value=
                                              ([7] if change == "pidfd" else [], [], [])))
                link = stack.enter_context(patch.object(worker.os, "readlink", return_value=
                              "/other/process" if change == "exe" else "/opt/bench/fips-relay"))
                command = stack.enter_context(patch.object(Path, "read_bytes", return_value=
                              b"other\0" if change == "cmdline" else worker.EXPECTED))
                self.assertEqual(worker.target_alive(200, 7), change is None)
                if change != "pidfd":
                    link.assert_called_once_with(Path("/proc/200/exe"))
                if change is None:
                    command.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
