"""Bounded crash ownership checks; Linux cases run real guarded shell and children."""

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.wifi_measurements import process_identity
from sim.wifi_restart import crash_profile
from tests import test_wifi_profiles as profiles


def sample(pid=123, start=456, npub="candidate"):
    return {"npub": npub, "host_process": {"pid": pid, "start_ticks": start}}


class CrashResponseTests(unittest.TestCase):
    def setUp(self):
        self.node = SimpleNamespace(npub="candidate", temporary="/tmp/owned",
                                    binary="/tmp/owned/relay", config="/tmp/owned/config.json",
                                    guarded=Mock(return_value=b"123\0" + b"456\0zombie\0"))

    def test_receipt_requires_exact_stopped_epoch(self):
        self.assertEqual(crash_profile(self.node, sample()),
                         {"pid": 123, "start_ticks": 456, "stopped": True, "state": "zombie"})
        self.node.guarded.assert_called_once()

    def test_invalid_sample_never_dispatches(self):
        for changed in (sample(pid=1), sample(pid=True), sample(pid="123"), sample(start=0),
                        sample(start=True), sample(start="456"), sample(npub="other"), {}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                crash_profile(self.node, changed)
        self.node.guarded.assert_not_called()

    def test_ambiguous_reply_or_transport_failure_is_not_replayed(self):
        for raw in (b"", b"123\0" + b"457\0gone\0", b"123\0" + b"456\0alive\0",
                    b"123\0" + b"456\0gone\0extra\0"):
            self.node.guarded.reset_mock()
            self.node.guarded.return_value = raw
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                crash_profile(self.node, sample())
            self.node.guarded.assert_called_once()
        self.node.guarded.reset_mock()
        self.node.guarded.side_effect = TimeoutError("unknown dispatch outcome")
        with self.assertRaises(TimeoutError):
            crash_profile(self.node, sample())
        self.node.guarded.assert_called_once()


@unittest.skipUnless(sys.platform == "linux" and shutil.which("flock"),
                     "crash lifecycle checks need Linux procfs and flock")
class CrashShellTests(unittest.TestCase):
    local = profiles.ProfileGuardTests.local
    start_guard = profiles.ProfileGuardTests.start_guard
    tearDown = profiles.ProfileGuardTests.tearDown
    wait_file = profiles.ProfileGuardTests.wait_file
    launch = profiles.ProfileGuardTests.launch

    def setUp(self):
        profiles.ProfileGuardTests.setUp(self)
        staged = self.remote / "fips-relay"
        shutil.copy2(sys.executable, staged)
        self.node.binary = self.aux.binary = str(staged)
        self.node.state = str(self.remote / "accounts" / "state")
        self.node.npub, self.aux.npub = "primary", "auxiliary"
        self.guard.write_bytes(self.node.guard_script())
        for node in (self.node, self.aux):
            Path(node.config).write_text("persistent configuration")
            Path(node.state).mkdir(parents=True)
            (Path(node.state) / "account").write_text("retained account")
        self.guard_process = self.start_guard()

    def observed(self, node, child):
        pid, ticks = process_identity(Path(f"/proc/{child.pid}/stat").read_text())
        return sample(pid, ticks, node.npub)

    def retained(self):
        paths = [self.guard, self.remote / "fips-relay", self.remote / "mesh.sh",
                 self.remote / "active", self.remote / "guard-ready", self.mesh_state,
                 self.tables]
        paths += [Path(n.config) for n in (self.node, self.aux)]
        paths += [Path(n.state) / "account" for n in (self.node, self.aux)]
        paths += [Path(n.temporary) / "process.pid" for n in (self.node, self.aux)]
        paths += [self.remote / name for name in ("candidate-forced-stop", "candidate-stop-failed")]
        return {str(path): path.read_bytes() if path.exists() else None for path in paths}

    def test_crash_only_sampled_profile_and_preserve_recovery_assets(self):
        primary, auxiliary = self.launch(self.node), self.launch(self.aux)
        for name in ("candidate-forced-stop", "candidate-stop-failed"):
            (self.remote / name).write_text("existing failure evidence")
        before = self.retained()
        observed = self.observed(self.aux, auxiliary)
        receipt = crash_profile(self.aux, observed)
        self.assertEqual(receipt["pid"], auxiliary.pid)
        self.assertEqual(receipt["start_ticks"], observed["host_process"]["start_ticks"])
        self.assertTrue(receipt["stopped"])
        self.assertEqual(auxiliary.wait(timeout=1), -9)
        self.assertIsNone(primary.poll())
        self.assertIsNone(self.guard_process.poll())
        self.assertEqual(self.retained(), before)
        self.assertFalse(self.mesh_log.exists())
        with self.assertRaises(RuntimeError):
            crash_profile(self.aux, observed)
        self.assertIsNone(primary.poll())

    def test_wrong_start_or_stored_pid_cannot_kill_candidate(self):
        child = self.launch(self.node)
        observed = self.observed(self.node, child)
        wrong = copy.deepcopy(observed)
        wrong["host_process"]["start_ticks"] += 1
        with self.assertRaises(RuntimeError):
            crash_profile(self.node, wrong)
        self.assertIsNone(child.poll())
        pid_file = Path(self.node.temporary) / "process.pid"
        pid_file.write_text(str(child.pid + 1))
        try:
            with self.assertRaises(RuntimeError):
                crash_profile(self.node, observed)
            self.assertIsNone(child.poll())
        finally:
            pid_file.write_text(str(child.pid))

    def test_foreign_command_and_executable_are_never_signalled(self):
        for executable, extra in ((self.node.binary, ["foreign"]), (sys.executable, [])):
            child = subprocess.Popen([executable, "run", self.node.config, *extra],
                                     cwd=self.remote, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            self.children.append(child)
            self.wait_file(Path(self.node.config + ".started"))
            (self.remote / "process.pid").write_text(str(child.pid))
            before = self.retained()
            with self.subTest(executable=executable), self.assertRaises(RuntimeError):
                crash_profile(self.node, self.observed(self.node, child))
            self.assertIsNone(child.poll())
            self.assertEqual(self.retained(), before)
            child.terminate()
            child.wait(timeout=2)
            Path(self.node.config + ".started").unlink()

    def test_lost_response_does_not_repeat_signal_or_discard_accounts(self):
        child = self.launch(self.node)
        observed = self.observed(self.node, child)
        before = self.retained()
        def lost(command, **kwargs):
            self.node.guarded_original(command, **kwargs)
            raise TimeoutError("reply lost after dispatch")
        self.node.guarded_original = self.node.guarded
        with patch.object(self.node, "guarded", side_effect=lost) as dispatched:
            with self.assertRaises(TimeoutError):
                crash_profile(self.node, observed)
            dispatched.assert_called_once()
        self.assertEqual(child.wait(timeout=1), -9)
        self.assertEqual(self.retained(), before)

    def test_identity_is_rechecked_after_obtaining_the_operation_lock(self):
        child = self.launch(self.node)
        observed = self.observed(self.node, child)
        entered, release = self.remote / "locked", self.remote / "release"
        with ThreadPoolExecutor(max_workers=2) as pool:
            holding = pool.submit(self.node.guarded,
                                  f"touch {entered}; while [ ! -f {release} ]; do sleep .02; done")
            self.wait_file(entered)
            crashing = pool.submit(crash_profile, self.node, observed)
            time.sleep(.1)
            self.assertFalse(crashing.done())
            pid_file = self.remote / "process.pid"
            pid_file.write_text(str(child.pid + 1))
            release.touch()
            holding.result(timeout=2)
            try:
                with self.assertRaises(RuntimeError):
                    crashing.result(timeout=2)
                self.assertIsNone(child.poll())
            finally:
                pid_file.write_text(str(child.pid))


if __name__ == "__main__":
    unittest.main()
