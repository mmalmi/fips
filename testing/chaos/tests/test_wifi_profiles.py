"""Run auxiliary lifecycle races through the production Linux cleanup guard."""

from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.wifi_remote import Router
from tests import test_wifi_discovery as base


@unittest.skipUnless(sys.platform == "linux" and shutil.which("flock"),
                     "profile lifecycle checks need Linux procfs and flock")
class ProfileGuardTests(unittest.TestCase):
    local = base.GuardTests.local
    start_guard = base.GuardTests.start_guard
    tearDown = base.GuardTests.tearDown

    def setUp(self):
        base.GuardTests.setUp(self)
        self.node.parent = str(self.remote / "accounts")
        self.aux = self.node.add_profile("free")
        Path(self.aux.temporary).mkdir()
        Path(self.aux.config).parent.mkdir(parents=True)
        self.guard.write_bytes(self.node.guard_script())
        (self.remote / "run").write_text(
            "from pathlib import Path\nimport sys,time\n"
            "Path(sys.argv[1]+'.started').touch()\ntime.sleep(30)\n")

    def wait_file(self, path):
        for _ in range(150):
            if path.exists():
                return
            time.sleep(.02)
        self.fail("candidate did not reach its deterministic barrier")

    def launch(self, profile, before_lock=None):
        script = self.node.start_script(profile)
        if before_lock is not None:
            entered = Path(profile.temporary) / "entered"
            release = Path(profile.temporary) / "release"
            barrier = f"touch {entered}; while [ ! -f {release} ]; do sleep .02; done\n".encode()
            boundary = b"#!/bin/sh\n" if before_lock else b"trap - EXIT\n"
            self.assertEqual(script.count(boundary), 1)
            script = script.replace(boundary, boundary + barrier)
        start = Path(profile.temporary) / "start.sh"
        start.write_bytes(script)
        child = subprocess.Popen(["sh", str(start)], cwd=self.remote, env=self.env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(child)
        self.wait_file(entered if before_lock is not None else Path(profile.config + ".started"))
        return child

    def test_expiry_stops_primary_and_auxiliary_and_retains_account_files(self):
        guard = self.start_guard()
        for profile in (self.node, self.aux):
            Path(profile.config).write_text("retained account settings")
        children = [self.launch(profile) for profile in (self.node, self.aux)]
        (self.remote / "heartbeat").write_text("0")
        guard.wait(timeout=12)
        self.assertEqual([child.wait(timeout=3) for child in children], [-15, -15])
        self.assertFalse((self.remote / "active").exists())
        for profile in (self.node, self.aux):
            self.assertEqual(Path(profile.config).read_text(), "retained account settings")
        self.assertFalse((self.remote / "candidate-forced-stop").exists())

    def test_router_cleanup_collects_all_logs_before_removing_shared_executable(self):
        staged = self.remote / "fips-relay"
        shutil.copy2(sys.executable, staged)
        self.node.binary = self.aux.binary = str(staged)
        self.guard.write_bytes(self.node.guard_script())
        self.start_guard()
        self.node.guard_ready = True
        children = [self.launch(profile) for profile in (self.node, self.aux)]
        for profile in (self.node, self.aux):
            Path(profile.config).write_text("retained account")
            (Path(profile.temporary) / "process.log").write_text(profile.config)
        with self.assertRaises(RuntimeError):
            self.local(["sh", str(self.guard), "stopped"])
        self.node.cleanup()
        self.assertEqual([child.wait(timeout=3) for child in children], [-15, -15])
        self.assertFalse(staged.exists())
        for profile in (self.node, self.aux):
            self.assertEqual((profile.output / "process.log").read_text(), profile.config)
            self.assertEqual(Path(profile.config).read_text(), "retained account")

    def test_all_profiles_receive_term_before_waiting_for_any_profile(self):
        self.start_guard()
        markers = [profile.config + ".term" for profile in (self.node, self.aux)]
        (self.remote / "run").write_text(
            "from pathlib import Path\nimport signal,sys,time\n"
            "def stop(*args):\n"
            " Path(sys.argv[1]+'.term').touch()\n"
            f" while not all(Path(p).exists() for p in {markers!r}): time.sleep(.01)\n"
            " sys.exit(0)\n"
            "signal.signal(signal.SIGTERM,stop)\n"
            "Path(sys.argv[1]+'.started').touch()\ntime.sleep(30)\n")
        children = [self.launch(profile) for profile in (self.node, self.aux)]
        self.local(["sh", str(self.guard), "stop"], timeout=8)
        self.assertEqual([child.wait(timeout=3) for child in children], [0, 0])
        self.assertTrue((self.remote / "active").exists())

    def test_auxiliary_foreign_pid_and_extra_arguments_are_preserved(self):
        self.start_guard()
        primary = self.launch(self.node)
        foreign = subprocess.Popen([sys.executable, "run", self.aux.config, "foreign"],
                                   cwd=self.remote)
        self.children.append(foreign)
        self.wait_file(Path(self.aux.config + ".started"))
        (Path(self.aux.temporary) / "process.pid").write_text(str(foreign.pid))
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertEqual(primary.wait(timeout=3), -15)
        self.assertIsNone(foreign.poll())

    def test_duplicate_launch_cannot_replace_the_tracked_process(self):
        self.start_guard()
        original = self.launch(self.aux)
        pid_file = Path(self.aux.temporary) / "process.pid"
        duplicate = subprocess.Popen(["sh", self.aux.temporary + "/start.sh"],
                                     cwd=self.remote, env=self.env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(duplicate)
        self.assertEqual(duplicate.wait(timeout=3), 1)
        self.assertEqual(int(pid_file.read_text()), original.pid)
        self.assertIsNone(original.poll())
        self.node.stop()
        self.assertEqual(original.wait(timeout=3), -15)
        Path(self.aux.config + ".started").unlink()
        restarted = self.launch(self.aux)
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertEqual(restarted.wait(timeout=3), -15)

    def test_duplicate_start_preserves_existing_diagnostic_log(self):
        self.start_guard()
        original = self.launch(self.aux)
        log = Path(self.aux.temporary) / "process.log"
        log.write_text("existing diagnostic evidence\n")
        def start_remote(command, data=None, timeout=20):
            # Wait only for this start call's background child to finish its
            # locked rejection before checking the original process and log.
            return self.local("cd " + shlex.quote(str(self.remote)) + "\n" + command + "\nwait",
                              data, timeout=5)
        with patch.object(self.node, "remote", side_effect=start_remote):
            self.aux.start()
        self.assertEqual(log.read_text(), "existing diagnostic evidence\n")
        self.assertEqual(int((Path(self.aux.temporary) / "process.pid").read_text()), original.pid)
        self.assertIsNone(original.poll())

    def test_dispatched_auxiliary_cannot_start_after_cleanup(self):
        self.start_guard()
        child = self.launch(self.aux, before_lock=True)
        self.local(["sh", str(self.guard), "cleanup"])
        (Path(self.aux.temporary) / "release").touch()
        self.assertEqual(child.wait(timeout=3), 1)
        self.assertFalse(Path(self.aux.config + ".started").exists())

    def test_cleanup_joins_auxiliary_launcher_after_it_releases_lock(self):
        self.start_guard()
        child = self.launch(self.aux, before_lock=False)
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertEqual(child.wait(timeout=3), -15)
        (Path(self.aux.temporary) / "release").touch()
        self.assertFalse(Path(self.aux.config + ".started").exists())

    def test_expired_lease_rejects_auxiliary_before_next_guard_poll(self):
        self.start_guard()
        (self.remote / "heartbeat").write_text("0")
        start = Path(self.aux.temporary) / "start.sh"
        start.write_bytes(self.node.start_script(self.aux))
        result = subprocess.run(["sh", str(start)], cwd=self.remote, env=self.env,
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertFalse((Path(self.aux.temporary) / "process.pid").exists())
        self.assertFalse(Path(self.aux.config + ".started").exists())

    def test_prepare_initializes_fresh_profile_and_rejects_expired_lease(self):
        unprepared = self.node.add_profile("unprepared")
        self.guard.write_bytes(self.node.guard_script())
        self.start_guard()
        # Use the same executable/command boundary as production, with an init
        # script standing in for the binary; no service is launched while funding.
        (self.remote / "init").write_text(
            "from pathlib import Path\nimport json,sys\n"
            "c=json.loads(Path(sys.argv[1]).read_text())\n"
            "Path(c['state_directory']).mkdir()\nprint('npub-test')\n")
        Path(self.aux.temporary).rmdir()
        Path(self.aux.config).parent.rmdir()
        def local_with_cwd(command, data=None, timeout=20):
            result = subprocess.run(["sh", "-c", command], cwd=self.remote, env=self.env,
                                    input=data, capture_output=True, timeout=timeout)
            if result.returncode:
                raise RuntimeError(result.stderr.decode())
            return result.stdout
        with patch.object(self.node, "remote", side_effect=local_with_cwd):
            with self.assertRaises(ValueError):
                self.aux.prepare({"state_directory": self.node.state})
            self.aux.prepare({"state_directory": self.aux.state})
            self.assertEqual(self.aux.npub, "npub-test")
            self.assertTrue(Path(self.aux.state).is_dir())
            self.assertEqual(Path(self.aux.config).stat().st_mode & 0o777, 0o600)
            self.assertEqual((Path(self.aux.temporary) / "start.sh").read_bytes(),
                             self.node.start_script(self.aux))
            with self.assertRaises(RuntimeError):
                self.aux.prepare({"state_directory": self.aux.state})
            # An expired lease cannot even begin creating another account.
            original = Path(self.aux.config).read_bytes()
            (self.remote / "heartbeat").write_text("0")
            with self.assertRaises(RuntimeError):
                unprepared.prepare({"state_directory": unprepared.state})
            self.assertFalse(Path(unprepared.parent).exists())
            self.assertFalse(Path(unprepared.temporary).exists())
            self.assertEqual(Path(self.aux.config).read_bytes(), original)


class ProfileRegistrationTests(unittest.TestCase):
    def test_registration_is_unique_validated_and_closed_before_guard_creation(self):
        with tempfile.TemporaryDirectory() as root:
            node = Router({"host": "lab1", "interface": "mesh0",
                           "management_interface": "br-lan", "original_binary": "/bin/original",
                           "original_config": "/etc/original.json", "state_parent": "/etc/bench"},
                          "123456789abc", Path(root))
            profile = node.add_profile("free")
            self.assertNotEqual(profile.config, node.config)
            self.assertEqual(profile.binary, node.binary)
            for name in ("free", "../escape", "unsafe name"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    node.add_profile(name)
            node.created = True
            with self.assertRaises(RuntimeError):
                node.add_profile("late")


if __name__ == "__main__":
    unittest.main()
