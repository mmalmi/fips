"""Crash-boundary authority and uncertain restart cleanup without devices."""

from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_promotion_restart import (
    crash_source, require_restarted, restart_source, restore_source,
)
from test_wifi_promotion_checks import held_fixture
from test_wifi_promotion import immediate
from test_wifi_promotion_finances import IDS


def sample(pid=101, start=10, identity="n01"):
    return {"npub": identity,
            "host_process": {"host": "n01", "pid": pid, "start_ticks": start},
            "native": {"status": {"data": {"node_addr": bytes(IDS["n01"]).hex()}}},
            "watched_routes": [{"destination": "n03", "max_rate_msat_per_kib": 8192,
                                "billing": "forwarding_data", "paused": False}]}


class RestartBoundaryTests(unittest.TestCase):
    def fixture(self):
        f, held = held_fixture()
        run = Mock()
        run.nodes = {name: SimpleNamespace(npub=name, node_addr=IDS[name], start=Mock()) for name in IDS}
        run.ctl.return_value = held
        return run, f, held

    def test_real_stopped_journal_boundary_precedes_launch_and_retains_watch(self):
        run, f, held = self.fixture()
        evidence = {}
        events = []
        run.save.side_effect = lambda: events.append("save")
        run.nodes["n01"].start.side_effect = lambda: events.append("start")
        def stop(_node, before):
            self.assertEqual(before, sample())
            events.append("kill")
            return {"pid": 101, "start_ticks": 10, "stopped": True}
        def read(_run):
            events.append("stopped journals")
            self.assertNotIn("start", events)
            return f.raw
        after = sample(102, 20)
        with patch("sim.wifi_promotion_restart.crash_profile", side_effect=stop), \
                patch("sim.wifi_promotion_restart.journals", side_effect=read), \
                patch("sim.wifi_promotion_restart.snapshot", return_value=after), \
                patch("sim.wifi_promotion_restart.eventually", side_effect=immediate):
            crash_source(run, evidence, f.trial, held["captured"], sample())
            run.nodes["n01"].start.assert_not_called()
            self.assertEqual(restart_source(run, evidence), after)
        self.assertLess(events.index("save"), events.index("kill"))
        self.assertLess(events.index("stopped journals"), events.index("start"))
        self.assertTrue(evidence["source_restart"]["stopped_boundary_verified"])
        run.nodes["n01"].start.assert_called_once_with()
        self.assertEqual([call.args[1] for call in run.ctl.call_args_list], ["test_accept_barrier_status"])

    def test_wrong_stopped_boundary_cannot_be_repaired_by_rewatching_or_launch(self):
        for mutation in ("withdrawn", "accepted", "trial_active", "different_commit"):
            run, f, held = self.fixture()
            source = f.raw["n01"]["controller"]
            if mutation == "withdrawn":
                source["watched_routes"]["n03"]["pending"] = None
            elif mutation == "accepted":
                source["outgoing"]["full"]["accepted"] = True
            elif mutation == "trial_active":
                source["outgoing"]["trial"]["retired"] = False
            else:
                held["captured"]["offer_id"] = "another"
            evidence = {}
            with self.subTest(mutation=mutation), \
                    patch("sim.wifi_promotion_restart.crash_profile"), \
                    patch("sim.wifi_promotion_restart.journals", return_value=f.raw), \
                    self.assertRaises((RuntimeError, TypeError)):
                crash_source(run, evidence, f.trial, held["captured"], sample())
            run.nodes["n01"].start.assert_not_called()
            self.assertNotIn("stopped_boundary_verified", evidence["source_restart"])

    def test_restart_requires_new_epoch_and_original_host_identity_and_watch(self):
        for change in ({}, {"npub": "new"}, {"host_process": {"host": "n02", "pid": 102, "start_ticks": 20}},
                       {"host_process": {"host": "n01", "pid": 102, "start_ticks": 10}}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                require_restarted(sample(), {**sample(), **change})
        require_restarted(sample(), sample(102, 20))
        # PID reuse is fine only when the observed process epoch advanced.
        require_restarted(sample(), sample(101, 20))
        for field, value in (("paused", True), ("max_rate_msat_per_kib", 9999)):
            run, _, _ = self.fixture()
            after = sample(102, 20)
            after["watched_routes"][0][field] = value
            evidence = {"source_restart": {"before": sample(), "stopped_boundary_verified": True}}
            with self.subTest(field=field), \
                    patch("sim.wifi_promotion_restart.snapshot", return_value=after), \
                    patch("sim.wifi_promotion_restart.eventually", side_effect=immediate), \
                    self.assertRaises(RuntimeError):
                restart_source(run, evidence)

    def test_uncertain_kill_or_launch_cleanup_observes_before_dispatching(self):
        for current in (sample(), sample(102, 20)):
            run, _, _ = self.fixture()
            evidence = {"source_restart": {"before": sample(), "crash_attempted": True}}
            with patch("sim.wifi_promotion_restart.snapshot", return_value=current):
                restore_source(run, evidence)
            run.nodes["n01"].start.assert_not_called()
            self.assertEqual(evidence["source_restart"]["cleanup_process"], current)
        run, _, _ = self.fixture()
        evidence = {"source_restart": {"before": sample(), "crash_attempted": True}}
        with patch("sim.wifi_promotion_restart.snapshot", side_effect=[RuntimeError("stopped"), sample(102, 20)]), \
                patch("sim.wifi_promotion_restart.eventually", side_effect=immediate):
            restore_source(run, evidence)
        run.nodes["n01"].start.assert_called_once_with()
        self.assertTrue(evidence["source_restart"]["cleanup_start_attempted"])

    def test_evidence_failure_before_kill_does_not_dispatch_and_absent_fault_never_starts(self):
        run, f, held = self.fixture()
        run.save.side_effect = RuntimeError("disk unavailable")
        with patch("sim.wifi_promotion_restart.crash_profile") as crash, self.assertRaises(RuntimeError):
            crash_source(run, {}, f.trial, held["captured"], sample())
        crash.assert_not_called()
        restore_source(run, {})
        run.nodes["n01"].start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
