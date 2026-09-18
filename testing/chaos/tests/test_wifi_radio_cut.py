"""One finite sender owns each interruption, including uncertain failures."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from sim import wifi_probes as probes
from test_wifi_active_outage import probe_report


class RadioCutTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.run = Mock()
        self.run.participants.return_value = {
            name: SimpleNamespace(npub=name) for name in ("n01", "n03")}
        self.radio = Mock()
        self.shape, self.sender, self.report = probe_report(2)
        self.run.ctl.return_value = {"probe": self.report}
        self.evidence = {}
        self.saved = []
        self.run.save.side_effect = lambda: self.saved.append(copy.deepcopy(self.evidence))
        self.future = Mock()
        self.future.done.return_value = False
        self.future.result.return_value = self.sender
        self.pool = Mock()
        self.pool.submit.return_value = self.future
        executor = patch.object(probes, "ThreadPoolExecutor", create=True).start()
        executor.return_value.__enter__.return_value = self.pool
        self.clock = patch.object(probes, "time", create=True).start()
        self.clock.monotonic.side_effect = [0, 1, 2]
        self.eventually = patch.object(probes, "eventually", create=True,
                                       side_effect=lambda _name, check, _timeout: check()).start()

    def cut(self, *, round_trip=True, verify_route=None):
        return probes.send_with_radio_cut(self.run, "n01", "n03", self.shape, 2,
                                          self.radio, self.evidence, round_trip=round_trip,
                                          verify_route=verify_route)

    def assert_single_send(self, *, round_trip=True):
        self.pool.submit.assert_called_once_with(probes.send, self.run, "n01", "n03",
                                                self.shape, 2, round_trip=round_trip)
        self.future.result.assert_called_once_with(timeout=35)
        self.radio.mesh_up.assert_not_called()

    def test_partial_round_trips_cut_before_last_paced_send_and_drain_once(self):
        self.assertIs(self.cut(), self.sender)
        self.assert_single_send()
        self.radio.mesh_down.assert_called_once_with()
        self.assertEqual(self.evidence["before_cut"], self.report)
        self.assertEqual(self.evidence["dispatch_started"], 0)
        self.assertEqual(self.evidence["cut_completed"], 2)
        self.assertEqual(self.evidence["earliest_final_send_seconds"], 11.5)
        self.assertEqual(self.evidence["rate"], 2)
        self.assertEqual(self.saved[0]["cut_started"], 1)
        self.assertNotIn("cut_completed", self.saved[0])
        self.assertEqual(self.saved[-1]["sender"], self.sender)

    def test_one_way_probe_observes_destination_without_requiring_reflection(self):
        self.report.update(source="n01", round_trip_latency=None)
        self.assertIs(self.cut(round_trip=False), self.sender)
        self.assert_single_send(round_trip=False)
        self.assertEqual(self.run.ctl.call_args_list,
                         [call("n03", "status"), call("n03", "status")])

    def test_partial_mesh_down_failure_keeps_saved_intent_and_original_sender(self):
        def failed_cut():
            self.assertEqual(self.saved[-1]["cut_started"], 1)
            raise RuntimeError("radio command reply lost")
        self.radio.mesh_down.side_effect = failed_cut
        with self.assertRaisesRegex(RuntimeError, "radio command reply lost"):
            self.cut()
        self.assert_single_send()
        self.radio.mesh_down.assert_called_once_with()
        self.assertNotIn("cut_completed", self.evidence)
        self.assertEqual(self.evidence["sender"], self.sender)

    def test_cut_intent_save_failure_prevents_radio_mutation_but_still_drains(self):
        self.run.save.side_effect = RuntimeError("evidence unavailable")
        with self.assertRaisesRegex(RuntimeError, "evidence unavailable"):
            self.cut()
        self.radio.mesh_down.assert_not_called()
        self.assert_single_send()
        self.assertNotIn("cut_attempted", self.evidence)

    def test_pending_control_reply_cannot_accept_cut_after_paced_stream_ends(self):
        self.clock.monotonic.side_effect = [0, 1, 12]
        with self.assertRaisesRegex(RuntimeError, "earliest final paced send"):
            self.cut()
        self.radio.mesh_down.assert_called_once_with()
        self.assert_single_send()

    def test_finished_sender_before_or_after_partial_read_cannot_trigger_cut(self):
        for done in ([True], [False, True]):
            with self.subTest(done=done):
                self.future.done.side_effect = done
                with self.assertRaisesRegex(RuntimeError, "finished before the radio cut"):
                    self.cut()
                self.radio.mesh_down.assert_not_called()
                self.assertNotIn("cut_started", self.evidence)
                self.assert_single_send()
                self.pool.submit.reset_mock()
                self.future.result.reset_mock()
                self.clock.monotonic.side_effect = [0, 1, 2]

    def test_sender_completion_during_cut_rejects_overlap_without_resending(self):
        self.future.done.side_effect = [False, False, True]
        with self.assertRaisesRegex(RuntimeError, "did not overlap active sending"):
            self.cut()
        self.radio.mesh_down.assert_called_once_with()
        self.assert_single_send()

    def test_malformed_receiver_cannot_authorize_cut(self):
        self.report["unique_bytes"] += 1
        with self.assertRaisesRegex(RuntimeError, "inconsistent data"):
            self.cut()
        self.radio.mesh_down.assert_not_called()
        self.assert_single_send()

    def test_route_verification_follows_partial_delivery_and_precedes_saved_cut(self):
        def verify():
            self.assertEqual(self.evidence["before_cut"], self.report)
            self.assertNotIn("cut_started", self.evidence)
            self.radio.mesh_down.assert_not_called()
            return {"provider": "n01", "agreement": "original"}
        verify_route = Mock(side_effect=verify)
        self.cut(verify_route=verify_route)
        verify_route.assert_called_once_with()
        self.assertEqual(self.saved[0]["pre_cut_route"],
                         {"provider": "n01", "agreement": "original"})
        self.assert_single_send()

    def test_changed_route_does_not_cut_radio_or_replay_original_send(self):
        verify_route = Mock(side_effect=RuntimeError("selected carrier changed"))
        with self.assertRaisesRegex(RuntimeError, "selected carrier changed"):
            self.cut(verify_route=verify_route)
        verify_route.assert_called_once_with()
        self.assertNotIn("cut_started", self.evidence)
        self.radio.mesh_down.assert_not_called()
        self.assert_single_send()

    def test_slow_route_verification_cannot_cut_after_earliest_final_send(self):
        self.clock.monotonic.side_effect = [0, 12]
        with self.assertRaisesRegex(RuntimeError, "started after the earliest final paced send"):
            self.cut(verify_route=Mock(return_value={"provider": "n01"}))
        self.assertNotIn("cut_started", self.evidence)
        self.radio.mesh_down.assert_not_called()
        self.assert_single_send()

    def test_route_verification_that_outlasts_sender_cannot_cut_radio(self):
        def verify():
            self.future.done.return_value = True
            return {"provider": "n01"}
        with self.assertRaisesRegex(RuntimeError, "finished before the radio cut"):
            self.cut(verify_route=verify)
        self.assertNotIn("cut_started", self.evidence)
        self.radio.mesh_down.assert_not_called()
        self.assert_single_send()

    def test_receiver_timeout_drains_original_send_without_cut_or_replay(self):
        self.eventually.side_effect = RuntimeError("partial delivery absent")
        with self.assertRaisesRegex(RuntimeError, "partial delivery absent"):
            self.cut()
        self.radio.mesh_down.assert_not_called()
        self.assert_single_send()

    def test_sender_error_is_recorded_and_not_retried(self):
        self.future.result.side_effect = RuntimeError("send reply lost")
        with self.assertRaisesRegex(RuntimeError, "send reply lost"):
            self.cut()
        self.assertEqual(self.evidence["sender_error"], "RuntimeError")
        self.assertNotIn("sender", self.evidence)
        self.assert_single_send()

    def test_sender_error_during_cut_failure_preserves_first_error(self):
        self.radio.mesh_down.side_effect = RuntimeError("radio failure")
        self.future.result.side_effect = TimeoutError("send reply lost")
        with self.assertRaisesRegex(RuntimeError, "radio failure"):
            self.cut()
        self.assertEqual(self.evidence["sender_error"], "TimeoutError")
        self.assert_single_send()

    def test_incomplete_submission_cannot_pass_even_when_cut_overlaps(self):
        self.sender["submitted_packets"] -= 1
        with self.assertRaisesRegex(RuntimeError, "not fully submitted"):
            self.cut()
        self.assert_single_send()


if __name__ == "__main__":
    unittest.main()
