"""A radio cut must interrupt real paid replies and still recover owned funds."""

import itertools
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.paid_wifi import PaidWifiRun
from sim.wifi_active_outage import active_radio_outage
from test_wifi_roundtrip import round_trip_report


def probe_report(count, expected=24, stream="a" * 32):
    shape, sender, report = round_trip_report()
    shape.update(stream_id=stream, packet_count=expected)
    sender.update(stream_id=stream, requested_packets=expected, submitted_packets=expected,
                  submitted_bytes=expected * 128)
    report.update(stream_id=stream, expected_packets=expected, unique_packets=count,
                  unique_bytes=count * 128, missing_packets=expected-count)
    report["round_trip_latency"].update(samples=count, min_us=1000, max_us=1000,
                                        sum_us=count * 1000, bucket_counts=[count, 0, 0, 0])
    return shape, sender, report


class ActiveOutageTests(unittest.TestCase):
    def run_cut(self, *, completed=False, lost=False, observation_error=False, restart=False,
                late_cut=False, cut_error=False):
        run = Mock()
        run.nodes = {name: Mock(npub=name) for name in ("n01", "n02", "n03")}
        if cut_error:
            run.nodes["n03"].mesh_down.side_effect = RuntimeError("radio command reply lost")
        run.evidence = {}
        run.assert_finances = Mock()
        shape, sent, partial = probe_report(2)
        run.ctl.side_effect = lambda node, _kind: {
            "npub": node, "measurements": {"version": 1, "process_id": int(node[-1])},
            "probe": partial}
        recovery_shape, recovery_sent, recovered = probe_report(8, expected=8, stream="b" * 32)
        _, _, full = round_trip_report()
        future = Mock()
        future.done.return_value = completed
        future.result.return_value = sent
        pool = Mock()
        pool.submit.return_value = future
        results = [partial, full if lost else partial, partial, recovered]
        if observation_error:
            results[1] = RuntimeError("invalid reply")
        snapshots = []
        for after in (False, True):
            snapshots.extend({"npub": name, "host_process": {
                "pid": int(name[-1]), "start_ticks": 20 if after and restart else 10}}
                for name in run.nodes)
        clock = iter([0, 1, 12, *range(13, 30)]) if late_cut else itertools.count()
        with patch("sim.wifi_active_outage.time.monotonic", side_effect=lambda: next(clock)), \
                patch("sim.wifi_active_outage.snapshot", side_effect=snapshots), \
                patch("sim.wifi_probes.ThreadPoolExecutor") as executor, \
                patch("sim.wifi_active_outage.probes.arm", side_effect=[shape, recovery_shape]), \
                patch("sim.wifi_active_outage.probes.send", return_value=recovery_sent), \
                patch("sim.wifi_active_outage.probes.receive", side_effect=results), \
                patch("sim.wifi_probes.eventually", side_effect=lambda _d, f, _s: f()), \
                patch("sim.wifi_active_outage.eventually", side_effect=lambda _d, f, _s: f()), \
                patch("sim.wifi_active_outage.time.sleep"):
            executor.return_value.__enter__.return_value = pool
            error = None
            try:
                active_radio_outage(run)
            except RuntimeError as value:
                error = value
        pool.submit.assert_called_once()
        future.result.assert_called_once_with(timeout=35)
        return run, error

    def test_partial_live_stream_cut_rejoins_and_uses_fresh_recovery_probe(self):
        run, error = self.run_cut()
        self.assertIsNone(error)
        run.nodes["n03"].mesh_down.assert_called_once_with()
        run.nodes["n03"].mesh_up.assert_called_once_with()
        self.assertTrue(run.evidence["active_outage"]["passed"])
        self.assertEqual(run.evidence["active_outage"]["outage_receiver"]["missing_packets"], 22)
        self.assertEqual(run.evidence["active_outage"]["recovery_receiver"]["unique_packets"], 8)

    def test_finished_sender_cannot_claim_an_active_radio_cut(self):
        run, error = self.run_cut(completed=True)
        self.assertIsNotNone(error)
        run.nodes["n03"].mesh_down.assert_not_called()
        self.assertFalse(run.evidence["active_outage"]["passed"])

    def test_no_loss_does_not_prove_interruption_and_radio_still_restores(self):
        run, error = self.run_cut(lost=True)
        self.assertIsNotNone(error)
        run.nodes["n03"].mesh_up.assert_called_once_with()
        self.assertFalse(run.evidence["active_outage"]["passed"])

    def test_bad_observation_still_rejoins_without_resending_original_stream(self):
        run, error = self.run_cut(observation_error=True)
        self.assertIn("invalid reply", str(error))
        run.nodes["n03"].mesh_up.assert_called_once_with()
        self.assertFalse(run.evidence["active_outage"]["passed"])

    def test_uncertain_radio_departure_restores_after_draining_original_send(self):
        run, error = self.run_cut(cut_error=True)
        self.assertIn("radio command reply lost", str(error))
        run.nodes["n03"].mesh_up.assert_called_once_with()
        self.assertIn("sender", run.evidence["active_outage"])
        self.assertNotIn("cut_completed", run.evidence["active_outage"])
        self.assertFalse(run.evidence["active_outage"]["passed"])

    def test_pending_control_response_cannot_prove_late_cut_interrupted_sending(self):
        run, error = self.run_cut(late_cut=True)
        self.assertIn("earliest final paced send", str(error))
        run.nodes["n03"].mesh_up.assert_called_once_with()
        self.assertFalse(run.evidence["active_outage"]["passed"])

    def test_process_restart_cannot_masquerade_as_radio_recovery(self):
        run, error = self.run_cut(restart=True)
        self.assertIn("restarted", str(error))
        self.assertFalse(run.evidence["active_outage"]["passed"])



class RecoveryTests(unittest.TestCase):
    def service(self):
        service = object.__new__(PaidWifiRun)
        service.args = SimpleNamespace(active_outage=True)
        service.nodes = {name: Mock(npub=name) for name in ("n01", "n02", "n03")}
        service.evidence = {}
        service.channel_anchor = None
        for name in ("form_line", "assert_finances", "save", "ctl", "finances", "phase",
                     "collect", "verify_shortcuts", "paid_streams", "mesh_outage"):
            setattr(service, name, Mock())
        return service

    def test_failed_active_cut_collects_only_original_known_channels(self):
        service = self.service()
        with patch("sim.paid_wifi.original_channels"), \
                patch("sim.paid_wifi.PaidRelayRun.unpaid_probe"), \
                patch("sim.paid_wifi.eventually", side_effect=lambda _d, f: f()), \
                patch("sim.paid_wifi.active_radio_outage", side_effect=RuntimeError("cut failed")), \
                patch("sim.paid_wifi.signal.alarm") as alarm:
            with self.assertRaisesRegex(RuntimeError, "cut failed"):
                service.exercise()
        service.collect.assert_called_once_with()
        service.mesh_outage.assert_not_called()
        self.assertEqual(service.evidence["acceptance_failure"], "cut failed")
        alarm.assert_called_once_with(0)

    def test_uncertain_purchase_preserves_accounts_without_repeat_or_settlement(self):
        service = self.service()
        service.ctl.side_effect = RuntimeError("purchase uncertain")
        with patch("sim.paid_wifi.PaidRelayRun.unpaid_probe"):
            with self.assertRaisesRegex(RuntimeError, "purchase uncertain"):
                service.exercise()
        self.assertEqual(service.ctl.call_count, 1)
        service.collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
