"""A radio cut must interrupt real paid replies and still recover owned funds."""

import copy
import itertools
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from sim.paid_wifi import PaidWifiRun
from sim.paid_faults import PACKETS, PAYLOAD_BYTES, paid_progress
from sim.wifi_active_outage import active_radio_outage
from sim.wifi_discovery import WifiRun
from test_wifi_roundtrip import round_trip_report
from test_paid_wifi import accounts


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
                late_cut=False, cut_error=False, outage_node="n03", stale_peer=None, timing=False,
                diagnostic_error=False, brief=False, radio_station=False, removed_peer=None,
                replaced_link=None):
        run = Mock()
        run.args = SimpleNamespace(recovery_timing=timing, brief_outage=brief)
        run.nodes = {name: Mock(npub=name) for name in ("n01", "n02", "n03")}
        rejoined = False
        for name, node in run.nodes.items():
            node.interface = "mesh0"
            node.native.return_value = {"status": "ok", "data": {"transports": [{
                "type": "ethernet", "name": "mesh0", "transport_id": 1,
                "stats": {"beacons_sent": 1, "beacons_recv": 2, "beacons_dropped": 0}}]}}
            node.remote.side_effect = lambda command: (
                b"1000\n20.50\n" if isinstance(command, str) else b"Station test\n")
            def native(command, name=name, node=node):
                if command["command"] != "show_peers":
                    return node.native.return_value
                peers = [{"npub": other, "connectivity": "stale" if radio_down and
                          outage_node in (name, other) else "connected", "transport_type": "ethernet",
                          "link_id": int(other[-1]), "authenticated_at_ms": 50,
                          "our_session_index": "00000002" if rejoined and name == replaced_link else "00000001"}
                         for other in run.nodes if abs(int(other[-1]) - int(name[-1])) == 1]
                if radio_down and name == removed_peer:
                    peers = []
                return {"status": "ok", "data": {"peers": peers}}
            node.native.side_effect = native
        if diagnostic_error:
            node = run.nodes[outage_node]
            node.native.side_effect = [RuntimeError("diagnostic unavailable"), node.native.return_value]
        radio_down = False
        def down():
            nonlocal radio_down
            radio_down = True
            if cut_error:
                raise RuntimeError("radio command reply lost")
        def up():
            nonlocal radio_down, rejoined
            radio_down = False
            rejoined = True
        run.nodes[outage_node].mesh_down.side_effect = down
        run.nodes[outage_node].mesh_up.side_effect = up
        run.evidence = {}
        run.assert_finances = Mock()
        shape, sent, partial = probe_report(2)
        def status(node, _kind):
            peers = [{"npub": other, "connected": not (radio_down and outage_node in (node, other)),
                      "transport": "ethernet"}
                     for other in run.nodes if abs(int(other[-1]) - int(node[-1])) == 1
                     and not (radio_down and not brief and outage_node in (node, other))]
            if radio_down and node == removed_peer:
                peers = []
            if radio_down and node == stale_peer:
                peers.append({"npub": "n02", "connected": False, "transport": "ethernet"})
            return {"npub": node, "measurements": {"version": 1, "process_id": int(node[-1])},
                    "probe": partial, "peers": peers}
        run.ctl.side_effect = status
        run.ready.side_effect = lambda **kwargs: WifiRun.ready(run, **kwargs)
        def observed(description, predicate, _seconds):
            result = predicate()
            if not result:
                raise RuntimeError(description + " not observed")
            return result
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
                patch("sim.wifi_active_outage.stations", create=True,
                      return_value="Station still joined" if radio_station else ""), \
                patch("sim.wifi_probes.eventually", side_effect=lambda _d, f, _s: f()), \
                patch("sim.wifi_active_outage.eventually", side_effect=observed), \
                patch("sim.wifi_active_outage.time.sleep"):
            executor.return_value.__enter__.return_value = pool
            error = None
            try:
                active_radio_outage(run, outage_node=outage_node)
            except RuntimeError as value:
                error = value
        pool.submit.assert_called_once()
        future.result.assert_called_once_with(timeout=35)
        return run, error

    def test_brief_cut_recovers_before_peer_eviction_on_leaf_and_bridge(self):
        for node in ("n02", "n03"):
            with self.subTest(node=node):
                run, error = self.run_cut(brief=True, outage_node=node)
                self.assertIsNone(error)
                evidence = run.evidence["active_outage"]
                self.assertTrue(evidence["passed"])
                self.assertEqual(evidence["radio_stations_during_outage"], "")
                self.assertEqual(evidence["retained_peer_sessions"], evidence["peer_sessions_before"])
                self.assertNotIn("eviction_observed", evidence)
                self.assertNotIn("isolated_peers", evidence)
                self.assertEqual(evidence["outage_receiver"]["missing_packets"], 22)
                self.assertEqual(evidence["recovery_receiver"]["unique_packets"], 8)
                run.ready.assert_called_once_with(line=True)
                run.nodes[node].mesh_up.assert_called_once_with()

    def test_brief_cut_rejects_remaining_radio_stations_and_restores(self):
        run, error = self.run_cut(brief=True, radio_station=True)
        self.assertIn("radio stations", str(error))
        self.assertFalse(run.evidence["active_outage"]["passed"])
        run.nodes["n03"].mesh_up.assert_called_once_with()

    def test_brief_cut_rejects_evicted_peers_and_restores(self):
        run, error = self.run_cut(brief=True, removed_peer="n03")
        self.assertIn("peer sessions", str(error))
        self.assertFalse(run.evidence["active_outage"]["passed"])
        run.nodes["n03"].mesh_up.assert_called_once_with()

    def test_brief_uncertain_cut_restores_without_replaying_sender(self):
        run, error = self.run_cut(brief=True, cut_error=True, outage_node="n02")
        self.assertIn("radio command reply lost", str(error))
        run.nodes["n02"].mesh_up.assert_called_once_with()
        self.assertFalse(run.evidence["active_outage"]["passed"])

    def test_brief_cut_rejects_a_replacement_session_after_retained_observation(self):
        run, error = self.run_cut(brief=True, replaced_link="n02", timing=True)
        self.assertIn("peer sessions", str(error))
        self.assertFalse(run.evidence["active_outage"]["passed"])
        run.nodes["n03"].mesh_up.assert_called_once_with()

    def test_partial_live_stream_cut_rejoins_and_uses_fresh_recovery_probe(self):
        run, error = self.run_cut()
        self.assertIsNone(error)
        run.nodes["n03"].mesh_down.assert_called_once_with()
        run.nodes["n03"].mesh_up.assert_called_once_with()
        self.assertTrue(run.evidence["active_outage"]["passed"])
        self.assertEqual(run.evidence["active_outage"]["outage_receiver"]["missing_packets"], 22)
        self.assertEqual(run.evidence["active_outage"]["recovery_receiver"]["unique_packets"], 8)
        self.assertEqual(run.evidence["active_outage"]["outage_node"], "n03")
        isolated = run.evidence["active_outage"]["isolated_peers"]
        self.assertEqual([p["npub"] for p in isolated["n01"]["peers"]], ["n02"])
        self.assertEqual([p["npub"] for p in isolated["n02"]["peers"]], ["n01"])
        self.assertEqual(isolated["n03"]["peers"], [])

    def test_timing_keeps_acceptance_and_failure_restoration(self):
        for failure in ({}, {"restart": True}, {"cut_error": True}, {"stale_peer": "n03"},
                        {"diagnostic_error": True}):
            with self.subTest(failure=failure):
                run, error = self.run_cut(timing=True, outage_node="n02", **failure)
                evidence = run.evidence["active_outage"]
                self.assertEqual(evidence["passed"], not failure)
                self.assertEqual(error is None, not failure)
                run.nodes["n02"].mesh_up.assert_called_once_with()
                self.assertEqual(set(evidence["timing"]["anchors"]["before_cut"]), set(run.nodes))
                if not failure:
                    self.assertEqual([s["phase"] for s in evidence["timing"]["samples"]],
                                     ["partition", "rejoin"])
                    self.assertEqual(set(evidence["timing"]["anchors"]["after_recovery"]), set(run.nodes))
                    for name in ("profile_check", "process_check", "recovery_arm", "recovery_send"):
                        self.assertLess(evidence[name + "_started"], evidence[name + "_completed"])

    def test_bridge_cut_partitions_all_three_then_restores_exact_line(self):
        run, error = self.run_cut(outage_node="n02")
        self.assertIsNone(error)
        evidence = run.evidence["active_outage"]
        self.assertEqual(evidence["outage_node"], "n02")
        self.assertTrue(evidence["passed"])
        self.assertEqual({name: state["peers"] for name, state in evidence["isolated_peers"].items()},
                         {name: [] for name in run.nodes})
        self.assertEqual({name: [p["npub"] for p in state["peers"]]
                          for name, state in evidence["rejoined_peers"].items()},
                         {"n01": ["n02"], "n02": ["n01", "n03"], "n03": ["n02"]})
        self.assertEqual(evidence["processes_before"], evidence["processes_after"])
        self.assertNotEqual(evidence["shape"]["stream_id"], evidence["recovery_shape"]["stream_id"])
        run.ready.assert_has_calls([call(line=True, isolated=True, outage_node="n02"), call(line=True)])
        run.nodes["n02"].mesh_down.assert_called_once_with()
        run.nodes["n02"].mesh_up.assert_called_once_with()
        for name in ("n01", "n03"):
            run.nodes[name].mesh_down.assert_not_called()
            run.nodes[name].mesh_up.assert_not_called()

    def test_bridge_stale_roster_rejects_partition_and_restores_radio(self):
        run, error = self.run_cut(outage_node="n02", stale_peer="n03")
        self.assertIn("partition", str(error))
        self.assertFalse(run.evidence["active_outage"]["passed"])
        run.nodes["n02"].mesh_up.assert_called_once_with()

    def test_uncertain_bridge_cut_restores_same_radio_without_send_replay(self):
        run, error = self.run_cut(outage_node="n02", cut_error=True)
        self.assertIn("radio command reply lost", str(error))
        run.nodes["n02"].mesh_up.assert_called_once_with()
        run.nodes["n03"].mesh_up.assert_not_called()
        self.assertIn("sender", run.evidence["active_outage"])
        self.assertFalse(run.evidence["active_outage"]["passed"])

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
    def service(self, outage_node="n03"):
        service = object.__new__(PaidWifiRun)
        service.args = SimpleNamespace(active_outage=True)
        service.outage_node = outage_node
        service.nodes = {name: Mock(npub=name) for name in ("n01", "n02", "n03")}
        service.evidence = {}
        service.channel_anchor = None
        for name in ("form_line", "assert_finances", "save", "ctl", "finances", "phase",
                     "collect", "verify_shortcuts", "paid_streams", "mesh_outage"):
            setattr(service, name, Mock())
        return service

    def test_failed_active_cut_collects_only_original_known_channels(self):
        service = self.service("n02")
        with patch("sim.paid_wifi.original_channels"), \
                patch("sim.paid_wifi.PaidRelayRun.unpaid_probe"), \
                patch("sim.paid_wifi.eventually", side_effect=lambda _d, f: f()), \
                patch("sim.paid_wifi.active_radio_outage", side_effect=RuntimeError("cut failed")) as cut, \
                patch("sim.paid_wifi.signal.alarm") as alarm:
            with self.assertRaisesRegex(RuntimeError, "cut failed"):
                service.exercise()
        service.collect.assert_called_once_with()
        cut.assert_called_once_with(service, outage_node="n02")
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

    def test_bridge_recovery_checks_both_original_paid_authorities_without_new_buys(self):
        service = self.service("n02")
        current = accounts()
        service.finances.side_effect = lambda: copy.deepcopy(current)
        service.assert_finances.side_effect = lambda: copy.deepcopy(current)
        service.ctl.side_effect = lambda name, _kind, **_fields: {"npub": name}
        service.collect.return_value = {"settled_wallet_balances": {"n01": 119, "n02": 146, "n03": 119}}
        service.paid_streams = PaidWifiRun.paid_streams.__get__(service)
        def progress(source, _destination, _phase):
            buyer, provider = current[source], current["n02"]
            buyer["authorized"] += 3
            buyer["remaining"] -= 3
            buyer["signed"][source] += 3
            buyer["signed_after"][source] += 3
            buyer["buyer_units"][source] += PACKETS * PAYLOAD_BYTES
            provider["seller_units"][source] += PACKETS * PAYLOAD_BYTES
            provider["credited"][source] += 3000
            usage = provider["seller_channels"][source]
            usage["paid_msat"] += 3000
            usage["submitted_msat"] += PACKETS * PAYLOAD_BYTES
            usage["reserved_msat"] += PACKETS * PAYLOAD_BYTES
        service.probe = Mock(side_effect=progress)
        with patch("sim.paid_wifi.PaidRelayRun.unpaid_probe"), \
                patch("sim.paid_wifi.eventually", side_effect=lambda _d, f: f()), \
                patch("sim.paid_wifi.active_radio_outage") as cut, \
                patch("sim.paid_wifi.paid_progress", wraps=paid_progress) as payment, \
                patch("sim.paid_wifi.signal.alarm"):
            service.exercise()
        cut.assert_called_once_with(service, outage_node="n02")
        self.assertEqual([(c.args[2], c.kwargs["wallet"]) for c in payment.call_args_list],
                         [("n01", False), ("n03", False)] * 2)
        self.assertTrue(all(c.args[3]["payment_targets_sat"] for c in payment.call_args_list))
        self.assertEqual([(c.args[0], c.kwargs["destination"]) for c in service.ctl.call_args_list
                          if c.args[1] == "buy"], [("n01", "n03"), ("n03", "n01")])
        self.assertEqual(service.probe.call_count, 4)
        service.collect.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
