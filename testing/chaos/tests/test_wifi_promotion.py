"""Live promotion orchestration with fake radio/control; no devices or funds."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.paid_wifi import PaidWifiRun
from sim.wifi_discovery import WifiRun
from sim.wifi_promotion import exercise, fresh_burst, process_samples, recover, restore_radio
from test_wifi_promotion_checks import held_fixture, native_quality
from test_wifi_promotion_finances import IDS


def immediate(description, condition, _seconds=120):
    result = condition()
    if not result:
        raise RuntimeError(description + " was not observed")
    return result


class PromotionLifecycleTests(unittest.TestCase):
    def run_case(self, *, cut_error=False, stale_peer=False, recovery_error=False, save_error=False,
                 pause_error=False, release_error=False, release_active=False, rejoin_error=None, restore_error=False,
                 connectivity_error=False, collection_error=False, cleanup_save_error=False,
                 restart=False, crash_error=False, start_error=False, source_restore_error=False):
        f, held = held_fixture()
        captured = held["captured"]
        f.raw["n01"]["controller"]["recovery_only"] = [captured["offer_id"]]
        f.raw["n01"]["controller"]["watched_routes"]["n03"]["pending"] = None
        run = Mock()
        run.args = SimpleNamespace(promotion_restart_source=restart)
        run.evidence = {}
        run.assert_finances = Mock(return_value={})
        run.nodes = {name: Mock(npub=name, node_addr=IDS[name]) for name in IDS}
        radio = run.nodes["n02"]
        radio.open_mesh = False
        radio.temporary = "/owned/promotion"
        radio_down = False
        armed = False
        released = False
        restart_events = run.restart_events = []
        def down():
            nonlocal radio_down
            restart_events.append("radio down")
            radio_down = True
            if cut_error:
                raise RuntimeError("uncertain radio command")
        def up():
            nonlocal radio_down
            if rejoin_error == "before":
                raise RuntimeError("rejoin command uncertain before effect")
            radio_down = False
            if rejoin_error == "after":
                raise RuntimeError("rejoin response lost after effect")
        def guarded(command, **_fields):
            nonlocal radio_down
            if command.startswith("mesh_restore;"):
                radio_down = False
                if restore_error:
                    raise RuntimeError("cleanup rejoin response lost after effect")
            elif command == "mesh_profile; mesh_joined":
                if radio_down or connectivity_error:
                    raise RuntimeError("owned joined profile unavailable")
            else:
                raise AssertionError(command)
        radio.guarded.side_effect = guarded
        run.nodes["n02"].mesh_down.side_effect = down
        run.nodes["n02"].mesh_up.side_effect = up
        def control(name, kind, **_fields):
            nonlocal armed, released
            if kind == "test_accept_barrier_arm":
                armed = True
                return copy.deepcopy(held)
            if kind == "test_accept_barrier_status":
                if not armed:
                    return {"armed": False, "active": False, "captured": None}
                return copy.deepcopy(held)
            if kind == "test_accept_barrier_release":
                if release_error:
                    raise RuntimeError("barrier release unavailable")
                if release_active:
                    return copy.deepcopy(held)
                released = True
                return {**held, "active": False, "held_responses": 0,
                        "terminal_reason": "released", "closed_responders": 1}
            if kind == "watch":
                return {"purchase": f.trial}
            if kind == "buy":
                return {"purchase": "original reverse"}
            if kind == "route_quality":
                return native_quality(working=False)
            if kind == "status":
                peers = [{"npub": other, "connected": True, "transport": "ethernet"}
                         for other in IDS if abs(int(other[-1]) - int(name[-1])) == 1 and not radio_down]
                if radio_down and stale_peer and name == "n01":
                    peers.append({"npub": "n02", "connected": False, "transport": "ethernet"})
                return {"peers": peers}
            raise AssertionError(kind)
        run.ctl.side_effect = control
        run.ready.side_effect = lambda **kwargs: WifiRun.ready(run, **kwargs)
        accounts = Mock(used=4096)
        accounts.observe.return_value = (f.raw, {}, None)
        accounts.evidence.return_value = {"financial": "bounded"}
        def crash(_run, evidence, _trial, _captured, before):
            restart_events.append("crash")
            evidence["source_restart"] = {"crash_attempted": True, "before": before}
            if crash_error:
                raise RuntimeError("uncertain kill reply")
        def start(_run, _evidence):
            restart_events.append("start")
            self.assertTrue(radio_down)
            if start_error:
                raise RuntimeError("uncertain launch reply")
            return {"new": "source process"}
        def restore(_run, evidence):
            if evidence.get("source_restart"):
                restart_events.append("restore source")
                if source_restore_error:
                    raise RuntimeError("source control unavailable")
        if pause_error:
            accounts.pause.side_effect = RuntimeError("pause unavailable")
        if collection_error:
            accounts.collect.side_effect = RuntimeError("collection incomplete")
        def save():
            evidence = run.evidence["interrupted_promotion"]
            if ((save_error and "cut_started" in evidence)
                    or (cleanup_save_error and evidence.get("cut_attempted"))):
                raise RuntimeError("evidence disk unavailable")
        run.save.side_effect = save
        failure = None
        with patch("sim.wifi_promotion.PromotionAccounts", return_value=accounts), \
                patch("sim.wifi_promotion.PaidRelayRun.unpaid_probe"), \
                patch("sim.wifi_promotion.process_samples", return_value={"n01": {"original": "source process"}}), \
                patch("sim.wifi_promotion.crash_source", side_effect=crash), \
                patch("sim.wifi_promotion.restart_source", side_effect=start), \
                patch("sim.wifi_promotion.restore_source", side_effect=restore), \
                patch("sim.wifi_promotion.qualify"), \
                patch("sim.wifi_promotion.await_commit", return_value=captured), \
                patch("sim.wifi_promotion.idle"), \
                patch("sim.wifi_promotion.recover", side_effect=RuntimeError("not recovered") if recovery_error else None), \
                patch("sim.wifi_promotion.eventually", side_effect=immediate), \
                patch("sim.wifi_promotion.time.monotonic", return_value=10), \
                patch("sim.wifi_promotion.signal.alarm"):
            try:
                exercise(run)
            except RuntimeError as error:
                failure = str(error)
        return run, accounts, failure, released, radio_down

    def test_restart_crashes_at_commit_then_launches_during_radio_absence(self):
        run, accounts, failure, released, down = self.run_case(restart=True)
        self.assertIsNone(failure)
        self.assertEqual(run.restart_events, ["crash", "radio down", "start", "restore source"])
        evidence = run.evidence["interrupted_promotion"]
        self.assertFalse(evidence["live_only"])
        self.assertTrue(evidence["passed"])
        self.assertTrue(released)
        self.assertFalse(down)
        self.assertEqual(sum(call.args[1] == "watch" for call in run.ctl.call_args_list), 1)
        self.assertEqual(sum(call.args[1] == "buy" for call in run.ctl.call_args_list), 1)
        accounts.collect.assert_called_once_with()

    def test_uncertain_crash_or_launch_recovers_control_for_collection(self):
        for fault in ("crash_error", "start_error"):
            with self.subTest(fault=fault):
                run, accounts, failure, released, down = self.run_case(restart=True, **{fault: True})
                self.assertIsNotNone(failure)
                self.assertIn("restore source", run.restart_events)
                self.assertTrue(released)
                self.assertFalse(down)
                self.assertFalse(run.evidence["interrupted_promotion"]["passed"])
                accounts.collect.assert_called_once_with()

    def test_unavailable_source_cleanup_still_restores_radio_and_retains_accounts(self):
        run, accounts, failure, released, down = self.run_case(
            restart=True, start_error=True, source_restore_error=True)
        self.assertIsNotNone(failure)
        self.assertTrue(released)
        self.assertFalse(down)
        accounts.pause.assert_called_once_with()
        accounts.collect.assert_not_called()
        cleanup = run.evidence["interrupted_promotion"]["cleanup"]
        self.assertFalse(cleanup["source_control_restored"])
        self.assertTrue(cleanup["accounts_retained_for_recovery"])

    def test_ambiguous_radio_cut_after_crash_uses_cleanup_before_collection(self):
        run, accounts, failure, released, down = self.run_case(restart=True, cut_error=True)
        self.assertIsNotNone(failure)
        self.assertEqual(run.restart_events, ["crash", "radio down", "restore source"])
        self.assertTrue(released)
        self.assertFalse(down)
        evidence = run.evidence["interrupted_promotion"]
        self.assertFalse(evidence["passed"])
        self.assertTrue(all(evidence["cleanup"][field] for field in (
            "source_control_restored", "authority_paused", "connectivity_verified", "collected")))
        accounts.collect.assert_called_once_with()

    def test_live_success_has_one_watch_and_only_original_reverse_buy(self):
        run, accounts, failure, released, down = self.run_case()
        self.assertIsNone(failure)
        self.assertTrue(run.evidence["interrupted_promotion"]["passed"])
        self.assertTrue(released)
        self.assertFalse(down)
        actions = [(call.args[0], call.args[1]) for call in run.ctl.call_args_list]
        self.assertEqual([item for item in actions if item[1] == "watch"], [("n01", "watch")])
        self.assertEqual([item for item in actions if item[1] == "buy"], [("n03", "buy")])
        self.assertFalse(any(item[1] in ("settle", "resume_renewals") for item in actions))
        run.nodes["n02"].mesh_down.assert_called_once_with()
        run.nodes["n02"].mesh_up.assert_called_once_with()
        accounts.collect.assert_called_once_with()

    def test_uncertain_cut_or_stale_native_peer_restores_and_collects_without_rescue(self):
        for kwargs in ({"cut_error": True}, {"stale_peer": True}, {"recovery_error": True}):
            with self.subTest(kwargs=kwargs):
                run, accounts, failure, released, down = self.run_case(**kwargs)
                self.assertIsNotNone(failure)
                self.assertFalse(run.evidence["interrupted_promotion"]["passed"])
                self.assertTrue(released)
                self.assertFalse(down)
                self.assertTrue(any(call.args[0].startswith("mesh_restore;")
                                    for call in run.nodes["n02"].guarded.call_args_list))
                accounts.collect.assert_called_once_with()

    def test_pre_command_save_failure_never_changes_radio(self):
        run, accounts, failure, _, _ = self.run_case(save_error=True)
        self.assertIsNotNone(failure)
        run.nodes["n02"].mesh_down.assert_not_called()
        run.nodes["n02"].mesh_up.assert_not_called()
        accounts.collect.assert_not_called()
        self.assertTrue(run.evidence["interrupted_promotion"]["cleanup"]["accounts_retained_for_recovery"])

    def test_cleanup_save_failure_does_not_skip_radio_restoration(self):
        run, accounts, failure, released, down = self.run_case(cut_error=True, cleanup_save_error=True)
        self.assertIsNotNone(failure)
        self.assertTrue(released)
        self.assertFalse(down)
        accounts.collect.assert_not_called()
        cleanup = run.evidence["interrupted_promotion"]["cleanup"]
        self.assertTrue(cleanup["radio_restore_attempted"])
        self.assertFalse(cleanup["connectivity_verified"])
        self.assertEqual([item["stage"] for item in cleanup["errors"]],
                         ["save_before_restore", "connectivity", "save_after_cleanup"])

    def test_pause_failure_still_releases_and_restores_but_retains_accounts(self):
        run, accounts, failure, released, down = self.run_case(cut_error=True, pause_error=True)
        self.assertIsNotNone(failure)
        self.assertTrue(released)
        self.assertFalse(down)
        accounts.collect.assert_not_called()
        cleanup = run.evidence["interrupted_promotion"]["cleanup"]
        self.assertFalse(cleanup["authority_paused"])
        self.assertTrue(cleanup["barrier_quiescent"])
        self.assertTrue(cleanup["connectivity_verified"])
        self.assertTrue(cleanup["accounts_retained_for_recovery"])
        self.assertEqual(cleanup["errors"], [{"stage": "pause", "error": "RuntimeError"}])

    def test_release_failure_still_restores_but_retains_accounts(self):
        run, accounts, failure, released, down = self.run_case(release_error=True)
        self.assertIsNotNone(failure)
        self.assertFalse(released)
        self.assertFalse(down)
        accounts.collect.assert_not_called()
        evidence = run.evidence["interrupted_promotion"]
        self.assertFalse(evidence["passed"])
        self.assertTrue(evidence["cleanup"]["authority_paused"])
        self.assertFalse(evidence["cleanup"]["barrier_quiescent"])
        self.assertTrue(evidence["cleanup"]["connectivity_verified"])
        self.assertTrue(evidence["cleanup"]["accounts_retained_for_recovery"])
        self.assertEqual(evidence["cleanup"]["errors"],
                         [{"stage": "barrier_release", "error": "RuntimeError"}])

    def test_recorded_but_active_release_reply_cannot_skip_cleanup_or_allow_collection(self):
        run, accounts, failure, _, down = self.run_case(release_active=True)
        self.assertIsNotNone(failure)
        self.assertFalse(down)
        accounts.collect.assert_not_called()
        evidence = run.evidence["interrupted_promotion"]
        self.assertIn("release", evidence)
        self.assertNotIn("release_verified", evidence)
        self.assertIn("barrier_release", evidence["cleanup"])
        self.assertFalse(evidence["cleanup"]["barrier_quiescent"])
        self.assertFalse(evidence["passed"])
        self.assertEqual(sum(call.args[1] == "test_accept_barrier_release"
                             for call in run.ctl.call_args_list), 2)

    def test_uncertain_rejoin_is_observed_and_restored_before_collection(self):
        for when in ("before", "after"):
            with self.subTest(when=when):
                run, accounts, failure, released, down = self.run_case(rejoin_error=when)
                self.assertIsNotNone(failure)
                self.assertTrue(released)
                self.assertFalse(down)
                run.nodes["n02"].mesh_up.assert_called_once_with()
                accounts.collect.assert_called_once_with()
                evidence = run.evidence["interrupted_promotion"]
                self.assertFalse(evidence["passed"])
                self.assertTrue(evidence["cleanup"]["radio_restore_attempted"])
                self.assertTrue(evidence["cleanup"]["connectivity_verified"])
                self.assertFalse(evidence["cleanup"]["accounts_retained_for_recovery"])

    def test_lost_cleanup_restore_reply_needs_independent_readback(self):
        run, accounts, failure, _, down = self.run_case(cut_error=True, restore_error=True)
        self.assertIsNotNone(failure)
        self.assertFalse(down)
        accounts.collect.assert_called_once_with()
        cleanup = run.evidence["interrupted_promotion"]["cleanup"]
        self.assertTrue(cleanup["connectivity_verified"])
        self.assertEqual(cleanup["errors"], [{"stage": "radio_restore", "error": "RuntimeError"}])

    def test_failed_restore_readback_prevents_collection(self):
        run, accounts, failure, _, _ = self.run_case(connectivity_error=True)
        self.assertIsNotNone(failure)
        accounts.collect.assert_not_called()
        cleanup = run.evidence["interrupted_promotion"]["cleanup"]
        self.assertFalse(cleanup["connectivity_verified"])
        self.assertTrue(cleanup["accounts_retained_for_recovery"])
        self.assertFalse(run.evidence["interrupted_promotion"]["passed"])

    def test_collection_failure_cannot_certify_recovered_case(self):
        run, accounts, failure, _, _ = self.run_case(collection_error=True)
        self.assertIsNotNone(failure)
        accounts.collect.assert_called_once_with()
        evidence = run.evidence["interrupted_promotion"]
        self.assertTrue(evidence["recovery_passed"])
        self.assertFalse(evidence["passed"])
        self.assertTrue(evidence["cleanup"]["accounts_retained_for_recovery"])
        self.assertEqual(evidence["cleanup"]["errors"],
                         [{"stage": "collection", "error": "RuntimeError"}])

    def test_open_cleanup_checks_joined_state_before_readding_group(self):
        radio = Mock(open_mesh=True, temporary="/owned/promotion")
        restore_radio(radio)
        radio.guarded.assert_called_once_with(
            "original_isolated; open_profile; if open_joined; then open_limited; "
            "else open_resume; fi; rm -f /owned/promotion/mesh-down", timeout=60)

    def test_opt_in_dispatch_does_not_run_ordinary_two_channel_exercise(self):
        run = object.__new__(PaidWifiRun)
        run.args = SimpleNamespace(interrupted_promotion=True)
        with patch("sim.paid_wifi.wifi_promotion.exercise") as scenario:
            run.exercise()
        scenario.assert_called_once_with(run)

    def test_process_snapshot_rejects_restart_even_with_same_identity(self):
        run = Mock()
        run.nodes = {"n01": Mock(npub="n01")}
        before = {"npub": "n01", "host_process": {"host": "n01", "pid": 1, "start_ticks": 3}}
        now = {"npub": "n01", "host_process": {"host": "n01", "pid": 1, "start_ticks": 4},
               "native": {"status": {"data": {"npub": "n01", "node_addr": "01" * 16}}}}
        with patch("sim.wifi_promotion.snapshot", return_value=now), self.assertRaises(RuntimeError):
            process_samples(run, {"n01": before})

    def test_uncertain_finite_send_is_recorded_and_never_replayed(self):
        run, evidence = Mock(), {}
        shape = {"stream_id": "fresh", "packet_count": 8, "payload_bytes": 128}
        with patch("sim.wifi_promotion.probes.arm", return_value=shape), \
                patch("sim.wifi_promotion.probes.send", side_effect=RuntimeError("reply lost")) as send, \
                self.assertRaises(RuntimeError):
            fresh_burst(run, evidence, "trial")
        send.assert_called_once()
        self.assertEqual(evidence["bursts"][0]["shape"], shape)
        self.assertIn("started", evidence["bursts"][0])


class RecoveredPayloadTests(unittest.TestCase):
    def case(self, *, acknowledgment=2000, changed=False, stale=False):
        f, held = held_fixture()
        trial, captured = f.trial, held["captured"]
        full = copy.deepcopy(captured["purchase"])
        full["contract"]["id"] = "full" if stale else "fresh-full"
        channel = full["channel"]["id"]
        state = {"purchases": [full], "watched_routes": [{"destination": "n03", "billing": "forwarding_data",
            "max_rate_msat_per_kib": 8192, "paused": False, "pending": None}],
            "payment_progress": {channel: {"authorized_sat": 2, "evidence_msat": 1900,
                                            "acknowledged_msat": acknowledgment, "in_flight": False}}}
        after = copy.deepcopy(state)
        if changed:
            after["purchases"][0]["contract"]["id"] = "changed-midstream"
        run = Mock()
        run.nodes = {name: SimpleNamespace(npub=name, node_addr=IDS[name]) for name in IDS}
        run.ctl.side_effect = [state, after, state]
        accounts = Mock(used=4096)
        accounts.observe.return_value = ({}, {"n01": {"signed": {channel: 1}},
                                              "n02": {"credited": {channel: 2000}}}, None)
        accounts.evidence.return_value = {"financial": "retained"}
        evidence = {"bursts": []}
        row = {"shape": {"packet_count": 8}, "receiver": {"unique_packets": 8}}
        def burst(*_args):
            evidence["bursts"].append(row)
            return row
        calls = 0
        def bounded_wait(description, condition, seconds):
            nonlocal calls
            calls += 1
            if calls > 1 and changed:
                raise RuntimeError("unchanged agreement was not accepted")
            return immediate(description, condition, seconds)
        with patch("sim.wifi_promotion.route_quality", side_effect=[native_quality(working=False), native_quality()]), \
                patch("sim.wifi_promotion.fresh_burst", side_effect=burst), \
                patch("sim.wifi_promotion.eventually", side_effect=bounded_wait), \
                patch("sim.wifi_promotion.time.sleep"):
            if acknowledgment is None or changed or stale:
                with self.assertRaises(RuntimeError):
                    recover(run, accounts, evidence, trial, captured)
                self.assertNotIn("recovered_purchase", evidence)
            else:
                recover(run, accounts, evidence, trial, captured)
                self.assertEqual(evidence["recovered_purchase"], full)
        self.assertTrue(all(call.args[1] == "status" for call in run.ctl.call_args_list))

    def test_fresh_same_agreement_payload_requires_automatic_acknowledged_credit(self):
        self.case()
        self.case(acknowledgment=None)

    def test_changed_midstream_agreement_cannot_certify_recovery(self):
        self.case(changed=True)

    def test_stale_withdrawn_full_response_cannot_supply_recovery_payload(self):
        self.case(stale=True)
