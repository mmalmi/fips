"""Paid diamond funding and recovery stay single-shot without live devices."""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_diamond import Accounts, PaidDiamondRun
from sim.wifi_diamond_selection import PRICE_CEILING
from test_settlement_fixture import DiamondRun as FinancialFixture


URL = "http://127.0.0.1:41234"
MODULE = "sim.paid_diamond"


def runner():
    run = object.__new__(PaidDiamondRun)
    run.evidence = {"passed": False, "phases": []}
    run.root = Path("/unused-mocked-diamond")
    run.nodes = {name: SimpleNamespace(
        host=name, npub="identity-" + name, state="/tmp/bench-state",
        stop=Mock(), mesh_down=Mock(), mesh_up=Mock(), control=Mock(return_value={
            "mint_url": URL, "unit": "sat", "balance_sat": 0}))
        for name in ("n01", "n02", "n03")}
    run.source = SimpleNamespace(owner=run.nodes["n03"], state="/tmp/bench-state",
                                 control=Mock(return_value={
                                     "mint_url": URL, "unit": "sat", "balance_sat": 128}))
    run.accounts = Accounts(run)
    run.mint_url = URL
    run.mint = Mock(info={"owned": True})
    run.mint.grant.return_value = "private-test-token"
    run.mint.request.return_value = {"issued_sat": 128, "collected_sat": 0, "conserved": True}
    run.forwards = None
    run.monitor = Mock()
    run.watch_started = run.collection_attempted = False
    run.fixture = None
    for name in ("save", "phase", "prepare_source", "offline_empty", "form_diamond",
                 "process_snapshots", "financial_checkpoint", "drive_route", "topology",
                 "verify_open_profiles", "verify_shortcuts", "ctl"):
        setattr(run, name, Mock())
    return run


def paused_status(run, pending=None):
    return {"watched_routes": [{
        "destination": run.nodes["n03"].npub, "max_rate_msat_per_kib": PRICE_CEILING,
        "billing": "forwarding_data", "paused": True, "pending": pending,
    }]}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch(MODULE + ".signal.alarm").start()
        patch(MODULE + ".eventually", side_effect=lambda _name, check, *_args: check()).start()

    def forward_owner(self):
        owner = Mock(info={"owned": True})
        owner.finish.return_value = {"retained_for_recovery": True}
        return patch(MODULE + ".MintForwards", return_value=owner).start(), owner

    def test_only_source_receives_one_grant_and_import(self):
        run = runner()
        constructor, forwards = self.forward_owner()
        run.before_launch()
        constructor.assert_called_once_with(run.nodes, URL, run.root)
        forwards.start.assert_called_once_with()
        run.prepare_source.assert_called_once_with()
        run.offline_empty.assert_called_once_with()
        run.mint.grant.assert_called_once_with("source")
        self.assertEqual(run.source.control.call_args_list, [
            call("import", action="wallet", token="private-test-token"),
            call("balance", action="wallet")])
        for node in run.nodes.values():
            node.control.assert_called_once_with("balance", action="wallet")
        self.assertEqual(run.evidence["source_funding_stage"], "verified")
        self.assertNotIn("private-test-token", repr(run.evidence))

    def test_uncertain_grant_or_import_is_never_replayed_by_cleanup(self):
        for operation in ("grant", "import"):
            with self.subTest(operation=operation):
                run = runner()
                _, forwards = self.forward_owner()
                if operation == "grant":
                    run.mint.grant.side_effect = RuntimeError("grant reply lost")
                else:
                    run.source.control.side_effect = RuntimeError("import reply lost")
                run.setup = run.before_launch
                run.exercise = Mock()
                with patch(MODULE + ".DiamondRun.finish") as cleanup:
                    with self.assertRaisesRegex(RuntimeError, "preserve"):
                        run.execute()
                cleanup.assert_called_once_with()
                run.exercise.assert_not_called()
                run.mint.grant.assert_called_once_with("source")
                self.assertEqual(run.source.control.call_count, int(operation == "import"))
                self.assertEqual(run.evidence["source_funding_stage"], operation + "_attempted")
                forwards.start.assert_called_once_with()
                forwards.retain.assert_called_once_with("RuntimeError")
                run.mint.finish.assert_not_called()
                self.assertEqual(run.evidence["mint_retained_for_recovery"], run.mint.info)
                self.assertFalse(run.evidence["passed"])

    def test_shared_source_and_destination_process_is_stopped_once(self):
        run = runner()
        for _ in range(2):
            for name in run.accounts.nodes:
                run.accounts.stop(name)
        for node in run.nodes.values():
            node.stop.assert_called_once_with()
        self.assertEqual(run.accounts.stopped, {"n01", "n02", "n03"})

    def test_one_watch_survives_success_or_uncertain_submission(self):
        for failed in (False, True):
            with self.subTest(watch_reply_lost=failed):
                run = runner()
                run.collect = Mock()
                def control(_name, kind, **_fields):
                    if failed and kind == "watch":
                        raise RuntimeError("watch reply lost")
                    return {}
                run.ctl.side_effect = control
                if failed:
                    with self.assertRaisesRegex(RuntimeError, "watch reply lost"):
                        run.exercise()
                    run.drive_route.assert_not_called()
                else:
                    run.exercise()
                    self.assertTrue(run.evidence["paid_switching_accepted"])
                watches = [item for item in run.ctl.call_args_list if item.args[1] == "watch"]
                self.assertEqual(watches, [call("source", "watch", destination="identity-n03",
                                                max_rate_msat_per_kib=PRICE_CEILING)])
                self.assertTrue(run.watch_started)
                self.assertEqual(run.evidence["watch_calls"], 1)
                run.collect.assert_called_once_with()

    def test_mesh_restored_before_collection_on_each_cut_failure(self):
        for failed in ("mesh_down", "post_cut_phase", "failover"):
            with self.subTest(failure=failed):
                run = runner()
                events = []
                def cut():
                    events.append("down")
                    if failed == "mesh_down":
                        raise RuntimeError("cut command reply lost")
                def phase(name, **_fields):
                    if failed == "post_cut_phase" and name.startswith("cheaper provider left"):
                        raise RuntimeError("forward check after cut failed")
                def drive(provider, *_args):
                    if failed == "failover" and provider == "n02":
                        raise RuntimeError("working failover unavailable")
                run.nodes["n01"].mesh_down.side_effect = cut
                run.nodes["n01"].mesh_up.side_effect = lambda: events.append("up")
                run.phase.side_effect = phase
                run.drive_route.side_effect = drive
                run.collect = Mock(side_effect=lambda: events.append("collect"))
                with self.assertRaises(RuntimeError):
                    run.exercise()
                self.assertEqual(events, ["down", "up", "collect"])
                self.assertIn("acceptance_failure", run.evidence)
                self.assertFalse(run.evidence.get("paid_switching_accepted", False))
                run.collect.assert_called_once_with()
                self.assertEqual(sum(c.args[1] == "watch" for c in run.ctl.call_args_list), 1)

    def collection_runner(self):
        run, financial = runner(), FinancialFixture()
        run.fixture = financial.fixture()
        run.financial_checkpoint.return_value = financial.prior
        run.accounts.finances = financial.finances
        run.accounts.state_json = financial.state_json
        run.accounts.execute = financial.execute
        run.watch_started = True
        def control(name, kind, **_fields):
            if kind == "status":
                return paused_status(run)
            if kind == "pause_route_refresh":
                return {}
            return financial.ctl(name, kind)
        run.ctl.side_effect = control
        return run, financial

    def test_real_collector_settles_and_exports_source_first_once(self):
        run, financial = self.collection_runner()
        run.collect()
        self.assertEqual(run.ctl.call_args_list[:2], [
            call("source", "pause_route_refresh"), call("source", "status")])
        self.assertEqual([name for name, kind in financial.calls if kind == "settle"],
                         ["source", "n01", "n02", "n03"])
        self.assertEqual([name for name, kind in financial.calls if kind == "export"],
                         ["source", "n01", "n02"])
        self.assertEqual(financial.calls.count(("mint", "collect")), 3)
        self.assertEqual(financial.collected, 128)
        for node in run.nodes.values():
            node.stop.assert_called_once_with()
        before = list(financial.calls)
        with self.assertRaisesRegex(RuntimeError, "cannot be replayed"):
            run.collect()
        self.assertEqual(financial.calls, before)

    def test_pending_watch_or_ambiguous_checkpoint_never_reaches_collector(self):
        for failed in ("pause", "pending", "checkpoint"):
            with self.subTest(failure=failed):
                run = runner()
                run.watch_started = True
                run.ctl.return_value = paused_status(run, {} if failed == "pending" else None)
                if failed == "pause":
                    run.ctl.side_effect = RuntimeError("pause reply lost")
                if failed == "checkpoint":
                    run.financial_checkpoint.side_effect = RuntimeError("funding unresolved")
                with patch(MODULE + ".settle_and_collect") as collector:
                    with self.assertRaises(RuntimeError):
                        run.collect()
                    calls = list(run.ctl.call_args_list)
                    with self.assertRaisesRegex(RuntimeError, "cannot be replayed"):
                        run.collect()
                    self.assertEqual(run.ctl.call_args_list, calls)
                    collector.assert_not_called()
                self.assertTrue(run.evidence["collection_attempted"])

    def test_uncertain_mint_collection_never_reexports_or_redeems_again(self):
        run, financial = self.collection_runner()
        def lost_reply(stage, value):
            if stage == "collect":
                raise RuntimeError("collection reply lost")
            return value
        financial.transform = lost_reply
        with self.assertRaisesRegex(RuntimeError, "collection reply lost"):
            run.collect()
        before = list(financial.calls)
        with self.assertRaisesRegex(RuntimeError, "cannot be replayed"):
            run.collect()
        self.assertEqual(financial.calls, before)
        self.assertEqual(list(financial.exports), ["source"])
        self.assertEqual(financial.calls.count(("mint", "collect")), 1)
        self.assertNotIn("mint", run.evidence)

    def test_restoration_failure_still_preserves_uncollected_mint_access(self):
        run = runner()
        _, run.forwards = self.forward_owner()
        with patch(MODULE + ".DiamondRun.finish", side_effect=RuntimeError("restore failed")):
            with self.assertRaisesRegex(RuntimeError, "restore failed"):
                run.finish()
        run.forwards.finish.assert_called_once_with(run.mint.request.return_value)
        run.forwards.retain.assert_called_once_with("RuntimeError")
        run.mint.finish.assert_not_called()
        self.assertEqual(run.evidence["mint_retained_for_recovery"], run.mint.info)
        self.assertFalse(run.evidence["passed"])


if __name__ == "__main__":
    unittest.main()
