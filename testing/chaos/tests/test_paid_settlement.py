"""Financial closure and process ownership; no Docker or live funds are used."""

import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_settlement import STOP_RELAY, settle_and_collect, stop_relay


NODES = ("n01", "n02", "n03")
MINT = "http://private-test:3338"


def finances(settled=False):
    result = {}
    for node, paid in zip(NODES, (7, 0, 9)):
        funded = node != "n02"
        signed = paid if settled else max(paid - 2, 0)
        refund = 32 - paid if settled and funded else 0
        result[node] = {
            "funding": {f"fund-{node}": (f"channel-{node}", f"operation-{node}")} if funded else {},
            "signed": {f"channel-{node}": signed} if funded else {},
            "authorized": signed, "remaining": 64 - signed,
            "budget": {"pending_reserved_sat": 0, "wallet_debited_sat": 32 if funded else 0,
                       "wallet_refunded_sat": refund, "locked_sat": 32 if funded and not settled else 0,
                       "exposure_sat": (32 if funded else 0) - refund},
            "wallet": [], "credited": {},
        }
    return result


class FakeRun:
    def __init__(self):
        self.nodes = dict.fromkeys(NODES)
        self.name = "a12b34c5"
        self.containers = {node: str(index) * 64 for index, node in enumerate(NODES, 1)}
        self.evidence = {"phases": []}
        self.prior = finances()
        self.settled = finances(True)
        self.reports = {node: [] for node in NODES}
        for node, paid in (("n01", 7), ("n03", 9)):
            self.reports[node] = [{"channel_id": f"channel-{node}",
                                   "value_after_stage1_sat": 32, "paid_sat": paid,
                                   "receiver_fee_reserve_sat": 0, "refunded_sat": 32 - paid,
                                   "fee_sat": 0}]
        self.balances = {"n01": 121, "n02": 144, "n03": 119}
        self.collected = 0
        self.calls = []
        self.exports = {}
        self.transform = lambda _action, value: value

    def ctl(self, node, kind):
        self.calls.append((node, kind))
        assert kind == "settle"
        return {"settlements": copy.deepcopy(self.reports[node])}

    def finances(self):
        return copy.deepcopy(self.settled)

    def state_json(self, node, relative):
        assert relative == f"exports/collect-{node}.json"
        return self.transform("saved_export", copy.deepcopy(self.exports[node]))

    def execute(self, node, binary, action, request):
        kind = request["type"]
        self.calls.append((node, kind))
        if kind == "report":
            value = {"test_only": True, "url": MINT, "issued_sat": 384,
                     "external_funding_sat": 384, "total_accounted_sat": 384,
                     "collected_sat": self.collected, "conserved": True}
            return self.transform("final_report" if self.collected else "initial_report", value)
        if kind == "balance":
            return self.transform("balance", {"mint_url": MINT, "unit": "sat",
                                              "balance_sat": self.balances[node]})
        if kind == "export":
            amount = request["amount_sat"]
            assert node not in self.exports
            assert amount == self.balances[node]
            self.exports[node] = {"mint_url": MINT, "unit": "sat", "amount_sat": amount,
                                  "send_fee_sat": 0, "operation_id": f"export-{node}",
                                  "token": f"private-token-{node}"}
            self.balances[node] = 0
            return self.transform("export", {
                "path": f"/tmp/bench-state/exports/{request['id']}.json",
                "amount_sat": amount, "operation_id": f"export-{node}"})
        assert kind == "collect" and node == "mint"
        payment = next(p for p in self.exports.values() if p["token"] == request["token"])
        self.collected += payment["amount_sat"]
        return self.transform("collect", {"mint_url": MINT, "unit": "sat",
                                          "amount_sat": payment["amount_sat"]})


class SettlementTests(unittest.TestCase):
    def run_closure(self, run):
        with patch("sim.paid_settlement.stop_relay") as stop:
            settle_and_collect(run, run.prior)
            self.assertEqual([call.args[1] for call in stop.call_args_list], list(NODES))

    def test_original_channels_settle_and_every_account_is_collected_once(self):
        run = FakeRun()
        self.run_closure(run)
        self.assertEqual(run.calls[:4], [("mint", "report"), *( (n, "settle") for n in NODES)])
        self.assertEqual(run.collected, 384)
        self.assertEqual(run.balances, dict.fromkeys(NODES, 0))
        for node in NODES:
            self.assertEqual(run.calls.count((node, "export")), 1)
        self.assertEqual(run.calls.count(("mint", "collect")), 3)
        self.assertEqual(run.evidence["mint"]["collected_sat"], 384)
        self.assertNotIn("private-token", json.dumps(run.evidence))
        self.assertNotIn('"token"', json.dumps(run.evidence))

    def test_changed_original_account_or_funding_terms_fail_before_any_action(self):
        changes = (
            lambda r: r.prior["n01"]["budget"].update(wallet_debited_sat=33),
            lambda r: r.prior["n01"].update(remaining=64),
            lambda r: r.prior["n02"]["funding"].update({"extra": ("other", "new")}),
            lambda r: r.prior.pop("n03"),
        )
        for index, mutate in enumerate(changes):
            with self.subTest(case=index):
                run = FakeRun()
                mutate(run)
                with self.assertRaises(RuntimeError):
                    self.run_closure(run)
                self.assertEqual(run.calls, [])

    def test_missing_duplicate_or_wrong_owner_report_prevents_wallet_export(self):
        def missing(run):
            run.reports["n03"] = []

        def duplicate(run):
            run.reports["n01"] *= 2

        def wrong_owner(run):
            run.reports["n02"] = run.reports.pop("n03")

        for mutate in (missing, duplicate, wrong_owner):
            with self.subTest(mutate=mutate.__name__):
                run = FakeRun()
                mutate(run)
                with patch("sim.paid_settlement.stop_relay") as stop, self.assertRaises(RuntimeError):
                    settle_and_collect(run, run.prior)
                stop.assert_not_called()
                self.assertFalse(run.exports)

    def test_changed_funding_and_budget_or_incomplete_refund_fail_before_stop(self):
        changes = (
            lambda r: r.settled["n01"]["funding"].update({"extra": ("other", "new")}),
            lambda r: r.settled["n01"]["budget"].update(locked_sat=32),
            lambda r: r.settled["n01"]["budget"].update(pending_reserved_sat=1),
            lambda r: r.settled["n01"]["budget"].update(wallet_debited_sat=0),
            lambda r: r.settled["n01"]["budget"].update(wallet_refunded_sat=24),
            lambda r: r.settled["n01"]["budget"].update(exposure_sat=0),
            lambda r: r.settled["n01"].update(remaining=64, authorized=0),
            lambda r: r.settled["n01"]["signed"].update({"channel-n01": 6}),
        )
        for index, mutate in enumerate(changes):
            with self.subTest(case=index):
                run = FakeRun()
                mutate(run)
                with patch("sim.paid_settlement.stop_relay") as stop, self.assertRaises(RuntimeError):
                    settle_and_collect(run, run.prior)
                stop.assert_not_called()

    def test_settlement_must_return_exact_zero_fee_channel_value(self):
        for key, value in (("fee_sat", 1), ("receiver_fee_reserve_sat", 1),
                           ("refunded_sat", 24), ("paid_sat", True),
                           ("value_after_stage1_sat", 33)):
            with self.subTest(field=key):
                run = FakeRun()
                run.reports["n01"][0][key] = value
                with self.assertRaises(RuntimeError):
                    self.run_closure(run)
                self.assertFalse(run.exports)

    def test_stop_failure_never_attempts_offline_wallet_access(self):
        run = FakeRun()
        with patch("sim.paid_settlement.stop_relay", side_effect=RuntimeError("shutdown failed")):
            with self.assertRaises(RuntimeError):
                settle_and_collect(run, run.prior)
        self.assertFalse(any(kind == "balance" for _, kind in run.calls))

    def test_lost_wallet_value_is_rejected_before_any_export(self):
        run = FakeRun()
        run.balances["n02"] -= 1
        with self.assertRaises(RuntimeError):
            self.run_closure(run)
        self.assertFalse(run.exports)

    def test_invalid_export_scope_fee_or_identity_never_reaches_collection(self):
        for stage, field, value in (("export", "path", "/wrong"),
                                    ("export", "amount_sat", 1),
                                    ("saved_export", "send_fee_sat", 1),
                                    ("saved_export", "operation_id", "different"),
                                    ("saved_export", "mint_url", "http://other")):
            with self.subTest(stage=stage, field=field):
                run = FakeRun()
                def transform(action, result):
                    if action == stage:
                        result[field] = value
                    return result
                run.transform = transform
                with self.assertRaises(RuntimeError):
                    self.run_closure(run)
                self.assertNotIn(("mint", "collect"), run.calls)

    def test_failed_or_partial_collection_is_not_retried(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                run = FakeRun()
                def transform(action, result):
                    if action == "collect":
                        if ambiguous:
                            raise RuntimeError("reply lost")
                        result["amount_sat"] -= 1
                    return result
                run.transform = transform
                with self.assertRaises(RuntimeError):
                    self.run_closure(run)
                self.assertEqual(run.calls.count(("mint", "collect")), 1)
                self.assertEqual(len(run.exports), 1)
                self.assertNotIn("mint", run.evidence)

    def test_conserved_but_not_fully_collected_is_rejected(self):
        run = FakeRun()
        def transform(action, result):
            if action == "final_report":
                result["collected_sat"] = 383
            return result
        run.transform = transform
        with self.assertRaises(RuntimeError):
            self.run_closure(run)
        self.assertNotIn("mint", run.evidence)

    def test_nonempty_exported_wallet_is_rejected(self):
        run = FakeRun()
        def transform(action, result):
            if action == "balance" and result["balance_sat"] == 0:
                result["balance_sat"] = 1
            return result
        run.transform = transform
        with self.assertRaises(RuntimeError):
            self.run_closure(run)
        self.assertEqual(run.calls.count(("mint", "collect")), 1)
        self.assertNotIn("mint", run.evidence)

    def test_changed_issuance_or_prior_collection_fails_before_settlement(self):
        for key, value in (("issued_sat", 385), ("collected_sat", 1),
                           ("external_funding_sat", 385), ("conserved", False)):
            with self.subTest(field=key):
                run = FakeRun()
                def transform(action, result):
                    if action == "initial_report":
                        result[key] = value
                    return result
                run.transform = transform
                with self.assertRaises(RuntimeError):
                    self.run_closure(run)
                self.assertEqual(run.calls, [("mint", "report")])


class StopTests(unittest.TestCase):
    def test_stop_checks_exact_owned_container_before_executing(self):
        run = FakeRun()
        identity = run.containers["n01"]
        with patch("sim.paid_settlement.inspect_owned", return_value={
            "Id": identity, "State": {"Running": True}}) as inspect, \
             patch("sim.paid_settlement.docker", return_value="stopped") as command:
            stop_relay(run, "n01")
            inspect.assert_called_once_with("container", identity, run.name)
            command.assert_called_once_with(
                ["exec", identity, "python3", "-c", STOP_RELAY], timeout=55)
        with patch("sim.paid_settlement.inspect_owned", side_effect=RuntimeError("unowned")), \
             patch("sim.paid_settlement.docker") as command, self.assertRaises(RuntimeError):
            stop_relay(run, "n01")
        command.assert_not_called()

    def script(self, *, exe="/opt/bench/fips-relay", argv=None, polls=None, pid="25"):
        argv = argv if argv is not None else b"/opt/bench/fips-relay\0run\0/run/bench/config.json\0"
        class FakePath:
            def __init__(self, path):
                self.path = path

            def __truediv__(self, part):
                return FakePath(f"{self.path}/{part}")

            def read_text(self):
                return pid

            def read_bytes(self):
                return argv

        modules = {"os": SimpleNamespace(pidfd_open=Mock(return_value=55),
                                          readlink=Mock(return_value=exe), close=Mock()),
                   "signal": SimpleNamespace(SIGTERM=15, pidfd_send_signal=Mock()),
                   "select": SimpleNamespace(select=Mock(side_effect=polls or [([], [], []), ([55], [], [])])),
                   "pathlib": SimpleNamespace(Path=FakePath)}
        return modules

    def test_process_identity_is_verified_before_signaling_and_wait_is_bounded(self):
        modules = self.script()
        with patch.dict(sys.modules, modules), patch("builtins.print"):
            exec(STOP_RELAY, {})
        modules["os"].pidfd_open.assert_called_once_with(25)
        modules["signal"].pidfd_send_signal.assert_called_once_with(55, 15)
        self.assertEqual(modules["select"].select.call_args.args, ([55], [], [], 45))
        modules["os"].close.assert_called_once_with(55)

    def test_wrong_process_argv_or_already_exited_is_never_signaled(self):
        for kwargs in ({"exe": "/bin/sleep"}, {"argv": b"wrong\0"},
                       {"polls": [([55], [], [])]}, {"pid": "1"}):
            with self.subTest(kwargs=kwargs):
                modules = self.script(**kwargs)
                with patch.dict(sys.modules, modules), self.assertRaises(RuntimeError):
                    exec(STOP_RELAY, {})
                modules["signal"].pidfd_send_signal.assert_not_called()

    def test_timeout_does_not_escalate_to_forced_kill(self):
        modules = self.script(polls=[([], [], []), ([], [], [])])
        with patch.dict(sys.modules, modules), self.assertRaises(RuntimeError):
            exec(STOP_RELAY, {})
        modules["signal"].pidfd_send_signal.assert_called_once_with(55, 15)
        modules["os"].close.assert_called_once_with(55)


if __name__ == "__main__":
    unittest.main()
