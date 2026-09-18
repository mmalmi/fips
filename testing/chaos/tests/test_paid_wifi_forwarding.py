"""Private test-mint forwarding lifecycle without SSH, routers or issued money."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_wifi import PaidWifiRun
from sim.paid_wifi_forwarding import LOOPBACKS, MintForwards, finish_mint, listeners
from sim.paid_wifi_mint import LocalMint
from sim.wifi_remote import Router


PORT = 41234
URL = f"http://127.0.0.1:{PORT}"
COLLECTED = {"issued_sat": 384, "collected_sat": 384, "conserved": True}


def sockets(addresses, port=PORT):
    return ("  sl  local_address rem_address st\n" + "".join(
        f"  {i}: {address}:{port:04X} 00000000:0000 0A 0:0 0:0 0 0 0\n"
        for i, address in enumerate(addresses))).encode()


class FakeNode:
    ssh_args = Router.ssh_args

    def __init__(self, name, config):
        self.host, self.spec = name, {"ssh_config": str(config)}
        self.active = False
        self.preexisting = []
        self.bound = sorted(LOOPBACKS)
        self.info_reads = 0
        self.info_error = None
        self.control = Mock(return_value={"mint_url": URL, "unit": "sat", "balance_sat": 128})

    def remote(self, args, **_kwargs):
        if args[0] == "cat":
            return sockets(self.preexisting + (self.bound if self.active else []))
        if args[0] == "uclient-fetch":
            self.info_reads += 1
            if self.info_error:
                raise self.info_error
            return b'{"name":"test mint"}'
        raise AssertionError(args)


class FakeChild:
    def __init__(self, node, pid):
        self.node, self.pid, self.returncode = node, pid, None
        self.node.active = True
        self.terminate = Mock(side_effect=self.stop)
        self.wait = Mock(side_effect=lambda **_kwargs: self.returncode)

    def poll(self):
        return self.returncode

    def stop(self):
        self.node.active = False
        self.returncode = -15


class ForwardingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / "ssh_config"
        self.config.write_text("Host router-*\n  HostName 127.0.0.1\n")
        self.nodes = {f"n0{i}": FakeNode(f"router-{i}", self.config) for i in range(1, 4)}
        self.owner = MintForwards(self.nodes, URL, self.root)
        self.spawned = []
        self.effective = Mock(returncode=0, stdout=b"hostname 127.0.0.1\n")
        self.addCleanup(patch.stopall)
        patch("sim.paid_wifi_forwarding.subprocess.run", return_value=self.effective).start()
        self.popen = patch("sim.paid_wifi_forwarding.subprocess.Popen", side_effect=self.spawn).start()

    def spawn(self, args, **_kwargs):
        node = next(n for n in self.nodes.values() if n.host == args[-1])
        child = FakeChild(node, 100 + len(self.spawned))
        self.spawned.append(child)
        return child

    def test_start_checks_every_listener_and_http_before_issuance(self):
        self.owner.start()
        self.assertTrue(self.owner.info["verified_before_issuance"])
        self.assertEqual(len(self.spawned), 3)
        for node in self.nodes.values():
            self.assertEqual(node.info_reads, 1)
        for call in self.popen.call_args_list:
            args = call.args[0]
            for setting in ("BatchMode=yes", "ConnectTimeout=5", "ControlMaster=no",
                            "ControlPath=none", "ExitOnForwardFailure=yes", "ServerAliveInterval=5",
                            "ServerAliveCountMax=3", "ForkAfterAuthentication=no",
                            "ForwardAgent=no", "ForwardX11=no"):
                self.assertIn(setting, args)
            self.assertEqual(args[args.index("-F") + 1], str(self.config.resolve()))
            self.assertEqual(args[args.index("-R") + 1], f"127.0.0.1:{PORT}:127.0.0.1:{PORT}")
            self.assertTrue(call.kwargs["start_new_session"])
        saved = json.loads((self.root / "mint-forwards.json").read_text())
        self.assertEqual(saved, self.owner.info)
        self.assertEqual(set(saved["observations"]), set(self.nodes))

    def test_refuses_collision_before_starting_any_child(self):
        self.nodes["n03"].preexisting = ["0100007F"]
        with self.assertRaisesRegex(RuntimeError, "already has"):
            self.owner.start()
        self.popen.assert_not_called()
        self.owner.finish({**COLLECTED, "issued_sat": 0, "collected_sat": 0})
        self.assertEqual(self.nodes["n03"].preexisting, ["0100007F"])

    def test_refuses_additional_inventory_forwarding(self):
        for setting in ("localforward 99 localhost:99", "remoteforward 99 localhost:99",
                        "dynamicforward [127.0.0.1]:49999"):
            self.effective.stdout = f"hostname localhost\n{setting}\n".encode()
            with self.subTest(setting=setting), self.assertRaisesRegex(RuntimeError, "another forwarding"):
                self.owner.start()
        self.popen.assert_not_called()

    def test_rejects_wildcard_even_with_valid_loopback_listener(self):
        self.nodes["n02"].bound += ["00000000"]
        with self.assertRaisesRegex(ValueError, "exclusively loopback"):
            self.owner.start()
        self.assertFalse(self.owner.info["verified_before_issuance"])
        self.owner.finish({**COLLECTED, "issued_sat": 0, "collected_sat": 0})
        self.assertTrue(all(child.returncode is not None for child in self.spawned))

    def test_listener_observation_ignores_an_unrelated_port(self):
        node = Mock()
        node.remote.return_value = sockets(["00000000"], PORT + 1) + sockets(LOOPBACKS)
        self.assertEqual(listeners(node, PORT), sorted(LOOPBACKS))

    def test_partial_start_failure_cleans_only_the_owned_child_when_zero_issued(self):
        def spawn_once(args, **kwargs):
            if self.spawned:
                raise OSError("cannot spawn")
            return self.spawn(args, **kwargs)
        self.popen.side_effect = spawn_once
        with self.assertRaises(OSError):
            self.owner.start()
        self.assertEqual(set(self.owner.children), {"n01"})
        self.owner.finish({**COLLECTED, "issued_sat": 0, "collected_sat": 0})
        self.spawned[0].terminate.assert_called_once_with()
        self.assertFalse(self.nodes["n01"].active)

    def test_dead_tunnel_is_never_replaced(self):
        self.owner.start()
        self.spawned[1].stop()
        with self.assertRaisesRegex(ValueError, "never replace"):
            self.owner.check()
        self.assertEqual(self.popen.call_count, 3)

    def test_uncollected_or_unconserved_money_retains_all_children(self):
        self.owner.start()
        for report in ({**COLLECTED, "collected_sat": 383}, {**COLLECTED, "conserved": False}):
            result = self.owner.finish(report)
            self.assertTrue(result["retained_for_recovery"])
        for child in self.spawned:
            child.terminate.assert_not_called()

    def test_complete_collection_stops_children_and_verifies_ports_removed(self):
        self.owner.start()
        result = self.owner.finish(COLLECTED)
        self.assertFalse(result["retained_for_recovery"])
        self.assertTrue(result["stopped"])
        for child in self.spawned:
            child.terminate.assert_called_once_with()
            child.wait.assert_called_once_with(timeout=20)
            self.assertFalse(child.node.active)

    def run_fixture(self):
        run = object.__new__(PaidWifiRun)
        run.args = SimpleNamespace(mint_ssh_forward=True)
        run.nodes, run.root, run.mint_url = self.nodes, self.root, URL
        run.forwards = None
        run.evidence = {"passed": True}
        run.mint = Mock(info={"pid": 12})
        run.mint.request.return_value = COLLECTED
        run.mint.finish.return_value = {"retained_for_recovery": False}
        run.save, run.phase = Mock(), Mock()
        return run

    def test_failed_info_on_one_router_prevents_every_grant(self):
        run = self.run_fixture()
        self.nodes["n03"].info_error = ValueError("mint unavailable")
        with self.assertRaises(ValueError):
            run.before_launch()
        run.mint.grant.assert_not_called()
        self.assertTrue(all(not n.control.called for n in self.nodes.values()))

    def test_funding_starts_only_after_all_three_http_checks(self):
        run = self.run_fixture()
        def grant(_name):
            self.assertTrue(all(n.info_reads == 1 for n in self.nodes.values()))
            self.assertTrue(run.forwards.info["verified_before_issuance"])
            return "test-only-placeholder"
        run.mint.grant.side_effect = grant
        run.before_launch()
        self.assertEqual(run.mint.grant.call_count, 3)

    def test_tunnel_death_during_grant_prevents_import_and_further_issuance(self):
        run = self.run_fixture()
        def interrupted(_name):
            self.spawned[1].stop()
            return "test-only-placeholder"
        run.mint.grant.side_effect = interrupted
        with self.assertRaisesRegex(ValueError, "never replace"):
            run.before_launch()
        run.mint.grant.assert_called_once_with("n01")
        self.assertTrue(all(not node.control.called for node in self.nodes.values()))

    def test_uncertain_report_or_tunnel_stop_keeps_mint_and_other_tunnels(self):
        for kind in ("report", "stop"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                run = self.run_fixture()
                run.forwards = MintForwards(self.nodes, URL, Path(directory))
                run.forwards.start()
                if kind == "report":
                    run.mint.request.side_effect = subprocess.TimeoutExpired("report", 90)
                else:
                    self.spawned[-3].wait.side_effect = subprocess.TimeoutExpired("SSH stop", 20)
                with patch("sim.paid_wifi.WifiRun.finish"), self.assertRaises(RuntimeError):
                    run.finish()
                run.mint.finish.assert_not_called()
                self.assertTrue(run.forwards.info["retained_for_recovery"])
                self.assertTrue(self.nodes["n03"].active)
                for child in self.spawned:
                    child.stop()

    def test_uncertain_listener_removal_keeps_mint_and_remaining_tunnels(self):
        run = self.run_fixture()
        self.owner.start()
        run.forwards = self.owner
        # A foreign replacement listener must never be stopped by this harness.
        self.nodes["n01"].preexisting = ["0100007F"]
        def removal_check(_description, condition, _seconds):
            self.assertFalse(condition())
            raise RuntimeError("listener remains")
        with patch("sim.paid_wifi.WifiRun.finish"), patch(
                "sim.paid_wifi_forwarding.eventually", side_effect=removal_check):
            with self.assertRaises(RuntimeError):
                run.finish()
        run.mint.finish.assert_not_called()
        self.assertTrue(self.owner.info["retained_for_recovery"])
        self.assertTrue(self.nodes["n03"].active)
        self.assertEqual(self.nodes["n01"].preexisting, ["0100007F"])

    def test_mint_stop_follows_verified_tunnel_cleanup(self):
        run = self.run_fixture()
        self.owner.start()
        run.forwards = self.owner
        def finish():
            self.assertTrue(self.owner.info["stopped"])
            self.assertTrue(all(not node.active for node in self.nodes.values()))
            return {"retained_for_recovery": False}
        run.mint.finish.side_effect = finish
        with patch("sim.paid_wifi.WifiRun.finish"):
            run.finish()
        run.mint.finish.assert_called_once_with()

    def test_shared_cleanup_before_mint_start_preserves_prior_failure(self):
        binary = self.root / "unused-mint"
        binary.write_bytes(b"not executed")
        run = SimpleNamespace(mint=LocalMint(binary, "127.0.0.1", self.root),
                              forwards=None, evidence={"passed": False}, save=Mock())
        finish_mint(run)
        self.assertEqual(run.evidence, {"passed": False, "mint_cleanup": {"started": False}})
        self.popen.assert_not_called()
        run.save.assert_called_once_with()

    def test_shared_cleanup_keeps_uncollected_mint_without_forwards(self):
        run = self.run_fixture()
        run.mint.finish.return_value = {"retained_for_recovery": True, "issued_sat": 128,
                                        "collected_sat": 0}
        finish_mint(run)
        self.assertFalse(run.evidence["passed"])
        self.assertEqual(run.evidence["mint_cleanup"], run.mint.finish.return_value)
        run.mint.request.assert_not_called()
        run.save.assert_called_once_with()

    def test_shared_cleanup_after_partial_forward_start_only_stops_owned_child(self):
        def spawn_once(args, **kwargs):
            if self.spawned:
                raise OSError("cannot spawn")
            return self.spawn(args, **kwargs)
        run = self.run_fixture()
        run.forwards = self.owner
        self.popen.side_effect = spawn_once
        with self.assertRaises(OSError):
            self.owner.start()
        run.evidence["passed"] = False
        run.mint.request.return_value = {**COLLECTED, "issued_sat": 0, "collected_sat": 0}
        finish_mint(run)
        self.assertEqual(len(self.spawned), 1)
        self.spawned[0].terminate.assert_called_once_with()
        self.assertTrue(run.evidence["mint_forward_cleanup"]["stopped"])
        self.assertFalse(run.evidence["passed"])
        run.mint.finish.assert_called_once_with()
        run.save.assert_called_once_with()

    def test_router_cleanup_error_survives_mint_retention(self):
        run = self.run_fixture()
        run.forwards = self.owner
        self.owner.start()
        run.mint.request.side_effect = subprocess.TimeoutExpired("report", 90)
        failure = OSError("original router cleanup error")
        with patch("sim.paid_wifi.WifiRun.finish", side_effect=failure):
            with self.assertRaises(OSError) as raised:
                run.finish()
        self.assertIs(raised.exception, failure)
        self.assertEqual(run.evidence["mint_cleanup_error"], "TimeoutExpired")
        self.assertFalse(run.evidence["passed"])
        self.assertEqual(run.evidence["mint_retained_for_recovery"], run.mint.info)
        self.assertTrue(self.owner.info["retained_for_recovery"])
        run.mint.finish.assert_not_called()
        run.save.assert_called_once_with()
        for child in self.spawned:
            child.terminate.assert_not_called()

    def test_lan_mode_uses_existing_reachability_and_mint_cleanup(self):
        run = self.run_fixture()
        run.args.mint_ssh_forward = False
        run.before_launch()
        self.popen.assert_not_called()
        self.assertIsNone(run.forwards)
        self.assertEqual(run.mint.grant.call_count, 3)
        with patch("sim.paid_wifi.WifiRun.finish"):
            run.finish()
        run.mint.finish.assert_called_once_with()

    def test_forwarding_rejects_nonloopback_or_ambiguous_urls(self):
        for url in ("http://0.0.0.0:9", "http://localhost:9", "http://127.0.0.1",
                    "https://127.0.0.1:9", "http://user@127.0.0.1:9", URL + "/other"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                MintForwards(self.nodes, url, self.root)


if __name__ == "__main__":
    unittest.main()
