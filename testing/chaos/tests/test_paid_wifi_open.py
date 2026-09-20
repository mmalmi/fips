"""Compose paid startup/recovery with the shared open-radio lifecycle, without funds or hosts."""

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_wifi import PaidWifiRun, main
from tests.test_paid_wifi_forwarding import FakeChild, FakeNode, URL


class OpenNode(FakeNode):
    def __init__(self, name, config, root, events, peers, opened):
        super().__init__(name, config)
        self.name = self.npub = name
        self.interface, self.state = "mesh0", str(root / name)
        self.mesh, self.mac = {"frequency": 5180}, name
        self.events, self.peers, self.open_mesh = events, peers, opened
        self.running = self.radio_open = self.prepared = False
        self.hide_peers = False
        self.balance = 0
        self.open_error = self.cleanup_error = None
        self.control = self.handle_control

    def baseline(self):
        if self.radio_open:
            raise ValueError("original radio restoration remains uncertain")
        return {"original": self.name, "original_accounts_unchanged": True}

    def prepare(self, _binary, config):
        self.config = config
        self.prepared = True
        self.events.append(("prepare", self.name))

    def begin_open_mesh(self):
        self.events.append(("radio", self.name))
        self.radio_open = True
        if self.open_error:
            raise self.open_error
        return self.verify_open_mesh()

    def verify_open_mesh(self):
        if not self.radio_open:
            raise ValueError("radio is not open")
        self.events.append(("verify_radio", self.name))
        return {"key_mgmt": "NONE", "limits": {"max_peer_links": 8}}

    def start(self):
        self.events.append(("start", self.name))
        self.running = True

    def handle_control(self, kind, action="ctl", **fields):
        self.events.append((kind, self.name))
        if action == "wallet":
            if self.running:
                raise AssertionError("offline wallet operation raced the running service")
            if kind == "import":
                if fields["token"] != "test-only-" + self.name:
                    raise AssertionError("wrong account grant")
                self.balance += 128
                return {}
            if kind == "balance":
                return {"mint_url": URL, "unit": "sat", "balance_sat": self.balance}
        if kind == "status":
            return {"peers": [{"npub": other.npub, "connected": True, "transport": "ethernet"}
                              for other in self.peers.values()
                              if other is not self and other.running and not self.hide_peers]}
        raise AssertionError((kind, action))

    def monetary_journals(self):
        return {"no_channels": True}

    def cleanup(self):
        self.events.append(("cleanup", self.name))
        self.running = False
        if self.cleanup_error:
            raise self.cleanup_error
        self.radio_open = False


class PaidOpenTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.events, self.nodes, self.children = [], {}, []
        self.issued = self.collected = 0
        self.uncertain_grant = False
        self.addCleanup(patch.stopall)

    def fixture(self, opened=True):
        inventory, binary, ssh_config = (self.root / name for name in ("inventory", "binary", "ssh_config"))
        inventory.write_text(json.dumps({"nodes": [{"host": name} for name in ("n01", "n02", "n03")]}))
        binary.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\xb7\x00")
        ssh_config.write_text("Host *\n HostName 127.0.0.1\n")
        args = SimpleNamespace(inventory=inventory, binary=binary, output=self.root / "out",
                               mint_binary=binary, mint_address="127.0.0.1", mint_ssh_forward=True,
                               open_mesh=opened)
        def node(spec, _run, _output, mesh):
            result = OpenNode(spec["host"], ssh_config, self.root, self.events, self.nodes, mesh)
            self.nodes[result.name] = result
            return result
        with patch("sim.wifi_discovery.Router", side_effect=node):
            run = PaidWifiRun(args)
        run.monitor = Mock(samples=[], errors=[])
        run.mint.start = Mock(return_value=URL)
        run.mint.process = Mock(returncode=0)
        run.mint.state.mkdir()
        (run.mint.state / "exports").mkdir()
        def request(body):
            self.events.append(("mint_" + body["type"], body.get("id")))
            if body["type"] == "issue":
                self.assertTrue(all(n.prepared and n.info_reads == 1 for n in self.nodes.values()))
                self.assertTrue(all(not n.running and not n.radio_open for n in self.nodes.values()))
                self.issued += body["amount_sat"]
                export = {"amount_sat": 128, "token": "test-only-" + body["id"]}
                (run.mint.state / "exports" / (body["id"] + ".json")).write_text(json.dumps(export))
                if self.uncertain_grant:
                    raise RuntimeError("lost grant response")
                return {"amount_sat": 128}
            if body["type"] == "report":
                return {"issued_sat": self.issued, "collected_sat": self.collected, "conserved": True}
            raise AssertionError(body)
        run.mint.request = Mock(side_effect=request)
        def spawn(argv, **_kwargs):
            child = FakeChild(self.nodes[argv[-1]], 100 + len(self.children))
            self.children.append(child)
            return child
        patch("sim.paid_wifi_forwarding.subprocess.run",
              return_value=Mock(returncode=0, stdout=b"hostname localhost\n")).start()
        patch("sim.paid_wifi_forwarding.subprocess.Popen", side_effect=spawn).start()
        return run

    def test_cli_requires_explicit_opt_in_and_preserves_default_sae_mode(self):
        base = ["paid_wifi", "--inventory", "inventory", "--binary", "binary", "--mint-binary", "mint",
                "--mint-address", "127.0.0.1", "--mint-ssh-forward", "--output", "output"]
        for extra, expected in (([], False), (["--open-mesh"], True)):
            with patch.object(sys, "argv", base + extra), patch("sim.paid_wifi.PaidWifiRun") as runner, \
                    patch("sim.paid_wifi.signal.signal"), patch("sim.paid_wifi.signal.alarm"), \
                    patch("sim.paid_wifi.os.umask"):
                main()
                self.assertEqual(runner.call_args.args[0].open_mesh, expected)
                runner.return_value.execute.assert_called_once_with()

    def test_outage_target_requires_active_mode_before_starting_any_run(self):
        base = ["paid_wifi", "--inventory", "inventory", "--binary", "binary", "--mint-binary", "mint",
                "--mint-address", "127.0.0.1", "--mint-ssh-forward", "--output", "output"]
        for node in ("n02", "n03"):
            with self.subTest(node=node), patch.object(sys, "argv", base + ["--outage-node", node]), \
                    patch("sim.paid_wifi.PaidWifiRun") as runner, \
                    patch("sim.paid_wifi.signal.alarm") as alarm, patch("sys.stderr"), \
                    self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)
            runner.assert_not_called()
            alarm.assert_not_called()
        for node in (None, "n02", "n03"):
            extra = ["--active-outage"] + (["--outage-node", node] if node else [])
            with self.subTest(node=node), patch.object(sys, "argv", base + extra), \
                    patch("sim.paid_wifi.PaidWifiRun") as runner, \
                    patch("sim.paid_wifi.signal.signal"), patch("sim.paid_wifi.signal.alarm"), \
                    patch("sim.paid_wifi.os.umask"):
                main()
                args = runner.call_args.args[0]
                self.assertTrue(args.active_outage)
                self.assertEqual(args.outage_node, node)
                runner.return_value.execute.assert_called_once_with()

    def test_brief_outage_requires_active_mode_before_any_run(self):
        base = ["paid_wifi", "--inventory", "inventory", "--binary", "binary", "--mint-binary", "mint",
                "--mint-address", "127.0.0.1", "--mint-ssh-forward", "--output", "output",
                "--brief-outage"]
        with patch.object(sys, "argv", base), patch("sim.paid_wifi.PaidWifiRun") as runner, \
                patch("sim.paid_wifi.signal.alarm") as alarm, patch("sys.stderr"), \
                self.assertRaises(SystemExit) as error:
            main()
        self.assertEqual(error.exception.code, 2)
        runner.assert_not_called()
        alarm.assert_not_called()
        with patch.object(sys, "argv", base + ["--active-outage"]), \
                patch("sim.paid_wifi.PaidWifiRun") as runner, \
                patch("sim.paid_wifi.signal.signal"), patch("sim.paid_wifi.signal.alarm"), \
                patch("sim.paid_wifi.os.umask"):
            main()
        self.assertTrue(runner.call_args.args[0].brief_outage)
        runner.return_value.execute.assert_called_once_with()
        with self.assertRaisesRegex(ValueError, "requires --active-outage"):
            PaidWifiRun(SimpleNamespace(brief_outage=True, active_outage=False))

    def test_paid_open_launch_funds_stopped_accounts_then_late_joins_third_radio(self):
        run = self.fixture()
        run.setup()
        first_radio = self.events.index(("radio", "n01"))
        third_radio = self.events.index(("radio", "n03"))
        for name in self.nodes:
            self.assertLess(self.events.index(("balance", name)), first_radio)
        for name in ("n01", "n02"):
            self.assertLess(self.events.index(("verify_radio", name), first_radio + 1), third_radio)
            self.assertLess(self.events.index(("start", name)), third_radio)
        self.assertEqual(self.issued, 384)
        self.assertTrue(all(n.balance == 128 and n.radio_open for n in self.nodes.values()))
        for node in self.nodes.values():
            self.assertEqual(node.config["neighbors"], [])
            self.assertEqual(node.config["neighbor_admission"], "authenticated_adjacent")
            terms = node.config["terms"]
            self.assertEqual((terms["buyer_budget_sat"], terms["fee_msat_per_kib"]), (64, 1024))
            self.assertEqual((terms["controller"]["channel_capacity_sat"],
                              terms["controller"]["max_wallet_spend_sat"]), (32, 128))
        self.assertEqual(run.evidence["radio_mode"], "temporary_open_mesh")
        self.assertTrue(run.forwards.info["verified_before_issuance"])
        # Model independently verified collection: exercise only cleanup composition here.
        self.collected, run.evidence["passed"] = 384, True
        run.finish()
        self.assertTrue(all(not n.radio_open and not n.running for n in self.nodes.values()))
        self.assertTrue(all(c.poll() is not None for c in self.children))
        run.mint.process.terminate.assert_called_once_with()

    def test_late_radio_failure_restores_radios_but_preserves_funded_profiles_and_mint(self):
        run = self.fixture()
        run.exercise = Mock()
        self.nodes["n03"].open_error = ValueError("late radio join failed")
        with self.assertRaises(RuntimeError):
            run.execute()
        run.exercise.assert_not_called()
        self.assertEqual(run.evidence["failure"], "ValueError")
        self.assertEqual(self.issued, 384)
        self.assertEqual([n.balance for n in self.nodes.values()], [128, 128, 128])
        self.assertTrue(all(not n.radio_open and not n.running for n in self.nodes.values()))
        self.assertTrue(run.forwards.info["retained_for_recovery"])
        self.assertTrue(all(c.poll() is None for c in self.children))
        run.mint.process.terminate.assert_not_called()
        self.assertEqual(run.evidence["cleanup_errors"], [])
        self.assertTrue(run.evidence["persistent_test_profiles_retained"])

    def test_uncertain_radio_restoration_cannot_discard_the_mint_or_funded_accounts(self):
        run = self.fixture()
        run.exercise = Mock()
        self.nodes["n02"].cleanup_error = ValueError("owned restoration remains uncertain")
        with self.assertRaises(RuntimeError):
            run.execute()
        self.assertTrue(self.nodes["n02"].radio_open)
        self.assertTrue(run.evidence["cleanup_errors"])
        self.assertFalse(run.evidence["passed"])
        self.assertTrue(run.forwards.info["retained_for_recovery"])
        self.assertTrue(all(n.balance == 128 for n in self.nodes.values()))
        run.mint.process.terminate.assert_not_called()
        run.monitor.close.assert_called_once_with()

    def test_uncertain_grant_keeps_export_and_forwards_without_joining_any_radio(self):
        run = self.fixture()
        run.exercise = Mock()
        self.uncertain_grant = True
        with self.assertRaises(RuntimeError):
            run.execute()
        run.exercise.assert_not_called()
        self.assertEqual(self.issued, 128)
        self.assertFalse(any(kind in ("radio", "start", "import") for kind, _ in self.events))
        self.assertTrue((run.mint.state / "exports" / "n01.json").exists())
        self.assertTrue(run.forwards.info["retained_for_recovery"])
        run.mint.process.terminate.assert_not_called()

    def test_pair_discovery_failure_does_not_join_third_radio_or_discard_funds(self):
        run = self.fixture()
        run.exercise = Mock()
        self.nodes["n02"].hide_peers = True
        def once(description, condition, _seconds):
            observed = condition()
            if description == "two open-radio peers discovered before late join":
                self.assertFalse(observed)
                raise RuntimeError("pair discovery deadline")
            self.assertTrue(observed, description)
            return observed
        with patch("sim.wifi_discovery.eventually", side_effect=once), self.assertRaises(RuntimeError):
            run.execute()
        run.exercise.assert_not_called()
        self.assertNotIn(("radio", "n03"), self.events)
        self.assertEqual(self.issued, 384)
        self.assertTrue(all(not n.radio_open and not n.running for n in self.nodes.values()))
        self.assertTrue(run.forwards.info["retained_for_recovery"])
        self.assertTrue(all(c.poll() is None for c in self.children))
        run.mint.process.terminate.assert_not_called()

    def test_default_paid_mode_funds_and_starts_without_changing_radio_profiles(self):
        run = self.fixture(opened=False)
        run.setup()
        self.assertEqual(run.evidence["radio_mode"], "saved_sae")
        self.assertFalse(any(kind == "radio" for kind, _ in self.events))
        self.assertEqual(self.issued, 384)


if __name__ == "__main__":
    unittest.main()
