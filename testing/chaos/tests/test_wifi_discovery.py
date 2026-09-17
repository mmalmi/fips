"""Exercise guard ownership and expired-lease behavior before a hardware outage."""

import json
import hashlib
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.wifi_discovery import WifiRun, free_config, validate_free_offer, validate_unfunded
from sim.wifi_remote import ETHERTYPE, Router, checked_name, checked_path
from sim.wifi_mesh import helpers as mesh_helpers, profile as mesh_profile


NFT = """import json,os,re,sys
from pathlib import Path
p=Path(os.environ['NFT_STATE']); tables=json.loads(p.read_text()); a=sys.argv[1:]
if a[:3]==['-j','list','tables']:
 print(json.dumps({'nftables':[{'table':{'name':k,'comment':v}} for k,v in tables.items()]}))
elif a[:3]==['-j','list','table']:
 if a[-1] not in tables: sys.exit(1)
 print(json.dumps({'nftables':[{'table':{'name':a[-1],'comment':tables[a[-1]]}}]}))
elif a[:2]==['delete','table']:
 tables.pop(a[-1]);p.write_text(json.dumps(tables))
elif a==['-f','-']:
 text=sys.stdin.read();m=re.search(r'create table netdev (\\w+) \\{ comment \"([^\"]+)\";',text)
 if not m or m[1] in tables:sys.exit(1)
 tables[m[1]]=m[2];p.write_text(json.dumps(tables))
else:sys.exit(2)
"""
JSONFILTER = """import json,sys
a=sys.argv[1:];r=json.load(open(a[a.index('-i')+1])) if '-i' in a else json.load(sys.stdin)
if a[-1]=='@.result':print(r['result']);sys.exit(0)
field='comment' if a[-1].endswith('.comment') else 'name'
for row in r['nftables']:
 if field in row.get('table',{}): print(row['table'][field])
"""
UBUS = """import json,os,sys
from pathlib import Path
p=Path(os.environ['MESH_STATE']);state=json.loads(p.read_text())
command=json.loads(sys.argv[-1])['command']
with open(os.environ['MESH_LOG'],'a') as f:f.write(command+'\\n')
result='FAIL';parts=command.split();network=state['network_id']
if command=='LIST_NETWORKS':
 result='network id / ssid / bssid / flags\\n'+str(network)+'\\tmesh\\tany\\t'+('[CURRENT]' if state['joined'] else '')
 if state.get('extra_network'):result+='\\n99\\tother\\tany\\t'
elif parts[0]=='GET_NETWORK' and int(parts[1])==network:
 result=str(state.get(parts[2],'FAIL'))
elif command=='STATUS':
 result='wpa_state='+('COMPLETED' if state['joined'] else 'DISCONNECTED')+'\\nid='+str(network)+'\\nfreq='+str(state['frequency'])
elif command=='MESH_GROUP_REMOVE mesh0':
 state['joined']=False;result='OK'
elif command=='MESH_GROUP_ADD '+str(network) and not os.environ.get('MESH_ADD_FAIL'):
 state['joined']=True;result='OK'
carrier=state['joined'] and not os.environ.get('MESH_NO_CARRIER')
Path(os.environ['MESH_NET'],'carrier').write_text('1' if carrier else '0')
p.write_text(json.dumps(state));print(json.dumps({'result':result}))
"""
IW = """import json,os
print(json.load(open(os.environ['MESH_STATE']))['mesh_fwding'])
"""


@unittest.skipUnless(sys.platform == "linux" and shutil.which("flock"),
                     "guard lifecycle checks need Linux procfs and flock")
class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        spec = {"host": "lab1", "interface": "mesh0", "management_interface": "br-lan",
                "original_binary": "/usr/sbin/original", "original_config": "/etc/original.json",
                "state_parent": "/etc/bench"}
        self.node = Router(spec, "123456789abc", self.root)
        self.remote = self.root / "remote"
        self.remote.mkdir()
        self.node.temporary = str(self.remote)
        self.node.binary = sys.executable
        self.node.config = str(self.remote / "config.json")
        self.tables = self.root / "tables.json"
        self.tables.write_text("{}")
        self.mesh_log = self.root / "mesh.log"
        self.mesh_state = self.root / "mesh.json"
        self.mesh_state.write_text(json.dumps({"network_id": 2, "mode": 5, "mesh_fwding": 0,
                                              "key_mgmt": "SAE", "ssid": '"mesh"',
                                              "frequency": 5180, "joined": True}))
        net = self.root / "sys-net" / "mesh0"
        net.mkdir(parents=True)
        for field, value in (("ifindex", "6"), ("address", "02:00:00:00:00:01"), ("carrier", "1")):
            (net / field).write_text(value)
        self.node.mesh = {"network_id": 2, "frequency": 5180, "ifindex": 6,
                          "mac": "02:00:00:00:00:01",
                          "ssid_sha256": hashlib.sha256(b'"mesh"').hexdigest()}
        with patch("sim.wifi_mesh.SYS_NET", net.parent), patch("sim.wifi_mesh.JOIN_ATTEMPTS", 1):
            (self.remote / "mesh.sh").write_text(mesh_helpers("mesh0", self.node.mesh))
        shim = self.root / "bin"
        shim.mkdir()
        for name, script in (("nft", NFT), ("jsonfilter", JSONFILTER), ("ubus", UBUS), ("iw", IW)):
            path = shim / name
            path.write_text("#!" + sys.executable + "\n" + script)
            path.chmod(0o700)
        self.env = dict(os.environ, PATH=str(shim) + ":" + os.environ["PATH"],
                        NFT_STATE=str(self.tables), MESH_STATE=str(self.mesh_state),
                        MESH_LOG=str(self.mesh_log), MESH_NET=str(net))
        self.guard = self.remote / "guard.sh"
        self.guard.write_bytes(self.node.guard_script())
        self.node.remote = self.local
        self.children = []

    def tearDown(self):
        if self.guard.exists():
            self.local(["sh", str(self.guard), "cleanup"])
        for process in self.children:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=8)
        self.temporary.cleanup()

    def local(self, command, data=None, timeout=20):
        result = subprocess.run(["sh", "-c", command] if isinstance(command, str) else command,
                                input=data, capture_output=True, env=self.env, timeout=timeout)
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        return result.stdout

    def start_guard(self):
        (self.remote / "active").touch()
        (self.remote / "heartbeat").write_text(Path("/proc/uptime").read_text().split(".")[0])
        process = subprocess.Popen(["sh", str(self.guard)], env=self.env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(process)
        for _ in range(100):
            if (self.remote / "guard-ready").exists():
                self.node.guarded(":")
                return process
            time.sleep(0.02)
        self.fail("guard did not acknowledge readiness")

    def mutations(self):
        return [line for line in self.mesh_log.read_text().splitlines()
                if line.startswith("MESH_GROUP_")] if self.mesh_log.exists() else []

    def set_mesh(self, **fields):
        state = json.loads(self.mesh_state.read_text())
        self.mesh_state.write_text(json.dumps({**state, **fields}))
        if "joined" in fields:
            (Path(self.env["MESH_NET"]) / "carrier").write_text("1" if fields["joined"] else "0")

    def test_expiry_restores_only_marked_mesh_and_owned_table(self):
        self.tables.write_text(json.dumps({self.node.table: self.node.table_owner, "household": "keep"}))
        for name in ("active", "heartbeat", "mesh-down", "table-created"):
            (self.remote / name).touch()
        (self.remote / "heartbeat").write_text("0")
        self.set_mesh(joined=False)
        self.local(["sh", str(self.guard)])
        self.assertEqual(self.mutations(), ["MESH_GROUP_ADD 2"])
        self.assertEqual(json.loads(self.tables.read_text()), {"household": "keep"})
        self.assertFalse((self.remote / "active").exists())

    def test_foreign_table_is_preserved_even_when_deletion_was_armed(self):
        self.tables.write_text(json.dumps({self.node.table: "different-owner"}))
        (self.remote / "table-created").touch()
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertEqual(json.loads(self.tables.read_text()), {self.node.table: "different-owner"})
        self.assertTrue((self.remote / "table-created").exists())
        self.assertEqual(self.mutations(), [])

    def test_existing_table_with_matching_owner_is_rejected_before_arming(self):
        self.start_guard()
        self.tables.write_text(json.dumps({self.node.table: self.node.table_owner}))
        with self.assertRaises(RuntimeError):
            self.node.install_filter("02:00:00:00:00:01")
        self.assertFalse((self.remote / "table-created").exists())
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertEqual(json.loads(self.tables.read_text()), {self.node.table: self.node.table_owner})

    def test_command_after_cleanup_cannot_disable_mesh_or_create_filter(self):
        self.start_guard()
        self.local(["sh", str(self.guard), "cleanup"])
        with self.assertRaises(RuntimeError):
            self.node.mesh_down()
        with self.assertRaises(RuntimeError):
            self.node.install_filter("02:00:00:00:00:01")
        self.assertEqual(self.mutations(), [])
        self.assertEqual(json.loads(self.tables.read_text()), {})

    def test_expired_lease_cannot_mutate_before_guard_next_poll(self):
        self.start_guard()
        (self.remote / "heartbeat").write_text("0")
        with self.assertRaises(RuntimeError):
            self.node.mesh_down()
        self.assertNotIn("MESH_GROUP_REMOVE mesh0", self.mutations())

    def test_cleanup_serializes_with_a_disruptive_command_already_in_flight(self):
        self.start_guard()
        entered, release = self.remote / "entered", self.remote / "release"
        command = (f"touch {entered}; while [ ! -f {release} ]; do sleep 0.02; done; "
                   f"touch {self.remote}/mesh-down; mesh_control 'MESH_GROUP_REMOVE mesh0'")
        with ThreadPoolExecutor(max_workers=1) as pool:
            action = pool.submit(self.node.guarded, command)
            for _ in range(100):
                if entered.exists():
                    break
                time.sleep(0.02)
            self.assertTrue(entered.exists())
            cleanup = subprocess.Popen(["sh", str(self.guard), "cleanup"], env=self.env)
            self.children.append(cleanup)
            time.sleep(0.1)
            self.assertIsNone(cleanup.poll(), "cleanup must wait for the active operation")
            self.assertTrue((self.remote / "active").exists())
            release.touch()
            action.result(timeout=3)
            self.assertEqual(cleanup.wait(timeout=3), 0)
        self.assertEqual(self.mutations(), ["MESH_GROUP_REMOVE mesh0", "MESH_GROUP_ADD 2"])
        self.assertFalse((self.remote / "mesh-down").exists())

    def test_stale_readiness_marker_does_not_authorize_a_command_without_guard(self):
        guard = self.start_guard()
        guard.kill()
        guard.wait(timeout=3)
        self.assertTrue((self.remote / "active").exists())
        with self.assertRaises(RuntimeError):
            self.node.mesh_down()
        self.assertEqual(self.mutations(), [])

    def delayed_launcher(self, before_lock):
        self.start_guard()
        entered, release = self.remote / "launch-entered", self.remote / "launch-release"
        barrier = f"touch {entered}; while [ ! -f {release} ]; do sleep 0.02; done\n".encode()
        script = self.node.start_script()
        boundary = b"#!/bin/sh\n" if before_lock else b"trap - EXIT\n"
        self.assertEqual(script.count(boundary), 1)
        script = script.replace(boundary, boundary + barrier)
        start = self.remote / "start.sh"
        start.write_bytes(script)
        (self.remote / "run").write_text(
            "from pathlib import Path\nimport time\nPath('candidate-started').touch()\ntime.sleep(30)\n")
        process = subprocess.Popen(["sh", str(start)], cwd=self.remote, env=self.env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(process)
        for _ in range(100):
            if entered.exists():
                return process, release
            time.sleep(0.02)
        self.fail("launcher did not reach its deterministic barrier")

    def test_child_dispatched_before_cleanup_cannot_start_after_cleanup(self):
        child, release = self.delayed_launcher(before_lock=True)
        self.local(["sh", str(self.guard), "cleanup"])
        release.touch()
        self.assertEqual(child.wait(timeout=3), 1)
        self.assertFalse((self.remote / "candidate-started").exists())

    def test_cleanup_joins_owned_pre_exec_launcher_before_finishing(self):
        child, release = self.delayed_launcher(before_lock=False)
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertEqual(child.wait(timeout=3), -15)
        release.touch()
        self.assertFalse((self.remote / "candidate-started").exists())
        self.assertFalse((self.remote / "candidate-stop-failed").exists())

    def test_cleanup_terminates_exact_candidate_but_not_unrelated_process(self):
        (self.remote / "run").write_text("import time; time.sleep(30)\n")
        candidate = subprocess.Popen([sys.executable, "run", self.node.config], cwd=self.remote)
        other = subprocess.Popen(["sleep", "30"])
        self.children.extend([candidate, other])
        (self.remote / "process.pid").write_text(str(other.pid))
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertIsNone(other.poll())
        (self.remote / "process.pid").write_text(str(candidate.pid))
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertEqual(candidate.wait(timeout=3), -15)
        self.assertIsNone(other.poll())

    def test_cleanup_does_not_terminate_a_process_with_additional_arguments(self):
        (self.remote / "run").write_text("import time; time.sleep(30)\n")
        other = subprocess.Popen([sys.executable, "run", self.node.config, "other"], cwd=self.remote)
        self.children.append(other)
        (self.remote / "process.pid").write_text(str(other.pid))
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertIsNone(other.poll())

    def test_stuck_candidate_is_stopped_and_forced_shutdown_remains_a_failure(self):
        with patch("sim.wifi_remote.CANDIDATE_STOP_SECONDS", 1):
            self.guard.write_bytes(self.node.guard_script())
        ready = self.remote / "ignoring-term"
        (self.remote / "run").write_text(
            "import signal,time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"Path({str(ready)!r}).touch()\ntime.sleep(30)\n")
        candidate = subprocess.Popen([sys.executable, "run", self.node.config], cwd=self.remote)
        self.children.append(candidate)
        for _ in range(100):
            if ready.exists():
                break
            time.sleep(.01)
        self.assertTrue(ready.exists())
        (self.remote / "process.pid").write_text(str(candidate.pid))
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertEqual(candidate.wait(timeout=3), -9)
        self.assertTrue((self.remote / "candidate-forced-stop").exists())
        self.assertFalse((self.remote / "candidate-stop-failed").exists())

    def test_failed_interface_restore_keeps_marker_and_continues_table_cleanup(self):
        self.env["MESH_ADD_FAIL"] = "1"
        self.set_mesh(joined=False)
        (self.remote / "mesh-down").touch()
        (self.remote / "table-created").touch()
        self.tables.write_text(json.dumps({self.node.table: self.node.table_owner}))
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertTrue((self.remote / "mesh-down").exists())
        self.assertEqual(json.loads(self.tables.read_text()), {})

    def test_mesh_preflight_derives_the_current_nonzero_network_id(self):
        with patch("sim.wifi_mesh.SYS_NET", Path(self.env["MESH_NET"]).parent):
            self.assertEqual(mesh_profile(self.local, "mesh0"), self.node.mesh)

    def test_leave_rejoin_preserves_interface_and_saved_network(self):
        self.start_guard()
        original = json.loads(self.mesh_state.read_text())
        self.node.mesh_down()
        self.assertFalse(json.loads(self.mesh_state.read_text())["joined"])
        self.assertTrue((self.remote / "mesh-down").exists())
        self.node.mesh_up()
        self.assertEqual(json.loads(self.mesh_state.read_text()), original)
        self.assertEqual((Path(self.env["MESH_NET"]) / "ifindex").read_text(), "6")
        self.assertFalse((self.remote / "mesh-down").exists())
        self.assertEqual(self.mutations(), ["MESH_GROUP_REMOVE mesh0", "MESH_GROUP_ADD 2"])

    def test_join_acknowledgment_without_carrier_does_not_disarm_recovery(self):
        self.set_mesh(joined=False)
        self.env["MESH_NO_CARRIER"] = "1"
        (self.remote / "mesh-down").touch()
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertTrue((self.remote / "mesh-down").exists())
        self.assertEqual(self.mutations(), ["MESH_GROUP_ADD 2"])

    def test_replaced_interface_is_not_reconfigured(self):
        self.set_mesh(joined=False)
        (Path(self.env["MESH_NET"]) / "ifindex").write_text("7")
        (self.remote / "mesh-down").touch()
        self.local(["sh", str(self.guard), "cleanup"])
        self.assertTrue((self.remote / "mesh-down").exists())
        self.assertEqual(self.mutations(), [])

    def test_changed_saved_policy_or_network_is_not_reconfigured(self):
        for change in ({"mesh_fwding": 1}, {"ssid": '"other"'}, {"network_id": 3},
                       {"extra_network": True}):
            with self.subTest(change=change):
                self.set_mesh(joined=False, mesh_fwding=0, ssid='"mesh"', network_id=2,
                              extra_network=False)
                self.set_mesh(**change)
                (self.remote / "mesh-down").touch()
                self.local(["sh", str(self.guard), "cleanup"])
                self.assertTrue((self.remote / "mesh-down").exists())
                self.assertEqual(self.mutations(), [])


class AcceptanceTests(unittest.TestCase):
    def test_false_trial_marker_may_be_omitted_but_true_or_paid_is_rejected(self):
        validate_free_offer({"price": {"msat": 0}})
        validate_free_offer({"price": {"msat": 0}, "trial": False})
        for offer in ({"price": {"msat": 0}, "trial": True}, {"price": {"msat": 1}}):
            with self.assertRaises(RuntimeError):
                validate_free_offer(offer)

    def test_beacon_observation_waits_for_a_late_starter_and_keeps_diagnostics(self):
        run = object.__new__(WifiRun)
        stats = {"beacons_sent": 1, "beacons_recv": 0}
        report = {"data": {"transports": [{"type": "ethernet", "name": "mesh0", "stats": stats}]}}
        run.nodes = {"n01": SimpleNamespace(interface="mesh0", native=lambda _: report)}
        run.evidence = {}
        run.save = Mock()
        self.assertIsNone(run.beacon_evidence())
        self.assertEqual(run.evidence["last_transport_observation"]["n01"], report)
        stats["beacons_recv"] = 1
        self.assertTrue(run.beacon_evidence())

    def test_late_management_failure_marks_evidence_and_fails_the_command(self):
        run = object.__new__(WifiRun)
        run.nodes = {}
        run.original = {}
        run.evidence = {"passed": True}
        run.monitor = SimpleNamespace(samples=[], errors=[])
        run.monitor.close = lambda: run.monitor.errors.append("late failure")
        with tempfile.TemporaryDirectory() as directory:
            run.root = Path(directory)
            with self.assertRaises(RuntimeError):
                run.finish()
            self.assertFalse(json.loads((run.root / "result.json").read_text())["passed"])

    def test_inventory_rejects_shell_syntax_and_root_paths(self):
        for value in ("-option", "mesh0;reboot", "x y", "a\nb"):
            with self.assertRaises(ValueError):
                checked_name(value)
        for value in ("/", "relative", "/etc/../root", "/tmp/a;reboot", "/tmp/a\nb"):
            with self.assertRaises(ValueError):
                checked_path(value)

    def test_profile_has_no_roster_or_non_mesh_fallback_or_paid_authority(self):
        config = free_config(SimpleNamespace(interface="mesh0", state="/etc/bench/state"))
        self.assertEqual(config["neighbors"], [])
        self.assertEqual(config["neighbor_admission"], "authenticated_adjacent")
        self.assertEqual(set(config["transports"]), {"ethernet"})
        self.assertEqual(config["transports"]["ethernet"]["mesh0"]["ethertype"], ETHERTYPE)
        self.assertEqual(config["terms"]["max_rate_msat_per_kib"], 0)
        self.assertEqual(config["terms"]["fee_msat_per_kib"], 0)

    def test_financial_validator_rejects_spending_or_history(self):
        clean = {"purchases": [], "history": [], "locked_sat": 0,
                 "remaining_budget_sat": 64, "funding_budget": {"spent_sat": 0}}
        validate_unfunded(clean)
        for field, value in (("purchases", [{}]), ("history", [{}]), ("locked_sat", 1),
                             ("remaining_budget_sat", 63), ("funding_budget", {"spent_sat": 1})):
            with self.assertRaises(RuntimeError):
                validate_unfunded({**clean, field: value})

    def test_isolation_requires_eviction_not_a_disconnected_flag(self):
        run = object.__new__(WifiRun)
        run.monitor = Mock()
        run.evidence = {}
        run.save = Mock()
        run.nodes = {name: SimpleNamespace(npub=name) for name in ("n01", "n02", "n03")}
        def peer(name, connected=True):
            return {"npub": name, "connected": connected, "transport": "ethernet"}
        statuses = {"n01": {"peers": [peer("n02")]},
                    "n02": {"peers": [peer("n01")]},
                    "n03": {"peers": [peer("n02", False)]}}
        run.ctl = lambda name, _: statuses[name]
        self.assertFalse(run.ready(line=True, isolated=True))
        statuses["n03"]["peers"] = []
        self.assertTrue(run.ready(line=True, isolated=True))

    def test_line_requires_old_direct_peers_to_be_removed(self):
        run = object.__new__(WifiRun)
        run.monitor = Mock()
        run.evidence = {}
        run.save = Mock()
        run.nodes = {name: SimpleNamespace(npub=name) for name in ("n01", "n02", "n03")}
        def peer(name, connected=True):
            return {"npub": name, "connected": connected, "transport": "ethernet"}
        statuses = {"n01": {"peers": [peer("n02"), peer("n03", False)]},
                    "n02": {"peers": [peer("n01"), peer("n03")]},
                    "n03": {"peers": [peer("n02"), peer("n01", False)]}}
        run.ctl = lambda name, _: statuses[name]
        self.assertFalse(run.ready(line=True))
        statuses["n01"]["peers"].pop()
        statuses["n03"]["peers"].pop()
        self.assertTrue(run.ready(line=True))


if __name__ == "__main__":
    unittest.main()
