"""Physical, roster-free Wi-Fi discovery and free forwarding on three OpenWrt routers.

Run from testing/chaos with an explicit private inventory, verified ARM64 binary
and new output directory. Original accounts/services remain running. No mint,
money, package or persisted network configuration changes. Default mode uses
the saved SAE profile and filters only the experimental EtherType. Explicit
--open-mesh temporarily isolates original EtherTypes in both directions and
joins an owned open radio profile; the guard restores the original profile.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import threading
import time

from .paid_faults import capture_probe
from .paid_relay import eventually, relay_config
from .wifi_remote import ETHERTYPE, Router, digest


def free_config(router):
    config = relay_config([router.interface], "http://127.0.0.1:9")
    config["state_directory"] = router.state
    config["transports"]["ethernet"][router.interface]["ethertype"] = ETHERTYPE
    config["terms"].update(fee_msat_per_kib=0, max_rate_msat_per_kib=0,
                           quote_max_units=1_048_576, quote_lifetime_secs=300)
    return config


def validate_unfunded(status):
    if (status["purchases"] or status["history"] or status["locked_sat"]
            or status["remaining_budget_sat"] != 64
            or any(status["funding_budget"].values())):
        raise RuntimeError("free hardware acceptance changed financial authority")


def validate_free_offer(offer):
    # False is intentionally omitted by the production RouteOffer serializer.
    if offer["price"]["msat"] != 0 or offer.get("trial", False):
        raise RuntimeError("free watch did not obtain a normal free grant")


class ManagementFailure(ValueError):
    pass


class ManagementMonitor:
    def __init__(self, nodes):
        self.nodes = nodes
        self.stop = threading.Event()
        self.samples = []
        self.errors = []
        self.threads = []

    def start(self):
        for node in self.nodes.values():
            thread = threading.Thread(target=self.monitor, args=(node,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def monitor(self, node):
        while not self.stop.is_set():
            stamp = time.monotonic()
            try:
                node.management_check(heartbeat=node.guard_ready)
                self.samples.append({"host": node.host, "at": stamp, "ok": True})
            except Exception as error:
                self.samples.append({"host": node.host, "at": stamp, "ok": False,
                                     "error": type(error).__name__})
                self.errors.append(node.host)
                return
            self.stop.wait(2)

    def check(self):
        if self.errors:
            raise ManagementFailure("management monitoring failed; restore the owned test")

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=12)
        if any(thread.is_alive() for thread in self.threads):
            raise ManagementFailure("management monitor did not finish")


class WifiRun:
    def __init__(self, args):
        self.args = args
        inventory = json.loads(args.inventory.read_text())
        specs = inventory["nodes"]
        if len(specs) != 3 or len({s["host"] for s in specs}) != 3:
            raise ValueError("the inventory must identify three distinct routers")
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700)
        self.run = secrets.token_hex(6)
        self.open_mesh = "fips-open-" + self.run if getattr(args, "open_mesh", False) else None
        self.nodes = {f"n{i + 1:02}": Router(spec, self.run, self.root, self.open_mesh)
                      for i, spec in enumerate(specs)}
        self.monitor = ManagementMonitor(self.nodes)
        self.evidence = {"run": self.run, "phases": [], "passed": False,
                         "test_ethertype": ETHERTYPE, "money_operations": False,
                         "original_services_replaced": False}
        self.evidence["radio_mode"] = "temporary_open_mesh" if self.open_mesh else "saved_sae"
        self.evidence["harness_sha256"] = {
            name: digest(Path(__file__).with_name(name).read_bytes())
            for name in ("wifi_discovery.py", "wifi_remote.py", "wifi_mesh.py", "wifi_open.py",
                         "paid_relay.py", "paid_faults.py")}
        self.original = {}
        self.financial = {}

    def save(self):
        temporary = self.root / "result.json.new"
        temporary.write_text(json.dumps(self.evidence, indent=2) + "\n")
        temporary.replace(self.root / "result.json")

    def phase(self, name, **evidence):
        self.evidence["phases"].append({"phase": name, "at": time.monotonic(), **evidence})
        self.save()
        print(name, flush=True)

    def ctl(self, node, kind, **fields):
        self.monitor.check()
        return self.nodes[node].control(kind, **fields)

    def ready(self, *, line=False, isolated=False):
        self.monitor.check()
        statuses = {name: self.ctl(name, "status") for name in self.nodes}
        self.evidence["last_peer_observation"] = {name: state["peers"] for name, state in statuses.items()}
        self.save()
        for name, status in statuses.items():
            i = int(name[-1])
            wanted = {other.npub for key, other in self.nodes.items()
                      if key != name and (not line or abs(int(key[-1]) - i) == 1)}
            if isolated:
                wanted = set() if name == "n03" else {self.nodes["n02" if name == "n01" else "n01"].npub}
            # Require actual removal, not just a stale disconnected peer; native
            # route lookup may retain that direct destination until eviction.
            if (line or isolated) and any(p["npub"] not in wanted for p in status["peers"]):
                return False
            peers = [p for p in status["peers"] if p["connected"]]
            if {p["npub"] for p in peers} != wanted or any(p["transport"] != "ethernet" for p in peers):
                return False
        return statuses

    def assert_finances(self):
        for name, node in self.nodes.items():
            validate_unfunded(self.ctl(name, "status"))
            if node.monetary_journals() != self.financial[name]:
                raise RuntimeError("free forwarding changed a financial journal")

    def probe(self, source, destination, phase):
        evidence = {"source": source, "destination": destination}
        # Separate physical clocks do not establish one-way latency accuracy.
        capture_probe(self, source, destination, eventually, evidence, measure_latency=False)
        self.phase(phase, **evidence)

    def profile_config(self, node):
        return free_config(node)

    def before_launch(self):
        """Optional offline funding step; the default profiles remain unfunded."""

    def setup(self):
        binary = self.args.binary.read_bytes()
        if binary[:6] != b"\x7fELF\x02\x01" or binary[18:20] != b"\xb7\x00":
            raise RuntimeError("the supplied executable must be Linux ARM64")
        self.evidence["binary_sha256"] = digest(binary)
        for name, node in self.nodes.items():
            self.original[name] = node.baseline()
        if self.open_mesh and len({node.mesh["frequency"] for node in self.nodes.values()}) != 1:
            raise RuntimeError("open radio test requires the same original frequency on every router")
        if len({node.mac for node in self.nodes.values()}) != 3:
            raise RuntimeError("inventory aliases do not identify three distinct mesh interfaces")
        self.evidence["original_baselines"] = self.original
        self.phase("read-only baseline and management checks passed")
        self.monitor.start()
        for node in self.nodes.values():
            node.prepare(binary, self.profile_config(node))
        self.launch_profiles()
        self.evidence["test_identities"] = {name: node.npub for name, node in self.nodes.items()}
        self.phase("isolated profiles started beside original instances")

    def launch_profiles(self):
        self.before_launch()
        for name, node in self.nodes.items():
            if self.open_mesh:
                if name == "n03":
                    def pair_ready():
                        for first, second in (("n01", "n02"), ("n02", "n01")):
                            peers = self.ctl(first, "status")["peers"]
                            if (len(peers) != 1 or not peers[0]["connected"]
                                    or peers[0]["transport"] != "ethernet"
                                    or peers[0]["npub"] != self.nodes[second].npub):
                                return False
                        return True
                    eventually("two open-radio peers discovered before late join", pair_ready, 150)
                    self.phase("two open-radio nodes authenticated before the third radio joined",
                               profiles={key: self.nodes[key].verify_open_mesh() for key in ("n01", "n02")})
                opened = node.begin_open_mesh()
                self.phase("owned radio joined the public test mesh", node=name, profile=opened)
            node.start()
            eventually("new service control", lambda: self.ctl(name, "status"), 60)
            self.financial[name] = node.monetary_journals()

    def verify_open_profiles(self):
        if self.open_mesh:
            self.phase("open radio policy and limits verified after convergence",
                       profiles={name: node.verify_open_mesh() for name, node in self.nodes.items()})

    def beacon_evidence(self):
        transports = {name: node.native({"command": "show_transports"})
                      for name, node in self.nodes.items()}
        self.evidence["last_transport_observation"] = transports
        self.save()
        announced_and_observed = True
        for name, report in transports.items():
            adapters = report["data"]["transports"]
            if (len(adapters) != 1 or adapters[0]["type"] != "ethernet"
                    or adapters[0]["name"] != self.nodes[name].interface):
                raise RuntimeError("test node has a non-mesh transport shortcut")
            if adapters[0]["stats"]["beacons_recv"] == 0 or adapters[0]["stats"]["beacons_sent"] == 0:
                announced_and_observed = False
        return transports if announced_and_observed else None

    def form_line(self):
        eventually("automatic radio triangle discovery", self.ready, 150)
        self.verify_open_profiles()
        # A late starter can authenticate incoming peers before hearing their
        # next periodic beacon. Observe the unmodified announcement cadence.
        transports = eventually("sent and received beacon evidence", self.beacon_evidence, 60)
        self.assert_finances()
        if any(self.ctl(name, "status")["watched_routes"] for name in self.nodes):
            raise RuntimeError("discovery created source spending authority")
        self.phase("authenticated triangle discovered without a peer roster", transports=transports)
        self.probe("n01", "n03", "triangle fresh stream delivered")

        first, last = self.nodes["n01"], self.nodes["n03"]
        filters = {"n01": first.install_filter(last.mac), "n03": last.install_filter(first.mac)}
        eventually("automatic line after excluding the shortcut", lambda: self.ready(line=True), 100)
        routing = {name: {command: node.native({"command": command})
                          for command in ("show_tree", "show_routing", "show_cache")}
                   for name, node in self.nodes.items()}
        self.phase("test-only shortcut filters established a two-hop line", filters=filters, routing=routing)

    def exercise(self):
        self.form_line()
        forwarded_before = self.ctl("n02", "status")["free_routes"]
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            response = self.ctl(source, "watch", destination=self.nodes[destination].npub,
                                max_rate_msat_per_kib=0)
            offer = response["free_route"]
            validate_free_offer(offer)
            self.probe(source, destination, "automatic discovered two-hop free stream delivered")
        self.assert_finances()
        forwarded_after = self.ctl("n02", "status")["free_routes"]
        if forwarded_after["admitted_packets"] - forwarded_before["admitted_packets"] < 16:
            raise RuntimeError("two-hop streams have no middle-router admission evidence")
        self.phase("two-hop forwarding preserves every financial journal",
                   middle_before=forwarded_before, middle_after=forwarded_after)

        self.mesh_outage()
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            self.probe(source, destination, "same watched route delivers after automatic rejoin")
        self.assert_finances()
        for name, node in self.nodes.items():
            state = self.ctl(name, "status")
            expected = [] if name == "n02" else [self.nodes["n03" if name == "n01" else "n01"].npub]
            watches = state["watched_routes"]
            if sorted(w["destination"] for w in watches) != expected:
                raise RuntimeError("rejoin changed the source watch roster")
            if any(w["paused"] or w["pending"] is not None or w["max_rate_msat_per_kib"] != 0 for w in watches):
                raise RuntimeError("rejoin changed source authority")
            if node.npub != state["npub"]:
                raise RuntimeError("rejoin changed identity")
        self.phase("automatic rejoin retains identities, free-only watches and financial state")
        self.verify_shortcuts()

    def mesh_outage(self):
        last = self.nodes["n03"]
        last.mesh_down()
        self.phase("leaf left the radio mesh; management monitoring continues")
        eventually("actual mesh peer eviction", lambda: self.ready(line=True, isolated=True), 100)
        self.assert_finances()
        self.phase("leaf peers evicted; financial invariants hold")
        last.mesh_up()
        eventually("automatic mesh rejoin", lambda: self.ready(line=True), 150)
        self.verify_open_profiles()

    def verify_shortcuts(self):
        counters = {}
        for name in ("n01", "n03"):
            node = self.nodes[name]
            table = json.loads(node.remote(["nft", "-j", "list", "table", "netdev", node.table]))
            packets = sum(expr["counter"]["packets"] for row in table["nftables"]
                          for expr in row.get("rule", {}).get("expr", []) if "counter" in expr)
            if packets == 0:
                raise RuntimeError("shortcut filter has no actual packet-drop evidence")
            counters[name] = {"dropped_packets": packets, "table": table}
        self.phase("two-hop topology has observed shortcut-drop evidence", filters=counters)

    def finish(self):
        errors = []
        for name, node in self.nodes.items():
            try:
                node.cleanup()
            except Exception as error:
                errors.append({"node": name, "error": type(error).__name__})
        self.evidence["cleanup_errors"] = errors
        for name, original in self.original.items():
            def restored():
                return self.nodes[name].baseline() == original
            try:
                eventually("original router state restored", restored, 100)
            except Exception as error:
                errors.append({"node": name, "restoration_error": type(error).__name__})
        try:
            self.monitor.close()
        except Exception as error:
            errors.append({"monitor_error": type(error).__name__})
        self.evidence["management_samples"] = self.monitor.samples
        self.evidence["management_errors"] = self.monitor.errors
        if errors or self.monitor.errors:
            self.evidence["passed"] = False
        self.evidence["persistent_test_profiles_retained"] = True
        self.save()
        if errors or self.monitor.errors:
            raise RuntimeError("owned Wi-Fi test restoration incomplete")

    def execute(self):
        try:
            self.setup()
            self.exercise()
            self.monitor.check()
            self.evidence["passed"] = True
        except Exception as error:
            self.evidence["failure"] = type(error).__name__
            raise
        finally:
            signal.alarm(0)
            self.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--open-mesh", action="store_true",
                        help="temporarily test open 802.11s joining, restoring the saved SAE profile")
    args = parser.parse_args()
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("Wi-Fi acceptance exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    WifiRun(args).execute()


if __name__ == "__main__":
    main()
