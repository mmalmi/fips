"""Unfunded four-identity topology on three guarded OpenWrt mesh routers.

An auxiliary source reaches two providers over the existing management LAN.
Both providers reach the destination only over native Wi-Fi. The source and
destination share a physical host, so this fixture is not a performance test.
No watch, grant, wallet import or payment is created by this topology pilot.
"""

import argparse
import os
from pathlib import Path
import signal
from types import SimpleNamespace

from .paid_faults import capture_probe
from .paid_relay import eventually, relay_config
from .paid_settlement import require
from .wifi_diamond_checks import adjacency, denied_stream, listener, management_address
from .wifi_discovery import WifiRun, validate_unfunded
from .wifi_profiles import configure_stopped
from .wifi_remote import ETHERTYPE, digest
from .wifi_measurements import snapshot


class DiamondRun(WifiRun):
    def __init__(self, args):
        super().__init__(args)
        self.source = self.nodes["n03"].add_profile("source")
        self.management_addresses = {}
        self.udp_addresses = {}
        self.mint_url = "http://127.0.0.1:9"
        self.evidence.update(
            acceptance_kind="unfunded_competing_provider_topology",
            source_host="n03", destination_host="n03",
            wireless_provider_edges=[["n01", "n03"], ["n02", "n03"]],
            source_transport="management_lan_udp", performance_test=False,
        )
        for name in ("wifi_diamond.py", "wifi_diamond_checks.py", "paid_settlement.py", "wifi_measurements.py"):
            self.evidence["harness_sha256"][name] = digest(Path(__file__).with_name(name).read_bytes())

    def participants(self):
        return {**self.nodes, "source": self.source}

    def ctl(self, node, kind, **fields):
        self.monitor.check()
        return self.participants()[node].control(kind, **fields)

    def management_address(self, name):
        node = self.nodes[name]
        value = management_address(node.remote([
            "ip", "-o", "-4", "addr", "show", "dev", node.management, "scope", "global",
        ]), node.management)
        previous = self.management_addresses.get(name)
        require(previous is None or previous == value, "management IPv4 changed during the test")
        require(all(other == name or address != value for other, address in self.management_addresses.items()),
                "management addresses do not identify distinct routers")
        self.management_addresses[name] = value
        return value

    def udp_config(self, name):
        return {"bind_addr": self.management_address(name) + ":0",
                "bind_interface": self.nodes[name].management, "advertise_on_nostr": False}

    def profile_config(self, node):
        name = next(name for name, value in self.nodes.items() if value is node)
        config = relay_config([node.interface], self.mint_url)
        config["state_directory"] = node.state
        config["transports"]["ethernet"][node.interface]["ethertype"] = ETHERTYPE
        config["terms"]["quote_max_units"] = 128 * 1024
        config["terms"]["controller"]["channel_capacity_sat"] = 64
        if name != "n03":
            config["transports"]["udp"] = self.udp_config(name)
            config["terms"]["fee_msat_per_kib"] = 1024 if name == "n01" else 1280
            config["return_allowance"] = True
        return config

    def source_config(self):
        config = relay_config([], self.mint_url)
        config["state_directory"] = self.source.state
        config["transports"] = {"udp": self.udp_config("n03")}
        config["terms"].update(buyer_budget_sat=128, quote_max_units=128 * 1024)
        config["terms"]["controller"].update(channel_capacity_sat=64, max_locked_sat=128)
        return config

    def before_launch(self):
        self.source.prepare(self.source_config())
        self.financial["source"] = self.source.monetary_journals()
        self.offline_empty()
        self.evidence["auxiliary_identities"] = {"source": self.source.npub}
        self.phase("four stopped accounts are unfunded; no mint is running")

    def offline_empty(self):
        balances = {}
        for name, node in self.participants().items():
            balance = node.control("balance", action="wallet")
            require(balance["mint_url"] == self.mint_url and balance["unit"] == "sat"
                    and balance["balance_sat"] == 0, "topology pilot wallet acquired funds")
            balances[name] = balance["balance_sat"]
        return balances

    def assert_finances(self):
        for name, node in self.participants().items():
            status = self.ctl(name, "status")
            validate_unfunded(status, buyer_budget_sat=128 if name == "source" else 64)
            require(not status["watched_routes"], "topology pilot created source spending authority")
            require(node.monetary_journals() == self.financial[name], "topology pilot changed financial journals")

    def transport_evidence(self, *, source=False):
        profiles = self.participants() if source else self.nodes
        reports, announced = {}, True
        for name, profile in profiles.items():
            report = profile.native({"command": "show_transports"})
            require(report["status"] == "ok", "native transport observation failed")
            adapters = report["data"]["transports"]
            ethernet = [item for item in adapters if item["type"] == "ethernet"]
            udp = [item for item in adapters if item["type"] == "udp"]
            require(len(ethernet) == int(name != "source") and len(udp) == int(name != "n03")
                    and len(adapters) == len(ethernet) + len(udp), "diamond transport shortcut")
            if ethernet:
                require(ethernet[0]["name"] == profile.interface, "wireless adapter changed")
                announced = announced and all(ethernet[0]["stats"][key] > 0
                                              for key in ("beacons_sent", "beacons_recv"))
            if udp:
                host = "n03" if name == "source" else name
                address = listener(udp[0]["local_addr"], self.management_addresses[host])
                require(name not in self.udp_addresses or self.udp_addresses[name] == address,
                        "owned UDP listener changed")
                self.udp_addresses[name] = address
            reports[name] = report
        self.evidence["last_transport_observation"] = reports
        self.save()
        return reports if announced else None

    def beacon_evidence(self):
        return self.transport_evidence()

    def topology(self, *, source=True, radio_down=None):
        profiles = self.participants() if source else self.nodes
        states = {name: self.ctl(name, "status") for name in profiles}
        self.evidence["last_peer_observation"] = states
        self.save()
        return adjacency(states, {name: p.npub for name, p in profiles.items()},
                         self.udp_addresses, source=source, radio_down=radio_down)

    def form_diamond(self):
        eventually("automatic native radio triangle", self.ready, 150)
        self.verify_open_profiles()
        eventually("native beacons and exact bound UDP listeners", self.beacon_evidence, 60)
        # Wait until after the open-mesh late-join check before removing this edge.
        first, second = self.nodes["n01"], self.nodes["n02"]
        filters = {"n01": first.install_filter(second.mac), "n02": second.install_filter(first.mac)}
        eventually("only the two provider-to-destination wireless edges",
                   lambda: self.topology(source=False), 100)
        configure_stopped(self.source, neighbors=[{
            "npub": self.nodes[name].npub,
            "addresses": [{"transport": "udp", "addr": self.udp_addresses[name]}],
        } for name in ("n01", "n02")])
        self.source.start()
        eventually("source admin socket", lambda: self.ctl("source", "status"), 60)
        eventually("all four exact transports", lambda: self.transport_evidence(source=True), 30)
        states = eventually("four-identity diamond without local shortcuts", self.topology, 90)
        self.phase("two provider choices have separate physical wireless egresses",
                   topology=states, filters=filters)

    def diagnostic(self, source, destination, *, loss=False):
        evidence = {"source": source, "destination": destination, "expected_loss": loss}
        accounts = SimpleNamespace(nodes=self.participants(), ctl=self.ctl)
        capture_probe(accounts, source, destination, eventually, evidence,
                      loss=loss, measure_latency=False)
        self.phase("fresh topology diagnostic observed", **evidence)
        return evidence

    def denial_observation(self):
        reports = {name: snapshot(self.nodes[name], name, native_counters=True)
                   for name in ("n01", "n02")}
        prior = snapshot(self.source, "n03")
        reports["sessions"] = self.source.native({"command": "show_sessions"})
        reports["source"] = snapshot(self.source, "n03")
        require(prior["host_process"] == reports["source"]["host_process"],
                "source process changed during session query")
        return reports

    def denied_stream(self):
        before = self.denial_observation()
        probe = self.diagnostic("source", "n03", loss=True)
        after = self.denial_observation()
        summary = denied_stream(before, after, self.nodes["n03"].npub,
                                probe["sent"]["submitted_packets"], probe["received"]["payload_bytes"])
        self.phase("unfunded native data attempts met provider policy denial",
                   before=before, after=after, probe=probe, summary=summary)

    def exercise(self):
        self.form_diamond()
        self.assert_finances()
        for provider in ("n01", "n02"):
            self.diagnostic("source", provider)
            self.diagnostic(provider, "n03")
        # With no watch or channel, the co-located destination must not receive
        # traffic through a local shortcut or an unpaid forwarding bypass.
        self.denied_stream()
        self.assert_finances()
        self.topology()
        self.verify_shortcuts(names=("n01", "n02"))
        for name, node in self.nodes.items():
            self.management_address(name)
            node.stop()
        self.phase("topology pilot stopped with four empty wallets", balances=self.offline_empty())


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--inventory", type=Path, required=True)
    result.add_argument("--binary", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--open-mesh", action="store_true")
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("diamond topology pilot exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    DiamondRun(args).execute()


if __name__ == "__main__":
    main()
