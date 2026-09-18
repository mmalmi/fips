"""Bounded mixed FREE/PAID acceptance on three guarded OpenWrt mesh routers.

The unfunded source enters n02 over loopback; both classes leave n02 toward
n03 over the same wireless neighbor. Two auxiliary accounts remain unfunded.
This verifies delivery, actual background overflow and automatic payment, not
throughput, CPU efficiency or latency between unsynchronized router clocks.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import time

from .paid_relay import eventually, relay_config
from .paid_settlement import original_channels, require, settle_and_collect
from .paid_wifi import PaidWifiRun, retain_channels
from .paid_wifi_forwarding import MintForwards
from .remote_mint import RemoteMint
from .wifi_discovery import validate_free_offer, validate_unfunded
from .wifi_measurements import snapshot
from .wifi_priority_checks import (
    acknowledged, adjacency, bandwidth, bounded_free, free_policy, loopback_address,
    patch_config, payment, pressure_pair, received, running, submitted, workload,
)
from .wifi_remote import digest


class PriorityRun(PaidWifiRun):
    def __init__(self, args):
        self.schedule = workload(args)
        if args.mint_host and args.mint_ssh_forward:
            raise ValueError("remote mint and controller SSH forwards are separate choices")
        super().__init__(args)
        self.auxiliary = {
            "free-source": self.nodes["n02"].add_profile("free-source"),
            "free-sink": self.nodes["n03"].add_profile("free-sink"),
        }
        self.auxiliary_initial = {}
        self.udp_addresses = {}
        self.evidence.update(
            acceptance_kind="unfunded_topology_only" if args.topology_only else "mixed_wifi_priority",
            mixed_priority_accepted=False, workload=self.schedule,
            money_operations=not args.topology_only,
            free_bandwidth_policy=free_policy(self.schedule), one_way_latency=False,
            free_source_host="n02", shared_wireless_egress=["n02", "n03"],
        )
        for name in ("wifi_priority.py", "wifi_priority_checks.py", "wifi_profiles.py", "wifi_measurements.py"):
            self.evidence["harness_sha256"][name] = digest(Path(__file__).with_name(name).read_bytes())

    def create_mint(self, args):
        if args.mint_host:
            return RemoteMint(json.loads(args.mint_host.read_text()), args.mint_binary,
                              self.run, self.root, args.mint_address, max_issued_sat=384)
        return super().create_mint(args)

    def participants(self):
        return {**self.nodes, **self.auxiliary}

    def ctl(self, node, kind, **fields):
        if node in self.auxiliary:
            self.check_forwards()
            self.monitor.check()
            return self.auxiliary[node].control(kind, **fields)
        return super().ctl(node, kind, **fields)

    def profile_config(self, node):
        config = super().profile_config(node)
        config["return_allowance"] = False
        config["terms"]["quote_max_units"] = 96 * 1024 * 1024
        config["payment_cadence"] = {"max_delay_ms": 250, "unpaid_percent": 50}
        if node in (self.nodes["n02"], self.nodes["n03"]):
            config["transports"]["udp"] = {"bind_addr": "127.0.0.1:0", "advertise_on_nostr": False}
        if node is self.nodes["n02"]:
            config["free_bandwidth"] = free_policy(self.schedule)
        return config

    def auxiliary_config(self, profile):
        config = relay_config([], self.mint_url)
        config["state_directory"] = profile.state
        config["transports"] = {"udp": {"bind_addr": "127.0.0.1:0", "advertise_on_nostr": False}}
        config["terms"].update(fee_msat_per_kib=0, max_rate_msat_per_kib=0,
                               quote_max_units=96 * 1024 * 1024)
        config["return_allowance"] = False
        return config

    def configure_stopped(self, profile, **changes):
        owner = getattr(profile, "owner", profile)
        current = json.loads(profile.remote(["cat", profile.config]))
        changed = patch_config(current, changes)
        new_path = profile.config + ".priority-new"
        command = (shlex.join(["sh", owner.temporary + "/guard.sh", "can-start", profile.config])
                   + "\numask 077\nset -C\ncat > " + shlex.quote(new_path)
                   + "\n" + shlex.join(["mv", new_path, profile.config]))
        owner.guarded(command, json.dumps(changed).encode())

    def before_launch(self):
        for name, profile in self.auxiliary.items():
            profile.prepare(self.auxiliary_config(profile))
            self.auxiliary_initial[name] = profile.monetary_journals()
        sink = self.auxiliary["free-sink"].npub
        for profile in self.participants().values():
            self.configure_stopped(profile, destination_fees={sink: 0})
        self.evidence["auxiliary_identities"] = {name: p.npub for name, p in self.auxiliary.items()}
        if self.args.topology_only:
            # Reuse the identical mint reachability path, without issuing/importing anything.
            if self.args.mint_ssh_forward:
                self.forwards = MintForwards(self.nodes, self.mint_url, self.root)
                self.evidence["mint_forwards"] = self.forwards.info
                self.forwards.start()
            self.phase("unfunded topology pilot; mint issuance remains zero")
        else:
            super().before_launch()
        self.verify_auxiliary(stopped=True)

    def transport_evidence(self, *, auxiliaries=False):
        profiles = self.participants() if auxiliaries else self.nodes
        reports, announced = {}, True
        for name, profile in profiles.items():
            report = profile.native({"command": "show_transports"})
            require(report["status"] == "ok", "native transport observation failed")
            adapters = report["data"]["transports"]
            ethernet = [item for item in adapters if item["type"] == "ethernet"]
            udp = [item for item in adapters if item["type"] == "udp"]
            main = name in self.nodes
            needs_udp = name != "n01"
            require(len(ethernet) == int(main) and len(udp) == int(needs_udp)
                    and len(adapters) == len(ethernet) + len(udp), "unexpected transport shortcut")
            if main:
                require(ethernet[0]["name"] == profile.interface, "wireless adapter changed")
                announced = announced and all(ethernet[0]["stats"][key] > 0
                                              for key in ("beacons_sent", "beacons_recv"))
            if needs_udp:
                address = loopback_address(udp[0]["local_addr"])
                require(name not in self.udp_addresses or self.udp_addresses[name] == address,
                        "owned loopback listener changed")
                self.udp_addresses[name] = address
            reports[name] = report
        self.evidence["last_transport_observation"] = reports
        self.save()
        return reports if announced else None

    def beacon_evidence(self):
        return self.transport_evidence()

    def topology(self):
        states = {name: self.ctl(name, "status") for name in self.participants()}
        self.evidence["priority_peer_observation"] = states
        self.save()
        return adjacency(states, {name: p.npub for name, p in self.participants().items()}, self.udp_addresses)

    def start_auxiliaries(self):
        for name, host in (("free-source", "n02"), ("free-sink", "n03")):
            profile = self.auxiliary[name]
            address = self.udp_addresses[host]
            self.configure_stopped(profile, neighbors=[{
                "npub": self.nodes[host].npub, "addresses": [{"transport": "udp", "addr": address}],
            }])
            profile.start()
            eventually("unfunded loopback profile control", lambda name=name: self.ctl(name, "status"), 60)
        eventually("only the five intended transports", lambda: self.transport_evidence(auxiliaries=True), 30)
        states = eventually("exact five-identity shared-egress topology", self.topology, 90)
        self.phase("five isolated identities share the n02 to n03 wireless egress", topology=states)

    def verify_auxiliary(self, *, stopped=False):
        for name, profile in self.auxiliary.items():
            require(profile.monetary_journals() == self.auxiliary_initial[name],
                    "unfunded auxiliary financial journals changed")
            if stopped:
                balance = profile.control("balance", action="wallet")
                require(balance["mint_url"] == self.mint_url and balance["unit"] == "sat"
                        and balance["balance_sat"] == 0, "auxiliary wallet acquired funds")
            else:
                validate_unfunded(self.ctl(name, "status"))

    def arm(self, source, destination, count, size):
        shape = {"stream_id": secrets.token_hex(16), "packet_count": count, "payload_bytes": size}
        self.ctl(destination, "receive_probe", probe={
            **shape, "source": self.participants()[source].npub, "measure_one_way_latency": False,
        })
        return shape

    def send(self, source, destination, shape, rate):
        return self.ctl(source, "send_probe", probe={
            **shape, "destination": self.participants()[destination].npub, "packets_per_second": rate,
        })["probe"]

    def receive(self, source, destination, shape, *, complete=False):
        report = self.ctl(destination, "status")["probe"]
        received(report, shape, self.participants()[source].npub, complete=complete)
        return report

    def free_probe(self, label):
        shape = self.arm("free-source", "free-sink", 4, 128)
        sent = self.send("free-source", "free-sink", shape, 4)
        submitted(sent, shape)
        def delivered():
            value = self.receive("free-source", "free-sink", shape)
            return value if value["unique_packets"] == shape["packet_count"] else None
        result = eventually("fresh free diagnostic delivery", delivered, 30)
        self.phase(label, sender=sent, receiver=result)

    def open_free(self):
        result = self.ctl("free-source", "watch", destination=self.auxiliary["free-sink"].npub,
                          max_rate_msat_per_kib=0)
        require(result.get("purchase") is None, "free source created a paid purchase")
        validate_free_offer(result["free_route"])
        self.phase("unfunded source obtained its distinct zero-price destination grant", grant=result["free_route"])
        self.free_probe("unfunded free route warmed through the shared wireless egress")
        self.verify_auxiliary()

    def middle(self):
        self.monitor.check()
        self.check_forwards()
        return snapshot(self.nodes["n02"], "n02", native_counters=True)

    def wait_free_progress(self, future, before, deadline):
        while time.monotonic() < deadline:
            running(future)
            current = self.middle()
            running(future)
            if bandwidth(current)["admitted_packets"] > bandwidth(before)["admitted_packets"]:
                return current
            time.sleep(.05)
        raise RuntimeError("free admissions did not advance during the overlap window")

    def mixed(self):
        schedule = self.schedule
        free = self.arm("free-source", "free-sink", schedule["free_packets"], schedule["free_bytes"])
        paid = self.arm("n01", "n03", schedule["paid_packets"], schedule["paid_bytes"])
        require(free["stream_id"] != paid["stream_id"], "mixed streams must have distinct identities")
        evidence = {"free_shape": free, "paid_shape": paid, "observations": [], "pressure": None,
                    "passed": False, "payment_observations": []}
        self.evidence["mixed_priority"] = evidence
        evidence["before"] = self.middle()
        evidence["payment_before"] = payment(self.ctl("n01", "status"))
        self.save()
        deadline = time.monotonic() + schedule["overlap_seconds"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            free_future = pool.submit(self.send, "free-source", "free-sink", free, schedule["free_rate"])
            paid_future = None
            try:
                active = self.wait_free_progress(free_future, evidence["before"], deadline)
                evidence["free_active_before_paid"] = active
                paid_future = pool.submit(self.send, "n01", "n03", paid, schedule["paid_rate"])
                while time.monotonic() < deadline:
                    running(free_future)
                    item = {"receiver_before": self.receive("n01", "n03", paid), "middle": self.middle()}
                    item["receiver_after"] = self.receive("n01", "n03", paid)
                    running(free_future)
                    for prior in reversed(evidence["observations"]):
                        pressure = pressure_pair(prior, item, paid["packet_count"])
                        if pressure:
                            evidence["pressure"] = {"before": prior, "after": item, "delta": pressure}
                            break
                    evidence["observations"].append(item)
                    self.save()
                    if paid_future.done():
                        evidence["paid_sender"] = paid_future.result()
                        submitted(evidence["paid_sender"], paid)
                        if item["receiver_after"]["unique_packets"] == paid["packet_count"]:
                            evidence["paid_receiver"] = item["receiver_after"]
                            break
                    time.sleep(.05)
                require("paid_receiver" in evidence, "paid delivery did not complete within the overlap window")
                require(evidence["pressure"] is not None,
                        "no observed n02 background overflow during partial paid delivery")
                received(evidence["paid_receiver"], paid, self.nodes["n01"].npub, complete=True)
                evidence["free_after_paid_baseline"] = self.middle()
                evidence["free_active_after_paid"] = self.wait_free_progress(
                    free_future, evidence["free_after_paid_baseline"], deadline)
                while time.monotonic() < deadline:
                    running(free_future)
                    current = payment(self.ctl("n01", "status"))
                    running(free_future)
                    evidence["payment_observations"].append(current)
                    self.save()
                    if acknowledged(evidence["payment_before"], current):
                        evidence["payment_during_free"] = current
                        break
                    time.sleep(.05)
                require("payment_during_free" in evidence,
                        "automatic payment was not acknowledged during active free traffic")
                running(free_future)
            finally:
                # No resending: retain each original finite sender result even on failed acceptance.
                for name, future in (("free_sender", free_future), ("paid_sender", paid_future)):
                    if future is not None:
                        try:
                            evidence[name] = future.result(timeout=45)
                        except Exception as error:
                            evidence[name + "_error"] = type(error).__name__
                self.save()
        require("free_sender" in evidence and "paid_sender" in evidence,
                "finite mixed senders did not return complete results")
        submitted(evidence["free_sender"], free)
        evidence["after"] = self.middle()
        evidence["free_budget"] = bounded_free(evidence["before"], evidence["after"], free_policy(schedule))
        evidence["free_receiver"] = self.receive("free-source", "free-sink", free)
        require(evidence["free_receiver"]["unique_packets"] > 0, "free stream delivered no packets")
        time.sleep(1.1)
        self.free_probe("fresh free stream resumed after congestion")
        self.verify_auxiliary()
        self.transport_evidence(auxiliaries=True)
        self.topology()
        evidence["passed"] = True
        self.evidence["mixed_priority_accepted"] = True
        self.phase("paid packets and automatic payment completed during observed wireless background pressure")

    def collect(self):
        current = eventually("original financial accounts before collection", self.finances)
        original_channels(self.nodes, current)
        if self.channel_anchor is not None:
            retain_channels(self.channel_anchor, current)
        settle_and_collect(self, current, execute=self.account_execute,
                           stop=lambda name: self.nodes[name].stop(),
                           export_path=lambda name, relative: self.nodes[name].state + "/" + relative)
        self.verify_auxiliary(stopped=True)
        self.phase("all 384 test sats collected; both unfunded auxiliary wallets remain empty")

    def exercise(self):
        self.form_line()
        self.start_auxiliaries()
        if self.args.topology_only:
            self.open_free()
            self.assert_finances()
            self.verify_shortcuts()
            for node in self.nodes.values():
                node.stop()
                balance = node.control("balance", action="wallet")
                require(balance["balance_sat"] == 0 and balance["mint_url"] == self.mint_url
                        and balance["unit"] == "sat", "topology-only account acquired funds")
            self.verify_auxiliary(stopped=True)
            self.phase("unfunded five-identity topology accepted; paid congestion was not exercised")
            return
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            self.ctl(source, "buy", destination=self.nodes[destination].npub)
        funded = eventually("original two funded wireless channels", self.finances)
        original_channels(self.nodes, funded)
        try:
            self.channel_anchor = self.paid_streams(funded, "original paid channel warmed")
            self.open_free()
            self.mixed()
            self.verify_shortcuts()
        except Exception as error:
            self.evidence["acceptance_failure"] = str(error)
            self.evidence["mixed_priority_accepted"] = False
            self.save()
            raise
        finally:
            # Inconclusive pressure/delivery must not skip ordinary recovery of known funds.
            signal.alarm(0)
            try:
                self.collect()
            except Exception as error:
                self.evidence["collection_failure"] = str(error)
                self.evidence["mixed_priority_accepted"] = False
                self.save()
                raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "binary", "mint-binary", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    result.add_argument("--mint-host", type=Path, help="optional explicit Linux mint-host inventory")
    result.add_argument("--mint-address", required=True)
    result.add_argument("--mint-ssh-forward", action="store_true")
    result.add_argument("--topology-only", action="store_true", help="issue zero sats and verify only topology/free delivery")
    for name, value in (("free-packets", 64000), ("free-rate", 4000), ("free-bytes", 1000),
                        ("paid-packets", 24), ("paid-rate", 4), ("paid-bytes", 128),
                        ("free-bytes-per-second", 4 * 1024 * 1024),
                        ("free-burst-bytes", 256 * 1024), ("overlap-seconds", 30)):
        result.add_argument("--" + name, type=int, default=value)
    result.set_defaults(open_mesh=False)
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)
    def deadline(_signum, _frame):
        raise TimeoutError("mixed Wi-Fi acceptance exceeded its bounded window")
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    PriorityRun(args).execute()


if __name__ == "__main__":
    main()
