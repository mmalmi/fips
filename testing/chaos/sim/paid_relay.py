"""Bounded three-node paid Ethernet acceptance using existing relay CLIs.

Requires explicitly supplied Linux binaries. Never builds images or binaries.
Run as: python3 -m sim.paid_relay --help (from testing/chaos).
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time

from .run_scope import RUN_LABEL, OwnedResources, docker, inspect_owned, refuse_name_collision
from .paid_faults import capture_probe, exercise_faults, validate_unpaid_probe
from .paid_finances import financial_snapshot, payment_progress
from .paid_settlement import settle_and_collect
from .paid_payment_faults import diagnostics, exercise_payment_faults
from .topology import SimNode, SimTopology
from .veth import VethManager


def write_json(path: Path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def eventually(description, condition, seconds=120):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            result = condition()
            if result:
                return result
        except (RuntimeError, FileNotFoundError, json.JSONDecodeError) as error:
            last = type(error).__name__
        time.sleep(0.5)
    raise RuntimeError(f"deadline waiting for {description} (last error: {last})")


def relay_config(interfaces, mint):
    return {
        "state_directory": "/tmp/bench-state",
        "transports": {"ethernet": {
            interface: {"interface": interface, "discovery": True, "announce": True,
                        "auto_connect": True, "accept_connections": True}
            for interface in interfaces
        }},
        "neighbor_admission": "authenticated_adjacent",
        "neighbors": [], "terms": {
            "billing": "forwarding_data",
            "controller": {"mint_url": mint, "channel_capacity_sat": 32,
                           "max_locked_sat": 64, "max_funding_overhead_sat": 0,
                           "max_wallet_spend_sat": 128, "channel_lifetime_secs": 1800,
                           "renewal": None},
            "buyer_budget_sat": 64, "window_msat": 4000, "grace_msat": 8000,
            "fee_msat_per_kib": 1024, "max_rate_msat_per_kib": 8192,
            "quote_lifetime_secs": 1200, "quote_max_units": 30000,
        },
    }


class PaidRelayRun:
    def __init__(self, args):
        self.args = args
        self.name = secrets.token_hex(4)
        self.resources = OwnedResources(self.name)
        self.root = args.output.resolve()
        self.nodes = {f"n{i:02}": SimNode(f"n{i:02}", "", "", "") for i in range(1, 4)}
        edges = {("n01", "n02"), ("n02", "n03")}
        self.topology = SimTopology(self.nodes, edges, {edge: "ethernet" for edge in edges}, self.name)
        self.veth = VethManager(self.topology)
        self.containers = {}
        self.output_created = False
        self.funding_started = False
        self.evidence = {"run": self.name, "test_funds_only": True, "phases": [],
                         "payment_faults_requested": bool(getattr(args, "payment_faults", False))}

    def execute(self, node, binary, action, request=None, timeout=90):
        item = inspect_owned("container", self.containers[node], self.name)
        output = docker(["exec", "-i", item["Id"], f"/opt/bench/{binary}", action,
                         "/run/bench/config.json"],
                        data=json.dumps(request) if request is not None else None, timeout=timeout)
        return json.loads(output) if action != "init" else output

    def ctl(self, node, kind, **fields):
        return self.execute(node, "fips-relay", "ctl", {"type": kind, **fields},
                            timeout=10 if kind == "status" else 90)

    def state_json(self, node, relative):
        item = inspect_owned("container", self.containers[node], self.name)
        return json.loads(docker(["exec", item["Id"], "cat", f"/tmp/bench-state/{relative}"]))

    def launch(self, node, binary):
        # Fixed paths inside a newly created, owned container; no user shell input.
        docker(["exec", "-d", self.containers[node], "/bin/sh", "-c",
                f"echo $$ > /run/bench/process.pid; exec /opt/bench/{binary} run "
                "/run/bench/config.json > /run/bench/process.log 2>&1"])

    def create_container(self, node, network, image):
        name = self.topology.container_name(node)
        refuse_name_collision("container", name)
        directory = self.root / node
        directory.mkdir(mode=0o700)
        binary_mounts = []
        for binary in ("fips-relay", "fips-relay-test-mint"):
            binary_mounts.extend([
                "--mount", f"type=bind,src={(self.args.binary_dir / binary).resolve()},"
                f"dst=/opt/bench/{binary},readonly",
            ])
        identity = docker([
            "container", "create", "--name", name, "--label", f"{RUN_LABEL}={self.name}",
            "--network", network, "--cap-add=NET_ADMIN", "--cap-add=NET_RAW",
            "--mount", f"type=bind,src={directory},dst=/run/bench",
            *binary_mounts,
            "--entrypoint", "/bin/sleep", image, "infinity",
        ])
        self.resources.remember("container", identity)
        self.containers[node] = identity
        docker(["container", "start", identity])

    def profile_config(self, node, mint_url):
        return relay_config(self.topology.ethernet_interfaces(node), mint_url)

    def setup(self):
        # Preflight is read-only. Refuse an existing evidence directory.
        if self.root.exists():
            raise RuntimeError("output directory must be new; existing runs are never reset")
        binaries = {}
        for name in ("fips-relay", "fips-relay-test-mint"):
            data = (self.args.binary_dir / name).read_bytes()
            if data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01" or data[18:20] != b"\xb7\x00":
                raise RuntimeError(f"{name} must be a Linux ARM64 ELF binary")
            binaries[name] = hashlib.sha256(data).hexdigest()
        image = json.loads(docker(["image", "inspect", self.args.image]))[0]
        if image["Architecture"] != "arm64" or image["Os"] != "linux":
            raise RuntimeError("the acceptance image must be Linux ARM64")
        self.evidence.update(image=image["Id"], binaries=binaries)
        self.root.mkdir(mode=0o700)
        self.output_created = True
        network_name = f"fips-{self.name}-mint"
        refuse_name_collision("network", network_name)
        network = docker(["network", "create", "--internal", "--driver=bridge", "--label",
                          f"{RUN_LABEL}={self.name}", network_name])
        self.resources.remember("network", network)
        network_info = inspect_owned("network", network, self.name)
        subnets = [ipaddress.ip_network(item["Subnet"]) for item in network_info["IPAM"]["Config"]]
        if not subnets or not all(subnet.is_private for subnet in subnets):
            raise RuntimeError("Docker did not allocate private test subnets")
        for node in ("mint", *self.nodes):
            self.create_container(node, network_name, image["Id"])
        mint_info = inspect_owned("container", self.containers["mint"], self.name)
        mint_ip = mint_info["NetworkSettings"]["Networks"][network_name]["IPAddress"]
        if not ipaddress.ip_address(mint_ip).is_private:
            raise RuntimeError("mint requires a private allocated IP")
        mint_url = f"http://{mint_ip}:3338"
        write_json(self.root / "mint/config.json", {
            "state_directory": "/tmp/bench-state", "bind": f"{mint_ip}:3338", "max_issued_sat": 384,
        })
        self.launch("mint", "fips-relay-test-mint")
        eventually("private mint startup", lambda: self.execute("mint", "fips-relay-test-mint", "ctl", {"type": "report"}))
        self.veth.setup_all()
        for node in self.nodes:
            write_json(self.root / node / "config.json", self.profile_config(node, mint_url))
            self.nodes[node].npub = self.execute(node, "fips-relay", "init")
            # A lost issue/import reply leaves financial state uncertain.
            # Retain the original accounts unless collection is proven.
            self.funding_started = True
            grant = self.execute("mint", "fips-relay-test-mint", "ctl", {"type": "issue", "id": node, "amount_sat": 128})
            token = self.state_json("mint", f"exports/{node}.json")["token"]
            self.execute(node, "fips-relay", "wallet", {"type": "import", "token": token})
            balance = self.execute(node, "fips-relay", "wallet", {"type": "balance"})
            if grant["amount_sat"] != 128 or balance["balance_sat"] != 128:
                raise RuntimeError("test funding amount differs")
        self.initial_wallets = {node: self.wallet(node) for node in self.nodes}
        for node in self.nodes:
            self.launch(node, "fips-relay")

    def wallet(self, node):
        # Query inside Linux: copying a live WAL-backed database is not a
        # consistent snapshot. Only aggregate counts and amounts leave it.
        script = (
            "import json,sqlite3; "
            "db=sqlite3.connect('file:/tmp/bench-state/wallet/cashu/wallet.sqlite?mode=ro',uri=True); "
            "db.execute('BEGIN'); "
            "print(json.dumps(db.execute('SELECT state,count(*),sum(amount) FROM proof "
            "GROUP BY state ORDER BY state').fetchall()))"
        )
        item = inspect_owned("container", self.containers[node], self.name)
        return json.loads(docker(["exec", item["Id"], "python3", "-c", script]))

    def line_ready(self):
        for index, node in enumerate(self.nodes):
            expected = {other.npub for i, other in enumerate(self.nodes.values()) if abs(i - index) == 1}
            peers = [peer for peer in self.ctl(node, "status")["peers"] if peer["connected"]]
            if {peer["npub"] for peer in peers} != expected or any(peer["transport"] != "ethernet" for peer in peers):
                return False
        return True

    def finances(self):
        return financial_snapshot(self, wallet=self.wallet)

    def probe(self, source, destination):
        evidence = {"probe": f"{source}->{destination}"}
        self.evidence["phases"].append(evidence)
        capture_probe(self, source, destination, eventually, evidence)

    def unpaid_probe(self, before):
        shape = {"stream_id": secrets.token_hex(16), "packet_count": 4, "payload_bytes": 256}
        self.ctl("n03", "receive_probe", probe={**shape, "source": self.nodes["n01"].npub})
        attempted = self.ctl("n01", "send_probe", probe={
            **shape, "destination": self.nodes["n03"].npub, "packets_per_second": 4,
        })["probe"]
        validate_unpaid_probe(attempted, shape["stream_id"])
        # Observe the receiver for a complete interval. An empty queue caused
        # by a failed submission does not establish unpaid forwarding denial.
        until = time.monotonic() + 3
        while True:
            report = self.ctl("n03", "status")["probe"]
            if report["unique_packets"] != 0 or report["invalid_packets"] != 0:
                raise RuntimeError("unpaid traffic reached the remote application")
            if time.monotonic() >= until:
                break
            time.sleep(0.25)
        if eventually("unpaid financial snapshot", self.finances) != before:
            raise RuntimeError("unpaid traffic changed wallet or funding state")
        self.evidence["phases"].append({
            "unpaid_forwarding": "denied", "received": 0,
            "attempted_packets": attempted["requested_packets"],
            "submitted_packets": attempted["submitted_packets"],
            "sent": attempted,
            "observation_seconds": 3,
        })

    def exercise(self):
        eventually("native Ethernet beacon line", self.line_ready, 150)
        if self.evidence["payment_faults_requested"]:
            for node in self.nodes:
                diagnostics(self.ctl(node, "status"))
        discovered = eventually("discovery financial snapshot", self.finances)
        for node, state in discovered.items():
            if (state["wallet"] != self.initial_wallets[node] or state["funding"]
                    or any(state["budget"].values()) or state["authorized"] or state["remaining"] != 64):
                raise RuntimeError("discovery changed wallet or spending authority")
        self.evidence["phases"].append({"discovery_only": "wallet and funding unchanged", "quote_only": "covered by controller gate"})
        self.unpaid_probe(discovered)
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            self.ctl(source, "buy", destination=self.nodes[destination].npub)
            self.probe(source, destination)
        before = eventually("initial automatic payments", lambda: self.paid_after(discovered))
        self.veth.set_scoped_edge("n02", "n03", False)
        # Wait for real peer eviction, not merely a stale connected flag. No
        # production beacon, trust, or dead-link timeout is shortened.
        eventually("dead Ethernet peer eviction", lambda: all(
            not any(peer["npub"] == self.nodes[other].npub for peer in self.ctl(node, "status")["peers"])
            for node, other in (("n02", "n03"), ("n03", "n02"))), 100)
        self.veth.set_scoped_edge("n02", "n03", True)
        eventually("beacon rejoin", self.line_ready, 150)
        rejoined = eventually("rejoin financial snapshot", self.finances)
        for node, state in rejoined.items():
            for key in ("funding", "budget", "wallet"):
                if state[key] != before[node][key]:
                    raise RuntimeError(f"rejoin changed {key} for {node}")
            if state["remaining"] > before[node]["remaining"]:
                raise RuntimeError("rejoin reset the lifetime buyer budget")
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            self.probe(source, destination)
        final = eventually("payments after rejoin", lambda: self.paid_after(rejoined))
        if any(final[node][key] != before[node][key]
               for node in self.nodes for key in ("funding", "budget", "wallet")):
            raise RuntimeError("rejoin changed original funding or wallet custody")
        self.evidence["phases"].append({"rejoin": "same funding operations and channels", "financial": final})
        final = exercise_faults(self, final, eventually)
        if self.evidence["payment_faults_requested"]:
            final = exercise_payment_faults(self, final, eventually)
        settle_and_collect(self, final)

    def paid_after(self, prior, sources=("n01", "n03")):
        return payment_progress(self.finances(), prior, sources=sources)

    def run(self):
        try:
            self.setup()
            self.exercise()
            self.evidence["passed"] = True
        except Exception as error:
            self.evidence["passed"] = False
            self.evidence["failure"] = type(error).__name__
            raise
        finally:
            # The scenario deadline must not interrupt ownership-checked
            # cleanup. Each remaining Docker operation has its own deadline.
            signal.alarm(0)
            self.evidence["owned_resources"] = [
                {"kind": kind, "id": identity} for kind, identity in self.resources.created
            ]
            errors = []
            collected = self.evidence.get("mint", {})
            safe = not self.funding_started or (
                collected.get("conserved") is True and collected.get("issued_sat") == 384
                and collected.get("collected_sat") == 384
            )
            self.evidence["resources_retained"] = not safe
            if not safe:
                self.evidence["passed"] = False
            if safe:
                try:
                    self.veth.teardown_all()
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    errors.append(str(error))
                errors.extend(self.resources.cleanup())
            self.evidence["cleanup_errors"] = errors
            if errors:
                self.evidence["passed"] = False
            if self.output_created:
                write_json(self.root / "result.json", self.evidence)
            if not safe:
                raise RuntimeError("original funded resources retained; collection is unproven")
            if errors:
                raise RuntimeError("owned resource cleanup incomplete; inspect result.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new private evidence directory")
    parser.add_argument("--image", default="fips-test:latest", help="existing Linux ARM64 image; never pulled or rebuilt")
    parser.add_argument("--payment-faults", action="store_true",
                        help="also test short payment-carrier interruptions; requires measurements-enabled binaries")
    args = parser.parse_args()
    os.umask(0o077)
    def deadline(_signum, _frame):
        raise TimeoutError("paid Ethernet acceptance exceeded its 15-minute bound")
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    try:
        PaidRelayRun(args).run()
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
