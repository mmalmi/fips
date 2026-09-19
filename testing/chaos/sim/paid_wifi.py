"""Paid native Wi-Fi recovery with fresh test accounts and a capped local mint.

The optional open mesh uses the shared temporary-profile/restore guard. Funding
still precedes every candidate start; a radio failure retains outstanding test
funds and the original mint/forwards for deliberate recovery.
"""

import argparse
import json
import os
from pathlib import Path
import signal

from .paid_finances import financial_snapshot, payments_credited
from .paid_faults import paid_progress, validate_finances
from .paid_relay import PaidRelayRun, eventually, relay_config
from .paid_settlement import original_channels, require, settle_and_collect
from .paid_wifi_mint import LocalMint
from .paid_wifi_forwarding import MintForwards, finish_mint
from .remote_mint import RemoteMint
from .wifi_active_outage import active_radio_outage
from .wifi_discovery import WifiRun
from .wifi_remote import ETHERTYPE, digest


def retain_channels(prior, current):
    """Rejoining cannot replace funding, release capital or reset authorization."""
    require(original_channels(current, current) == original_channels(prior, prior),
            "rejoin changed the original channel owners")
    validate_finances(prior, current, wallet=False)


def reconciled_channels(prior, current):
    retain_channels(prior, current)
    # A new signature can race the earlier frozen stream-payment target. Only
    # require credit already observed here to survive the coming partition.
    return current if payments_credited(current) else None


class PaidWifiRun(WifiRun):
    def __init__(self, args):
        requested_outage = getattr(args, "outage_node", None)
        if requested_outage is not None:
            if not getattr(args, "active_outage", False):
                raise ValueError("--outage-node requires --active-outage")
            if requested_outage not in ("n02", "n03"):
                raise ValueError("outage node must be n02 or n03")
        self.outage_node = requested_outage or "n03"
        if getattr(args, "mint_host", None) and args.mint_ssh_forward:
            raise ValueError("remote mint and controller SSH forwards are separate choices")
        if args.mint_ssh_forward and args.mint_address != "127.0.0.1":
            raise ValueError("--mint-ssh-forward requires --mint-address 127.0.0.1")
        super().__init__(args)
        self.mint = self.create_mint(args)
        self.mint_url = None
        self.forwards = None
        self.channel_anchor = None
        self.evidence.update(active_radio_outage=getattr(args, "active_outage", False),
                             outage_node=self.outage_node if getattr(args, "active_outage", False) else None,
                             test_funds_only=True, money_operations=True,
                             wallet_observation="offline before launch and after settlement")
        for name in ("paid_wifi.py", "paid_wifi_mint.py", "paid_wifi_forwarding.py",
                     "paid_finances.py", "paid_settlement.py", "remote_mint.py", "mint_host.py",
                     "wifi_active_outage.py", "wifi_probes.py", "wifi_priority_checks.py",
                     "wifi_measurements.py"):
            self.evidence["harness_sha256"][name] = digest(Path(__file__).with_name(name).read_bytes())

    def create_mint(self, args):
        if getattr(args, "mint_host", None):
            return RemoteMint(json.loads(args.mint_host.read_text()), args.mint_binary,
                              self.run, self.root, args.mint_address, max_issued_sat=384)
        return LocalMint(args.mint_binary, args.mint_address, self.root)

    def profile_config(self, node):
        config = relay_config([node.interface], self.mint_url)
        config["state_directory"] = node.state
        if getattr(self.args, "active_outage", False):
            config["return_allowance"] = False
        config["transports"]["ethernet"][node.interface]["ethertype"] = ETHERTYPE
        return config

    def setup(self):
        self.mint_url = self.mint.start()
        self.evidence["mint_process"] = self.mint.info
        self.phase("fresh test mint started with a 384-sat issuance cap")
        super().setup()

    def before_launch(self):
        # The shared lifecycle calls this while all three candidates are stopped,
        # before any temporary open join. Wallet commands must stay offline.
        # Establish reachability for all participants before issuing any grant.
        if self.args.mint_ssh_forward:
            self.forwards = MintForwards(self.nodes, self.mint_url, self.root)
            self.evidence["mint_forwards"] = self.forwards.info
            self.forwards.start()
            self.phase("three private loopback mint forwards verified before issuance")
        else:
            for node in self.nodes.values():
                node.remote(["uclient-fetch", "-q", "-T", "5", "-O", "/dev/null",
                             self.mint_url + "/v1/info"], timeout=10)
        balances = {}
        for name, node in self.nodes.items():
            self.check_forwards()
            token = self.mint.grant(name)
            self.check_forwards()
            node.control("import", action="wallet", token=token)
            balance = node.control("balance", action="wallet")
            require(balance["mint_url"] == self.mint_url and balance["unit"] == "sat"
                    and balance["balance_sat"] == 128, "initial test wallet funding differs")
            balances[name] = balance["balance_sat"]
        self.phase("three stopped fresh accounts funded with 128 test sats each", balances=balances)

    def check_forwards(self):
        if self.forwards is not None:
            self.forwards.check()

    def ctl(self, node, kind, **fields):
        self.check_forwards()
        return super().ctl(node, kind, **fields)

    def phase(self, name, **evidence):
        self.check_forwards()
        return super().phase(name, **evidence)

    def state_json(self, name, relative):
        self.check_forwards()
        node = self.nodes[name]
        return json.loads(node.remote(["cat", node.state + "/" + relative]))

    def finances(self):
        return financial_snapshot(self, wallet=None)

    def assert_finances(self):
        current = eventually("consistent hardware financial observation", self.finances)
        if self.channel_anchor is None:
            for state in current.values():
                require(not state["funding"] and not state["signed"] and not state["credited"]
                        and not any(state["budget"].values()) and state["remaining"] == 64,
                        "discovery created spending or payment authority")
        else:
            retain_channels(self.channel_anchor, current)
        return current

    def account_execute(self, name, binary, action, body):
        self.check_forwards()
        self.monitor.check()
        if name == "mint":
            require(binary == "fips-relay-test-mint" and action == "ctl", "unexpected mint operation")
            return self.mint.request(body)
        require(binary == "fips-relay" and action == "wallet", "unexpected offline account operation")
        fields = dict(body)
        return self.nodes[name].control(fields.pop("type"), action=action, **fields)

    def paid_streams(self, before, phase):
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            self.probe(source, destination, phase)
        evidence = {}
        for source in ("n01", "n03"):
            sample = {}
            current = eventually("automatic payment for the fresh wireless stream", lambda: paid_progress(
                self, before, source, sample, wallet=False))
            evidence[source] = sample
        self.phase("wireless stream accounting and automatic payment confirmed", directions=evidence)
        return eventually("reconciled channel observation before radio departure", lambda:
                          reconciled_channels(before, self.finances()))

    def exercise(self):
        self.form_line()
        discovered = self.assert_finances()
        PaidRelayRun.unpaid_probe(self, discovered)
        self.save()
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            self.ctl(source, "buy", destination=self.nodes[destination].npub)
        funded = eventually("initial funded channel observation", self.finances)
        original_channels(self.nodes, funded)
        try:
            self.channel_anchor = self.paid_streams(funded, "paid two-hop wireless stream delivered")
            original_channels(self.nodes, self.channel_anchor)
            self.phase("original channels automatically paid before outage", financial=self.channel_anchor)
            if getattr(self.args, "active_outage", False):
                active_radio_outage(self, outage_node=self.outage_node)
            else:
                self.mesh_outage()
            rejoined = self.assert_finances()
            paid = self.paid_streams(rejoined, "same paid route delivers after automatic radio rejoin")
            retain_channels(self.channel_anchor, paid)
            for name, node in self.nodes.items():
                require(self.ctl(name, "status")["npub"] == node.npub, "radio rejoin changed identity")
            self.phase("same funding and channels pay automatically after radio rejoin", financial=paid)
            self.verify_shortcuts()
        except Exception as error:
            self.evidence["acceptance_failure"] = str(error)
            self.save()
            raise
        finally:
            # Known original channels must still close after a failed radio check.
            signal.alarm(0)
            try:
                collection = self.collect()
            except Exception as error:
                self.evidence["collection_failure"] = str(error)
                self.save()
                raise

        balances = collection["settled_wallet_balances"]
        require(balances["n02"] > 128 and balances["n01"] < 128 and balances["n03"] < 128,
                "the middle router did not earn both endpoints' payments")

    def collect(self):
        current = eventually("original financial accounts before collection", self.finances)
        original_channels(self.nodes, current)
        if self.channel_anchor is not None:
            retain_channels(self.channel_anchor, current)
        settle_and_collect(self, current, execute=self.account_execute,
                           stop=lambda name: self.nodes[name].stop(),
                           export_path=lambda name, relative: self.nodes[name].state + "/" + relative)
        collection = self.evidence["phases"][-1]["settlement_collection"]
        self.phase("all 384 test sats collected; every test wallet empty")
        return collection

    def finish(self):
        try:
            super().finish()
        finally:
            finish_mint(self)
        if not self.evidence["passed"]:
            raise RuntimeError("paid Wi-Fi acceptance incomplete; preserve the recorded mint and accounts")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mint-binary", type=Path, required=True,
                        help="test-mint executable for this controller host")
    parser.add_argument("--mint-address", required=True,
                        help="assigned private controller address, or 127.0.0.1 with SSH forwarding")
    parser.add_argument("--mint-ssh-forward", action="store_true",
                        help="use dedicated inventory SSH forwards instead of controller LAN access")
    parser.add_argument("--open-mesh", action="store_true",
                        help="temporarily test paid forwarding over open 802.11s, restoring the saved SAE profile")
    parser.add_argument("--active-outage", action="store_true",
                        help="interrupt live paid round trips before automatic radio recovery")
    parser.add_argument("--outage-node", choices=("n02", "n03"),
                        help="radio to remove with --active-outage: n02 bridge or n03 leaf (default)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.outage_node is not None and not args.active_outage:
        parser.error("--outage-node requires --active-outage")
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("paid Wi-Fi acceptance exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    PaidWifiRun(args).execute()


if __name__ == "__main__":
    main()
