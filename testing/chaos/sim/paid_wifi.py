"""Paid native Wi-Fi recovery with fresh test accounts and a capped local mint."""

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
        super().__init__(args)
        self.mint = LocalMint(args.mint_binary, args.mint_address, self.root)
        self.mint_url = None
        self.channel_anchor = None
        self.evidence.update(test_funds_only=True, money_operations=True,
                             wallet_observation="offline before launch and after settlement")
        for name in ("paid_wifi.py", "paid_wifi_mint.py", "paid_finances.py", "paid_settlement.py"):
            self.evidence["harness_sha256"][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = relay_config([node.interface], self.mint_url)
        config["state_directory"] = node.state
        config["transports"]["ethernet"][node.interface]["ethertype"] = ETHERTYPE
        return config

    def setup(self):
        self.mint_url = self.mint.start()
        self.evidence["mint_process"] = self.mint.info
        self.phase("fresh test mint started with a 384-sat issuance cap")
        super().setup()

    def before_launch(self):
        # Establish reachability for all participants before issuing any grant.
        for node in self.nodes.values():
            node.remote(["uclient-fetch", "-q", "-T", "5", "-O", "/dev/null",
                         self.mint_url + "/v1/info"], timeout=10)
        balances = {}
        for name, node in self.nodes.items():
            node.control("import", action="wallet", token=self.mint.grant(name))
            balance = node.control("balance", action="wallet")
            require(balance["mint_url"] == self.mint_url and balance["unit"] == "sat"
                    and balance["balance_sat"] == 128, "initial test wallet funding differs")
            balances[name] = balance["balance_sat"]
        self.phase("three stopped fresh accounts funded with 128 test sats each", balances=balances)

    def state_json(self, name, relative):
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
        self.channel_anchor = self.paid_streams(funded, "paid two-hop wireless stream delivered")
        original_channels(self.nodes, self.channel_anchor)
        self.phase("original channels automatically paid before outage", financial=self.channel_anchor)

        self.mesh_outage()
        rejoined = self.assert_finances()
        paid = self.paid_streams(rejoined, "same paid route delivers after automatic radio rejoin")
        retain_channels(self.channel_anchor, paid)
        for name, node in self.nodes.items():
            require(self.ctl(name, "status")["npub"] == node.npub, "radio rejoin changed identity")
        self.phase("same funding and channels pay automatically after radio rejoin", financial=paid)
        self.verify_shortcuts()
        settle_and_collect(self, paid, execute=self.account_execute,
                           stop=lambda name: self.nodes[name].stop(),
                           export_path=lambda name, relative: self.nodes[name].state + "/" + relative)
        collection = self.evidence["phases"][-1]["settlement_collection"]
        balances = collection["settled_wallet_balances"]
        require(balances["n02"] > 128 and balances["n01"] < 128 and balances["n03"] < 128,
                "the middle router did not earn both endpoints' payments")
        self.phase("all 384 test sats collected; every test wallet empty")

    def finish(self):
        try:
            super().finish()
        finally:
            try:
                result = self.mint.finish()
                self.evidence["mint_cleanup"] = result
                if result.get("retained_for_recovery"):
                    self.evidence["passed"] = False
            except Exception as error:
                self.evidence["mint_cleanup_error"] = type(error).__name__
                self.evidence["passed"] = False
            self.save()
        if not self.evidence["passed"]:
            raise RuntimeError("paid Wi-Fi acceptance incomplete; preserve the recorded mint and accounts")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mint-binary", type=Path, required=True,
                        help="test-mint executable for this controller host")
    parser.add_argument("--mint-address", required=True,
                        help="assigned private controller address reachable from all routers")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("paid Wi-Fi acceptance exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    PaidWifiRun(args).execute()


if __name__ == "__main__":
    main()
