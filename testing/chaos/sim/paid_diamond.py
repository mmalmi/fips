"""One capped source watch switches between two guarded wireless providers.

Only the source receives test funds. The fixture keeps production selector
defaults, never issues another Buy/Watch, and preserves uncertain accounts/mint.
Whole-radio failure proves working-route failover, not isolated loss ranking.
"""

import copy
from dataclasses import asdict
import json
import os
from pathlib import Path
import signal
import time

from .paid_finances import financial_snapshot, payments_credited
from .paid_relay import eventually
from .paid_settlement import require, settle_and_collect
from .paid_wifi_mint import LocalMint
from .paid_wifi_forwarding import MintForwards, finish_mint
from .wifi_diamond import DiamondRun, parser as topology_parser
from .wifi_diamond_checks import require_same_process, transitional_adjacency
from .wifi_diamond_finances import freeze_fixture
from .wifi_diamond_selection import (
    ACTIVE_WORKLOAD, FEES, NORMAL_WORKLOAD, PAYLOAD_BYTES, POLICY,
    PHASE_SECONDS, PRICE_CEILING,
    bounded_capital, current_purchase, paid_channel_progress,
    trial_ids, watch, working_route,
)
from .wifi_measurements import snapshot
from .wifi_priority_checks import submitted
from . import wifi_probes as probes
from .wifi_remote import digest


class Accounts:
    """Four logical accounts, with source first for cooperative settlement."""
    def __init__(self, run):
        self.run = run
        self.nodes = {"source": run.source, **run.nodes}
        self.evidence = run.evidence
        self.stopped = set()

    def ctl(self, name, kind, **fields):
        return self.run.ctl(name, kind, **fields)

    def state_json(self, name, relative):
        self.run.check_forwards()
        profile = self.nodes[name]
        return json.loads(profile.remote(["cat", profile.state + "/" + relative]))

    def journals(self):
        return {name: {key: self.state_json(name, path) for key, path in (
            ("controller", "controller/controller.json"), ("buyer", "buyer/buyer.json"),
            ("seller", "seller/ledger.json"),
        )} for name in self.nodes}

    def finances(self):
        return financial_snapshot(self, wallet=None)

    def execute(self, name, binary, action, body):
        self.run.check_forwards()
        self.run.monitor.check()
        if name == "mint":
            require(binary == "fips-relay-test-mint" and action == "ctl", "unexpected mint operation")
            return self.run.mint.request(body)
        require(binary == "fips-relay" and action == "wallet", "unexpected offline account operation")
        fields = dict(body)
        return self.nodes[name].control(fields.pop("type"), action=action, **fields)

    def stop(self, name):
        profile = self.nodes[name]
        owner = getattr(profile, "owner", profile)
        if owner.host not in self.stopped:
            owner.stop()
            self.stopped.add(owner.host)


class PaidDiamondRun(DiamondRun):
    def __init__(self, args):
        super().__init__(args)
        self.active_failover = args.active_failover
        self.mint = LocalMint(args.mint_binary, "127.0.0.1", self.root)
        self.forwards = None
        self.accounts = Accounts(self)
        self.fixture = self.journal_anchor = None
        self.process_anchor = {}
        self.watch_started = False
        self.collection_attempted = False
        self.evidence.update(acceptance_kind="paid_wireless_provider_switching", test_funds_only=True,
                             money_operations=True, paid_switching_accepted=False,
                             issued_sat=128, channel_capacity_sat=64, source_capital_limit_sat=128,
                             provider_fees_msat_per_kib=FEES, price_selection=POLICY)
        self.evidence["active_failover_enabled"] = self.active_failover
        for name in ("paid_diamond.py", "wifi_diamond_finances.py", "wifi_diamond_selection.py",
                     "paid_finances.py", "paid_wifi_mint.py", "paid_wifi_forwarding.py",
                     "wifi_probes.py", "wifi_priority_checks.py"):
            self.evidence["harness_sha256"][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        name = next(name for name, value in self.nodes.items() if value is node)
        if name in FEES:
            config["terms"]["fee_msat_per_kib"] = FEES[name]
        return config

    def source_config(self):
        config = super().source_config()
        config["price_selection"] = POLICY.copy()
        config["terms"].update(fee_msat_per_kib=PRICE_CEILING, max_rate_msat_per_kib=PRICE_CEILING)
        return config

    def setup(self):
        self.mint_url = self.mint.start()
        self.evidence["mint_process"] = self.mint.info
        self.phase("isolated test mint started; only one 128-sat grant is permitted")
        super().setup()

    def before_launch(self):
        self.prepare_source()
        self.offline_empty()
        self.forwards = MintForwards(self.nodes, self.mint_url, self.root)
        self.evidence["mint_forwards"] = self.forwards.info
        self.forwards.start()
        self.evidence["source_funding_stage"] = "grant_attempted"
        self.save()
        token = self.mint.grant("source")
        self.check_forwards()
        self.evidence["source_funding_stage"] = "import_attempted"
        self.save()
        self.source.control("import", action="wallet", token=token)
        balances = {}
        for name, profile in self.accounts.nodes.items():
            balance = profile.control("balance", action="wallet")
            expected = 128 if name == "source" else 0
            require(balance["mint_url"] == self.mint_url and balance["unit"] == "sat"
                    and balance["balance_sat"] == expected, "initial diamond funding differs")
            balances[name] = expected
        self.evidence["source_funding_stage"] = "verified"
        self.phase("only the stopped source account holds 128 test sats", balances=balances)

    def check_forwards(self):
        if self.forwards is not None:
            self.forwards.check()

    def ctl(self, node, kind, **fields):
        self.check_forwards()
        return super().ctl(node, kind, **fields)

    def phase(self, name, **evidence):
        self.check_forwards()
        return super().phase(name, **evidence)

    def process_snapshots(self):
        samples = {name: snapshot(profile, "n03" if name == "source" else name, native_counters=True)
                   for name, profile in self.accounts.nodes.items()}
        for name, sample in samples.items():
            if name in self.process_anchor:
                require_same_process(self.process_anchor[name], sample)
            else:
                native = sample["native"]["status"]["data"]
                address = bytes.fromhex(native["node_addr"])
                require(len(address) == 16 and native["npub"] == self.accounts.nodes[name].npub,
                        "native identity does not match its prepared profile")
                self.accounts.nodes[name].node_addr = list(address)
        if not self.process_anchor:
            self.process_anchor = samples
        return samples

    def financial_checkpoint(self, expected_count=None):
        raw = self.accounts.journals()
        require(all(value["controller"]["policy"]["mint_url"] == self.mint_url for value in raw.values()),
                "financial journals escaped the owned test mint")
        current = self.accounts.finances()
        count = len(raw["source"]["controller"]["funding"]) if expected_count is None else expected_count
        fixture = freeze_fixture(self.accounts.nodes, raw, current, count, previous=self.journal_anchor)
        self.fixture, self.journal_anchor = fixture, copy.deepcopy(raw)
        return current

    def observe(self):
        before = self.ctl("source", "status")
        quality = self.ctl("source", "route_quality", destination=self.nodes["n03"].npub)
        after = self.ctl("source", "status")
        return {"before": before, "quality": quality, "after": after}

    def wait_until(self, due, deadline):
        while time.monotonic() < due:
            require(time.monotonic() < deadline, "provider transition exceeded its bounded window")
            self.check_forwards()
            self.monitor.check()
            time.sleep(max(0, min(0.5, due - time.monotonic())))

    def receive_batch(self, shape, record, deadline, drain_seconds):
        end = min(deadline, time.monotonic() + drain_seconds)
        samples = record.setdefault("receiver_samples", [])
        while True:
            # Drain this same stream before re-arming; a late last packet must
            # not turn a successful burst into a permanently incomplete one.
            report = probes.receive(self, "source", "n03", shape)
            samples.append(report)
            record["receiver_observed_at"] = time.monotonic()
            self.save()
            if report["unique_packets"] == shape["packet_count"] or time.monotonic() >= end:
                return report
            self.wait_until(min(end, time.monotonic() + 0.25), deadline)

    def confirm_pre_cut_route(self, initial):
        destination, first = self.nodes["n03"], self.nodes["n01"]
        observation = self.observe()
        purchase = working_route(**observation, destination=destination.node_addr,
                                 destination_npub=destination.npub, provider=first.node_addr, fee=FEES["n01"])
        require(purchase is not None and current_purchase(initial, destination.node_addr) == purchase,
                "partially delivered stream is no longer on the original cheaper agreement")
        return observation

    def record_active_recovery(self, record):
        cut = self.evidence["active_failover"]
        cut["accepted_at"] = time.monotonic()
        cut["delivery_observed_at"] = record["receiver_observed_at"]
        cut["quality_payment_observed_at"] = record["observation_finished_at"]
        cut["working_route_upper_bound_seconds"] = cut["accepted_at"] - cut["cut_started"]
        cut["accepted_stream_id"] = record["shape"]["stream_id"]
        cut["membership_started_at"] = time.monotonic()
        states = {name: self.ctl(name, "status") for name in self.accounts.nodes}
        cut["membership_finished_at"] = time.monotonic()
        cut["membership"] = states
        self.save()
        transitional_adjacency(states, {name: p.npub for name, p in self.accounts.nodes.items()},
                               self.udp_addresses)

    def drive_route(self, provider, baseline, phase, *, radio=None):
        destination = self.nodes["n03"]
        target = self.nodes[provider]
        workload = ACTIVE_WORKLOAD if radio is not None else NORMAL_WORKLOAD
        self.evidence.setdefault("workloads", {})[phase] = asdict(workload)
        previous_trials = trial_ids(baseline, target.node_addr)
        prior_signed = {key: value["authorized_sat"] for key, value in baseline["payment_progress"].items()}
        records = self.evidence.setdefault("route_phases", {}).setdefault(phase, [])
        started = time.monotonic()
        deadline = started + PHASE_SECONDS
        for index in range(workload.batches):
            # Preserve finite bytes but leave the normal 60-second cooldown
            # enough wall time for a fresh trial and confirmed full agreement.
            self.wait_until(started + index * workload.spacing_seconds, deadline)
            require(time.monotonic() < deadline, "provider transition exceeded its bounded window")
            initial = self.ctl("source", "status")
            bounded_capital(initial)
            watch(initial, destination.npub)
            shape = probes.arm(self, "source", "n03", workload.packets, PAYLOAD_BYTES)
            record = {"shape": shape, "initial": initial, "started_at": time.monotonic()}
            records.append(record)
            self.save()
            if radio is not None and index == 0:
                cut = self.evidence.setdefault("active_failover", {})
                cut["shape"] = shape
                sent = probes.send_with_radio_cut(
                    self, "source", "n03", shape, workload.rate, radio, cut,
                    verify_route=lambda: self.confirm_pre_cut_route(initial))
            else:
                sent = probes.send(self, "source", "n03", shape, workload.rate)
            record["send_finished_at"] = time.monotonic()
            record["sender"] = sent
            self.save()
            submitted(sent, shape)
            received = self.receive_batch(shape, record, deadline, workload.drain_seconds)
            observation = self.observe()
            record.update(receiver=received, observation=observation, observation_finished_at=time.monotonic())
            self.save()
            require(time.monotonic() < deadline, "provider transition exceeded its bounded window")
            purchase = working_route(**observation, destination=destination.node_addr,
                                     destination_npub=destination.npub, provider=target.node_addr,
                                     fee=FEES[provider])
            if (purchase is not None and current_purchase(initial, destination.node_addr) == purchase
                    and received["unique_packets"] == workload.packets
                    and trial_ids(observation["after"], target.node_addr) - previous_trials):
                channel = purchase["channel"]["id"]
                if paid_channel_progress(observation["after"], channel, prior_signed.get(channel, 0)):
                    if radio is not None:
                        require(index > 0, "interrupted stream cannot prove unchanged replacement agreement")
                        self.record_active_recovery(record)
                    finances = eventually("reconciled original provider channels", lambda: self.reconciled())
                    self.phase("automatic route delivers with fresh quality and payment",
                               label=phase, provider=provider, purchase=purchase, quality=observation["quality"],
                               financial=finances, processes=self.process_snapshots())
                    return observation["after"]
        raise RuntimeError("provider did not deliver, promote and pay within the finite packet allowance")

    def reconciled(self):
        current = self.financial_checkpoint()
        return current if payments_credited(current) else None

    def collect(self):
        require(not self.collection_attempted, "collection cannot be replayed")
        self.collection_attempted = True
        self.evidence["collection_attempted"] = True
        self.save()
        self.ctl("source", "pause_route_refresh")
        status = self.ctl("source", "status")
        if self.watch_started:
            require(watch(status, self.nodes["n03"].npub, paused=True)["pending"] is None,
                    "unfinished watched purchase requires deliberate recovery")
        current = eventually("frozen financial ownership before collection", self.financial_checkpoint)
        settle_and_collect(self.accounts, current, execute=self.accounts.execute,
                           stop=self.accounts.stop, fixture=self.fixture,
                           export_path=lambda name, relative: self.accounts.nodes[name].state + "/" + relative)
        self.phase("all 128 test sats collected; four test wallets empty")

    def exercise(self):
        self.form_diamond()
        self.phase("native identities and process epochs bound", processes=self.process_snapshots())
        self.financial_checkpoint(0)
        try:
            baseline = self.ctl("source", "status")
            self.watch_started = True
            self.evidence["watch_calls"] = 1
            self.save()
            self.ctl("source", "watch", destination=self.nodes["n03"].npub,
                     max_rate_msat_per_kib=PRICE_CEILING)
            self.drive_route("n01", baseline, "initial_cheaper_provider")
            self.financial_checkpoint(1)
            before_cut = self.ctl("source", "status")
            first = self.nodes["n01"]
            try:
                if self.active_failover:
                    self.drive_route("n02", before_cut, "wireless_failover", radio=first)
                else:
                    first.mesh_down()
                    self.phase("cheaper provider left Wi-Fi; source UDP adjacency must remain")
                states = eventually("only the cheaper provider wireless edge disappears",
                                    lambda: self.topology(radio_down="n01"), 100)
                self.phase("provider radio loss observed with client adjacency intact", topology=states)
                if self.active_failover:
                    self.evidence["active_failover"]["eviction_observed_at"] = time.monotonic()
                else:
                    self.drive_route("n02", before_cut, "wireless_failover")
                self.financial_checkpoint(2)
                before_rejoin = self.ctl("source", "status")
            finally:
                if not self.active_failover or self.evidence.get("active_failover", {}).get("cut_attempted", False):
                    first.mesh_up()
            eventually("original provider radio rejoins", self.topology, 150)
            self.verify_open_profiles()
            self.drive_route("n01", before_rejoin, "recovered_cheaper_provider")
            self.financial_checkpoint(2)
            self.verify_shortcuts(names=("n01", "n02"))
            self.evidence["paid_switching_accepted"] = True
            self.save()
        except Exception as error:
            self.evidence["acceptance_failure"] = str(error)
            self.save()
            raise
        finally:
            signal.alarm(0)
            try:
                self.collect()
            except Exception as error:
                self.evidence["collection_failure"] = str(error)
                self.save()
                raise

    def finish(self):
        try:
            super().finish()
        finally:
            finish_mint(self)
        if not self.evidence["passed"]:
            raise RuntimeError("paid diamond incomplete; preserve the recorded mint and accounts")


def parser():
    result = topology_parser()
    result.description = __doc__
    result.add_argument("--mint-binary", type=Path, required=True)
    result.add_argument("--active-failover", action="store_true",
                        help="cut the selected provider during paid traffic and drive recovery before eviction")
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("paid diamond exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    PaidDiamondRun(args).execute()


if __name__ == "__main__":
    main()
