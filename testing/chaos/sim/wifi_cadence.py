"""Matched payment-cadence measurements on three guarded OpenWrt routers.

Reuse the paid Wi-Fi lifecycle with a fresh capped local or explicit remote
mint. Every trial settles and collects before the next can start. A pilot runs
one full workload sequence; it cannot establish a cadence comparison.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .paid_relay import eventually, write_json
from .paid_settlement import original_channels, require, settle_and_collect
from .paid_wifi import PaidWifiRun
from .wifi_remote import digest
from .wifi_measurements import DATAPLANE_DROP_LOG_FILTER


from .cadence_workloads import POLICIES, SCHEDULE, perform, policies, stream


def metadata(args):
    selected = policies(args)
    relay_sha = digest(args.binary.read_bytes())
    provenance = json.loads(args.provenance.read_text())
    verified = provenance["verification"]
    require(verified["artifact"]["sha256"] == relay_sha
            and verified["build"]["exit_code"] == 0
            and "--release" in verified["build"]["command"]
            and verified["features"] == ["measurements"]
            and verified["target"] == "aarch64-unknown-linux-musl"
            and verified["source_changes_during_build"] == [],
            "supplied relay does not match its optimized measurement build evidence")
    return {
        "schema": 3, "funded_directions": 2, "optimized": True,
        "nodes": 3, "paid_relays": 1, "active_channels": 2, "repeats": 2,
        "unpaid_percent": 50, "window_msat": 4000, "grace_msat": 8000,
        "channel_capacity_sat": 32, "fee_msat_per_kib": 1,
        "billing": "forwarding_data", "quote_max_units": 16 * 1024 * 1024,
        "transport": "native Ethernet over 802.11s", "one_way_latency": False,
        "workload_schedule": SCHEDULE, "common_tail_ms": 3000,
        "policy_order": list(selected), "pilot": args.pilot,
        "pilot_delay_ms": selected[0] if args.pilot else None,
        "native_counters": getattr(args, "native_counters", False),
        "dataplane_drop_log_filter": (DATAPLANE_DROP_LOG_FILTER
                                      if getattr(args, "dataplane_drop_logs", False) else None),
        "mint_connection": "controller_ssh" if args.mint_ssh_forward else "remote_lan",
        "relay_sha256": relay_sha,
        "mint_sha256": digest(args.mint_binary.read_bytes()),
        "provenance": provenance,
    }


class CadenceRun(PaidWifiRun):
    def __init__(self, args, trial, delay, record):
        self.trial, self.delay, self.record = trial, delay, record
        super().__init__(args)
        if getattr(args, "dataplane_drop_logs", False):
            for node in self.nodes.values():
                node.diagnostic_log_filter = DATAPLANE_DROP_LOG_FILTER
        self.evidence.update(trial=trial, max_delay_ms=delay,
                             measurement_acceptance="not_analyzed")
        for name in ("wifi_cadence.py", "cadence_workloads.py", "wifi_measurements.py", "remote_mint.py"):
            self.evidence["harness_sha256"][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config["terms"].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1,
                               quote_max_units=16 * 1024 * 1024)
        config["payment_cadence"] = {"max_delay_ms": self.delay, "unpaid_percent": 50}
        return config

    def emit(self, **fields):
        self.record({"trial": self.trial, "max_delay_ms": self.delay, **fields})

    def before_launch(self):
        self.evidence["hardware_context"] = {
            name: node.remote("uname -a; cat /proc/loadavg; cat /proc/meminfo; df -k /tmp").decode()
            for name, node in self.nodes.items()
        }
        super().before_launch()

    def sample(self):
        from .wifi_measurements import snapshot

        self.monitor.check()
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(snapshot, node, name, getattr(self.args, "native_counters", False),
                                   getattr(self.args, "dataplane_drop_logs", False))
                       for name, node in self.nodes.items()]
            return [future.result() for future in futures]

    stream = stream

    def warmup(self):
        results = []
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            for _ in range(6):
                probe = self.stream(1, 1, source=source, destination=destination)
                results.append({"source": source, "destination": destination, **probe})
                if probe["receiver"]["unique_packets"] == 1:
                    break
            require(probe["receiver"]["unique_packets"] == 1, "native session warmup failed")
        self.emit(warmup=results)
        time.sleep(3)

    def workload(self, name):
        before_guard, before = self.sample(), self.sample()
        started = time.monotonic()
        workload = perform(self.stream, name, started=started)
        offered, probes = workload["offered_elapsed_ms"], workload["probes"]
        time.sleep(3)
        # Preserve the fixed tail even if payment reconciliation is incomplete.
        # Quiet-boundary validation runs on this evidence after funds collection.
        after = self.sample()
        observed = int((time.monotonic() - started) * 1000)
        after_guard = self.sample()
        self.emit(data={"workload": name, "offered_elapsed_ms": offered,
                        "observation_elapsed_ms": observed, "before_guard": before_guard,
                        "before": before, "after": after, "after_guard": after_guard,
                        "probes": probes})
        self.phase("matched wireless workload recorded", workload=name)

    def collect(self):
        finances = eventually("financial snapshot before collection", self.finances)
        original_channels(self.nodes, finances)
        settle_and_collect(self, finances, execute=self.account_execute,
                           stop=lambda name: self.nodes[name].stop(),
                           export_path=lambda name, relative: self.nodes[name].state + "/" + relative)
        collection = self.evidence["phases"][-1]["settlement_collection"]
        self.emit(**self.evidence["mint"], settled_channels=len(collection["settlements"]))
        self.phase("all 384 test sats collected; every test wallet empty")

    def exercise(self):
        self.form_line()
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            self.ctl(source, "buy", destination=self.nodes[destination].npub)
        funded = eventually("initial funded channel observation", self.finances)
        original_channels(self.nodes, funded)
        # A workload or sampler failure must not skip collection of known funds.
        # Uncertain funding before this point retains the original accounts/mint.
        try:
            self.warmup()
            for name in SCHEDULE:
                self.workload(name)
            self.verify_shortcuts()
        finally:
            # Remote operations retain their own timeouts. The workload alarm
            # must not interrupt an export or collection partway through.
            signal.alarm(0)
            self.collect()


def run(args):
    selected = policies(args)
    report = metadata(args)
    args.output.mkdir(mode=0o700)
    raw = args.output / "measurements.jsonl"
    evidence = {"passed": False, "pilot": args.pilot, "trials_completed": 0,
                "comparison_complete": False}
    try:
        with raw.open("x") as output:
            def record(row):
                output.write(json.dumps(row) + "\n")
                output.flush()
                os.fsync(output.fileno())

            record(report)
            for trial, delay in enumerate(selected):
                trial_args = argparse.Namespace(**vars(args))
                trial_args.output = args.output / f"trial-{trial:02}-{delay}ms"
                trial_args.open_mesh = False
                signal.alarm(900)
                CadenceRun(trial_args, trial, delay, record).execute()
                evidence["trials_completed"] += 1
        analyzer = Path(__file__).resolve().parents[2] / "relay-cadence" / "analyze.py"
        command = [sys.executable, str(analyzer), str(raw)] + (["--pilot"] if args.pilot else [])
        checked = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        (args.output / "analysis.stderr").write_text(checked.stderr)
        require(checked.returncode == 0, "measurement validation failed; funds already collected")
        (args.output / "summary.json").write_text(checked.stdout)
        evidence["comparison_complete"] = not args.pilot
        evidence["passed"] = True
    except Exception as error:
        evidence["error"] = type(error).__name__
        raise
    finally:
        signal.alarm(0)
        write_json(args.output / "result.json", evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "binary", "mint-binary", "provenance", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    mint = parser.add_mutually_exclusive_group(required=True)
    mint.add_argument("--mint-host", type=Path, help="explicit private Linux mint-host inventory")
    mint.add_argument("--mint-ssh-forward", action="store_true",
                      help="use a native controller mint over private router loopback forwards")
    parser.add_argument("--mint-address", required=True)
    parser.add_argument("--pilot", action="store_true", help="one full trial; no policy comparison")
    parser.add_argument("--pilot-delay-ms", type=int, choices=sorted(set(POLICIES)),
                        help="pilot payment age limit; defaults to 250 ms")
    parser.add_argument("--native-counters", action="store_true",
                        help="capture existing native forwarding/drop counters at each boundary")
    parser.add_argument("--dataplane-drop-logs", action="store_true",
                        help="pin existing dataplane drop logging and capture per-window byte offsets")
    args = parser.parse_args()
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("cadence trial exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    run(args)


if __name__ == "__main__":
    main()
