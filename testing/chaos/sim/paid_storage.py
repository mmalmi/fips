"""Measure payment storage syscalls in a separate, isolated paid Ethernet run."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys

from .paid_faults import validate_finances
from .paid_payment_faults import diagnostics
from .paid_relay import PaidRelayRun, eventually, write_json
from .paid_settlement import original_channels, settle_and_collect
from .run_scope import docker, inspect_owned

DIAGNOSTICS = Path(__file__).resolve().parents[2] / "relay-cadence"
sys.path.insert(0, str(DIAGNOSTICS))
from storage_trace import analyze
from validation import reconciled_payment


def storage_paths():
    root = "/tmp/bench-state"
    return {
        "sdk_private_snapshot": [f"{root}/wallet/.cashu-private-*", f"{root}/wallet/spilman-client.json"],
        "receiver_sqlite": [f"{root}/receiver/spilman-receiver.sqlite*"],
        "wallet_sqlite": [f"{root}/wallet/cashu/*"],
        "relay_journals": [f"{root}/{name}/*" for name in ("buyer", "seller", "controller")],
        "directory_syncs": [root, *(f"{root}/{name}" for name in (
            "buyer", "seller", "controller", "wallet", "receiver"))],
        "process_log": ["/run/bench/process.log"],
    }


def validate_storage(summaries, lifecycles):
    if set(summaries) != {"n01", "n02", "n03"} or set(lifecycles) != set(summaries):
        raise RuntimeError("storage capture changed the original node set")
    for node, summary in summaries.items():
        if lifecycles[node].get("accepted") is not True:
            raise RuntimeError("storage tracer lifecycle is incomplete")
        for category in ("sdk_private_snapshot", "receiver_sqlite", "wallet_sqlite",
                         "relay_journals", "directory_syncs"):
            value = summary["categories"][category]
            if value["write_errors"] or value["sync_errors"]:
                raise RuntimeError("storage capture observed a failed file operation")
        if summary["categories"]["wallet_sqlite"]["write_calls"]:
            raise RuntimeError("ordinary payment window wrote to the funding wallet")
    for node in ("n01", "n03"):
        if summaries[node]["categories"]["sdk_private_snapshot"]["write_bytes"] <= 0:
            raise RuntimeError("capture did not observe the buyer SDK snapshot writes")
    if summaries["n02"]["categories"]["receiver_sqlite"]["write_bytes"] <= 0:
        raise RuntimeError("capture did not observe receiver SQLite writes")


class StorageRun(PaidRelayRun):
    def create_container(self, node, network, image):
        super().create_container(node, network, image)
        item = inspect_owned("container", self.containers[node], self.name)
        version = docker(["exec", item["Id"], "strace", "--version"]).splitlines()[0]
        self.evidence.setdefault("strace_versions", {})[node] = version

    def boundary(self, finances):
        def snapshot():
            result = {}
            for node in self.nodes:
                status = self.ctl(node, "status")
                channels = finances[node]["signed"]
                if status["last_error"] is not None or set(status["payment_progress"]) != set(channels):
                    raise RuntimeError("payment boundary changed original channels or has an error")
                result[node] = diagnostics(status, next(iter(channels), None))
                if channels:
                    try:
                        reconciled_payment(result[node]["progress"])
                    except ValueError:
                        return None
            return result

        def stable():
            first = snapshot()
            second = snapshot() if first else None
            return {"guard": first, "sample": second} if first is not None and first == second else None

        return eventually("quiet original payment boundary", stable, 15)

    def start_trace(self, node):
        item = inspect_owned("container", self.containers[node], self.name)
        directory = self.root / node
        for name in ("storage_trace.py", "storage_worker.py"):
            shutil.copyfile(DIAGNOSTICS / name, directory / name)
        write_json(directory / "storage-paths.json", storage_paths())
        self.trace_nodes.append(node)
        docker(["exec", "-d", item["Id"], "python3", "/run/bench/storage_worker.py"])

        def ready():
            done = directory / "storage.done.json"
            if done.exists():
                raise ValueError("storage worker ended before workload start")
            value = json.loads((directory / "storage.ready.json").read_text())
            return value if value.get("threads_attached", 0) > 0 else None

        self.evidence["trace_ready"][node] = eventually("storage tracer attachment", ready, 15)

    def stop_traces(self):
        errors = []
        for node in self.trace_nodes:
            (self.root / node / "storage.stop").touch(exist_ok=False)
        for node in self.trace_nodes:
            try:
                value = eventually("bounded tracer detach", lambda: json.loads(
                    (self.root / node / "storage.done.json").read_text()), 25)
                self.evidence["trace_lifecycle"][node] = value
                if value.get("accepted") is not True:
                    errors.append(node)
            except (RuntimeError, OSError) as error:
                errors.append(f"{node}:{type(error).__name__}")
        if errors:
            raise RuntimeError("tracer lifecycle failed: " + ",".join(errors))

    def capture(self, before):
        self.trace_nodes = []
        self.evidence.update(trace_ready={}, trace_lifecycle={}, timing_comparison=False)
        self.evidence["trace_source_sha256"] = {
            name: hashlib.sha256((DIAGNOSTICS / name).read_bytes()).hexdigest()
            for name in ("storage_trace.py", "storage_worker.py")}
        warm = self.boundary(before)
        try:
            for node in self.nodes:
                self.start_trace(node)
            self.evidence["payment_before"] = self.boundary(before)
            if self.evidence["payment_before"] != warm:
                raise RuntimeError("warmup payment work escaped into the trace")
            for _ in range(3):
                for source, destination in (("n01", "n03"), ("n03", "n01")):
                    self.probe(source, destination)
            after = eventually("traced automatic payments", lambda: self.paid_after(before))
            validate_finances(before, after)
            self.evidence["payment_after"] = self.boundary(before)
            self.evidence["traced_workload"] = {
                "delivered_packets": 48, "delivered_bytes": 12288,
                "automatic_payments_credited": True, "financial": after,
            }
        finally:
            self.stop_traces()
        summaries = {}
        for node in self.nodes:
            path = self.root / node / "storage.trace"
            with path.open() as stream:
                summaries[node] = analyze(stream, storage_paths())
        validate_storage(summaries, self.evidence["trace_lifecycle"])
        self.evidence["storage"] = summaries
        self.evidence["storage_accepted"] = True

    def exercise(self):
        eventually("native Ethernet line", self.line_ready, 150)
        discovered = eventually("initial financial snapshot", self.finances)
        self.unpaid_probe(discovered)
        for source, destination in (("n01", "n03"), ("n03", "n01")):
            self.ctl(source, "buy", destination=self.nodes[destination].npub)
            self.probe(source, destination)
        before = eventually("warm automatic payments", lambda: self.paid_after(discovered))
        original_channels(self.nodes, before)
        try:
            self.capture(before)
        finally:
            # Even rejected captures must close the same accounts. A failed or
            # uncertain closure retains resources through PaidRelayRun.run().
            signal.alarm(0)
            current = eventually("original accounts before closure", self.finances)
            settle_and_collect(self, current)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", required=True, help="existing ARM64 image with Python and strace")
    args = parser.parse_args()
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("storage diagnostic exceeded its ten-minute bound")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(600)
    try:
        StorageRun(args).run()
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
