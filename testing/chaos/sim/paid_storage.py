"""Measure payment storage syscalls in a separate, isolated paid Ethernet run."""

import argparse
from contextlib import contextmanager
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
from storage_worker import trace_directory
from validation import OPERATIONS, reconciled_payment, unsigned

DURABILITY_COUNTERS = ("journal_bytes_written", "journal_writes", "journal_syncs", "journal_commits")


def durability_counters(measurements):
    try:
        operations = measurements["operations"]
        if not isinstance(operations, dict) or set(operations) != OPERATIONS:
            raise ValueError("storage boundary requires every measurement operation")
        return {name: {key: unsigned(counters[key]) for key in DURABILITY_COUNTERS}
                for name, counters in operations.items()}
    except (KeyError, TypeError):
        raise ValueError("storage boundary has missing durability counters") from None


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


def validate_storage(summaries, lifecycles, require_activity=True):
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
    if require_activity:
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

    def boundary(self, finances, wait=True):
        def snapshot():
            result = {}
            reconciled = True
            for node in self.nodes:
                status = self.ctl(node, "status")
                channels = finances[node]["signed"]
                if status["last_error"] is not None or set(status["payment_progress"]) != set(channels):
                    raise RuntimeError("payment boundary changed original channels or has an error")
                result[node] = diagnostics(status, next(iter(channels), None))
                result[node]["durability"] = durability_counters(status["measurements"])
                if channels:
                    try:
                        reconciled_payment(result[node]["progress"])
                    except ValueError:
                        reconciled = False
            return result if reconciled else None

        def stable():
            first = snapshot()
            second = snapshot() if first is not None or not wait else None
            return {"guard": first, "sample": second} if first is not None and first == second else None

        if wait:
            return eventually("quiet original payment boundary", stable, 15)
        result = stable()
        if result is None:
            raise RuntimeError("payment boundary is not reconciled and stable")
        return result

    def start_trace(self, node, record, capture):
        item = inspect_owned("container", self.containers[node], self.name)
        node_root = self.root / node
        directory = trace_directory(node_root, capture)
        if capture is not None:
            directory.mkdir(mode=0o700)
        for name in ("storage_trace.py", "storage_worker.py"):
            shutil.copyfile(DIAGNOSTICS / name, node_root / name)
        write_json(directory / "storage-paths.json", storage_paths())
        self.trace_nodes.append(node)
        command = ["exec", "-d", item["Id"], "python3", "/run/bench/storage_worker.py"]
        docker(command + ([] if capture is None else [capture]))

        def ready():
            done = directory / "storage.done.json"
            if done.exists():
                raise ValueError("storage worker ended before workload start")
            value = json.loads((directory / "storage.ready.json").read_text())
            return value if value.get("threads_attached", 0) > 0 else None

        record["trace_ready"][node] = eventually("storage tracer attachment", ready, 15)

    def stop_traces(self, record, capture):
        errors = []
        for node in self.trace_nodes:
            try:
                (trace_directory(self.root / node, capture) / "storage.stop").touch(exist_ok=False)
            except OSError as error:
                errors.append(f"{node}:{type(error).__name__}")
        for node in self.trace_nodes:
            try:
                value = eventually("bounded tracer detach", lambda: json.loads(
                    (trace_directory(self.root / node, capture) / "storage.done.json").read_text()), 25)
                record["trace_lifecycle"][node] = value
                if value.get("accepted") is not True:
                    errors.append(node)
            except (RuntimeError, OSError) as error:
                errors.append(f"{node}:{type(error).__name__}")
        if errors:
            raise RuntimeError("tracer lifecycle failed: " + ",".join(errors))

    @contextmanager
    def trace(self, record, capture=None, require_activity=True):
        trace_directory(self.root, capture)
        if getattr(self, "trace_nodes", None):
            raise RuntimeError("storage capture is already active")
        self.trace_nodes = []
        record.update(trace_ready={}, trace_lifecycle={}, timing_comparison=False,
                      storage={}, storage_accepted=False)
        record["trace_source_sha256"] = {
            name: hashlib.sha256((DIAGNOSTICS / name).read_bytes()).hexdigest()
            for name in ("storage_trace.py", "storage_worker.py")}
        attached = False
        try:
            for node in self.nodes:
                self.start_trace(node, record, capture)
            attached = True
            yield
        finally:
            try:
                self.stop_traces(record, capture)
                if attached:
                    for node in self.nodes:
                        path = trace_directory(self.root / node, capture) / "storage.trace"
                        with path.open() as stream:
                            record["storage"][node] = analyze(
                                stream, storage_paths(),
                                allow_empty=capture is not None and not require_activity,
                                allow_detached_eventfd=True)
                    validate_storage(record["storage"], record["trace_lifecycle"], require_activity)
                    record["storage_accepted"] = True
            finally:
                self.trace_nodes = []

    def capture(self, before):
        warm = self.boundary(before)
        with self.trace(self.evidence):
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
