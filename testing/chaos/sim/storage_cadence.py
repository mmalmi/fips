"""Matched payment storage diagnostics; tracing results are not timing benchmarks."""

import argparse
import copy
import json
import os
from pathlib import Path
import signal
import time

from .cadence_workloads import POLICIES, SCHEDULE, perform, policies, stream
from .paid_relay import write_json
from .paid_settlement import require
from .paid_storage import DURABILITY_COUNTERS as DURABILITY, StorageRun, validate_storage
from .wifi_remote import digest
from validation import (COUNTERS, OPERATIONS, PAYMENT_OPERATIONS, reconciled_payment, unsigned,
                        validate_hardware_schedule, validate_probe)

NODES = {"n01", "n02", "n03"}
FILES = ("sdk_private_snapshot", "receiver_sqlite", "wallet_sqlite", "relay_journals")
CONTROL = {"stream_bytes_sent", "stream_bytes_received", "requests_started", "requests_received"}
MAX_SAMPLING_MS = 2000


def boundary_sample(record):
    require(record["guard"] == record["sample"], "payment work crossed a sampling boundary")
    result = record["sample"]
    require(set(result) == NODES, "measurement node set changed")
    for node, value in result.items():
        require(unsigned(value["process_id"]) > 0, "measurement process identity is missing")
        if node == "n02":
            require(value["progress"] is None, "forwarder acquired unexpected buyer authority")
        else:
            reconciled_payment(value["progress"])
        require(set(value["operations"]) == set(PAYMENT_OPERATIONS)
                and set(value["control"]) == CONTROL, "payment measurements changed shape")
        require(set(value["durability"]) == OPERATIONS, "durability operations changed shape")
        for operation, counters in value["durability"].items():
            require(set(counters) == set(DURABILITY), "durability counters are missing")
            for key, amount in counters.items():
                unsigned(amount)
                if operation in PAYMENT_OPERATIONS:
                    require(amount == value["operations"][operation][key],
                            "payment and durability evidence disagree")
        for counters in value["operations"].values():
            require(set(counters) == COUNTERS, "payment counters are missing")
            for amount in counters.values():
                unsigned(amount)
    return result


def difference(before, after):
    require(set(before) == set(after), "counter shape changed")
    result = {}
    for key in before:
        old, new = unsigned(before[key]), unsigned(after[key])
        require(new >= old, "measurement counter reset")
        result[key] = new - old
    return result


def summarize_window(record):
    name = record["workload"]
    expected = SCHEDULE[name].get("packet_counts", [])
    require(len(record["probes"]) == len(expected), "workload stream count changed")
    validate_hardware_schedule(record)
    tail, sampling = (unsigned(record[key]) for key in ("tail_elapsed_ms", "sampling_elapsed_ms"))
    require(3000 <= tail <= 3250 and sampling <= MAX_SAMPLING_MS,
            "the fixed payment tail or boundary sampling exceeded its bounds")
    elapsed = unsigned(record["observation_elapsed_ms"])
    require(0 <= elapsed - record["offered_elapsed_ms"] - tail - sampling <= 5,
            "workload timing does not account for the observation window")
    seen = set()
    for probe, count in zip(record["probes"], expected):
        validate_probe(probe, count, schema=3)
        receiver = probe["receiver"]
        require(receiver["source"] == record["source"] and receiver["stream_id"] not in seen,
                "measured stream source or identity changed")
        seen.add(receiver["stream_id"])
    before, after = (boundary_sample(record[key]) for key in ("payment_before", "payment_after"))
    require(record["payment_after_detach"] == record["payment_after"],
            "payment work escaped the final measurement boundary")
    validate_storage(record["storage"], record["trace_lifecycle"], require_activity=False)
    updates = signs = usage = record_bytes = partial_cpu_ns = 0
    changed = False
    for node in sorted(NODES):
        old, new = before[node], after[node]
        require(old["process_id"] == new["process_id"], "service restarted during tracing")
        control = difference(old["control"], new["control"])
        record_bytes += control["stream_bytes_sent"]
        changed |= any(control.values())
        for operation in OPERATIONS:
            changed |= any(difference(old["durability"][operation],
                                      new["durability"][operation]).values())
        for operation in PAYMENT_OPERATIONS:
            delta = difference(old["operations"][operation], new["operations"][operation])
            require(delta["cpu_samples"] == delta["spans"], "payment CPU samples are missing")
            partial_cpu_ns += delta["thread_cpu_ns"]
            changed |= any(delta.values())
            if operation == "payment_update":
                updates += delta["spans"]
            elif operation == "payment_sign":
                signs += delta["spans"]
            else:
                usage += delta["spans"]
        if old["progress"] is not None:
            difference(
                {k: v for k, v in old["progress"].items() if k != "in_flight"},
                {k: v for k, v in new["progress"].items() if k != "in_flight"})
    categories = {kind: {key: sum(unsigned(record["storage"][node]["categories"][kind][key])
                                  for node in NODES)
                         for key in ("write_bytes", "write_calls", "sync_calls")}
                  for kind in (*FILES, "directory_syncs")}
    for node in NODES:
        require(not any(record["storage"][node]["categories"]["unmatched"][key]
                        for key in ("write_calls", "sync_calls", "write_errors", "sync_errors")),
                "file operations have unmatched paths")
    writes = sum(categories[k]["write_bytes"] for k in FILES)
    syncs = sum(value["sync_calls"] for value in categories.values())
    if name == "idle":
        require(not changed and not any(value for category in categories.values() for value in category.values()),
                "idle payment/storage work did not quiesce")
    delivered = sum(expected) * 1000
    usage_msat = after["n01"]["progress"]["evidence_msat"] - before["n01"]["progress"]["evidence_msat"]
    # The tariff is 1 msat/KiB; encrypted forwarding bytes include the payload.
    require(usage_msat >= delivered // 1024, "delivered traffic lacks metered paid usage")
    return {"workload": name, "delivered_packets": sum(expected), "delivered_bytes": delivered,
            "source_usage_msat": usage_msat, "tail_elapsed_ms": tail,
            "sampling_elapsed_ms": sampling,
            "payment_updates": updates, "payment_signs": signs, "usage_polls": usage,
            "payment_record_bytes": record_bytes, "partial_payment_cpu_ns_under_trace": partial_cpu_ns,
            "file_write_bytes": writes, "file_write_calls": sum(categories[k]["write_calls"] for k in FILES),
            "file_and_directory_sync_calls": syncs, "categories": categories,
            "file_write_bytes_per_delivered_byte": writes / delivered if delivered else None,
            "timing_comparison": False, "physical_media_bytes": None}


class StorageCadenceRun(StorageRun):
    stream = stream

    def __init__(self, args, trial, delay):
        super().__init__(args)
        self.delay = delay
        self.evidence.update(trial=trial, max_delay_ms=delay, timing_comparison=False,
                             workload_schedule=copy.deepcopy(SCHEDULE), common_tail_ms=3000)
        self.evidence["cadence_source_sha256"] = {
            name: digest(Path(__file__).with_name(name).read_bytes())
            for name in ("storage_cadence.py", "cadence_workloads.py", "paid_storage.py", "paid_relay.py")}

    def profile_config(self, node, mint_url):
        config = super().profile_config(node, mint_url)
        config["terms"].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1,
                               quote_max_units=16 * 1024 * 1024)
        config["payment_cadence"] = {"max_delay_ms": self.delay, "unpaid_percent": 50}
        return config

    def capture(self, before):
        windows = self.evidence["storage_windows"] = []
        previous = self.boundary(before)
        for name in SCHEDULE:
            require(self.line_ready(), "measured Ethernet path changed")
            record = {"workload": name, "source": self.nodes["n01"].npub}
            windows.append(record)
            with self.trace(record, capture=name, require_activity=False):
                record["payment_before"] = self.boundary(before, wait=False)
                require(record["payment_before"] == previous, "payment work occurred between windows")
                started = time.monotonic()
                record.update(perform(self.stream, name, started=started))
                tail_started = time.monotonic()
                time.sleep(3)
                sampling_started = time.monotonic()
                record["tail_elapsed_ms"] = int((sampling_started - tail_started) * 1000)
                record["payment_after"] = self.boundary(before, wait=False)
                record["sampling_elapsed_ms"] = int((time.monotonic() - sampling_started) * 1000)
                record["observation_elapsed_ms"] = int((time.monotonic() - started) * 1000)
            record["payment_after_detach"] = self.boundary(before, wait=False)
            record["summary"] = summarize_window(record)
            previous = record["payment_after"]
            require(self.line_ready(), "measured Ethernet path changed")
            print(f"storage cadence {self.delay} ms: {name} captured", flush=True)
        self.evidence["storage_accepted"] = True


def run(args):
    selected = policies(args)
    args.output.mkdir(mode=0o700)
    evidence = {"passed": False, "pilot": args.pilot, "comparison_complete": False,
                "policy_order": list(selected), "timing_comparison": False, "trials": []}
    try:
        for trial, delay in enumerate(selected):
            trial_args = argparse.Namespace(**vars(args))
            trial_args.output = args.output / f"trial-{trial:02}-{delay}ms"
            signal.alarm(600)
            StorageCadenceRun(trial_args, trial, delay).run()
            result = json.loads((trial_args.output / "result.json").read_text())
            require(result["passed"] and result["storage_accepted"] and not result["resources_retained"]
                    and not result["cleanup_errors"], "trial or financial cleanup did not complete")
            require(result["mint"]["conserved"] is True and result["mint"]["issued_sat"] == 384
                    and result["mint"]["collected_sat"] == 384, "trial money is not conserved")
            windows = result["storage_windows"]
            require([window["workload"] for window in windows] == list(SCHEDULE), "trial schedule changed")
            summaries = [summarize_window(window) for window in windows]
            if evidence["trials"]:
                require(result["binaries"] == evidence["binaries"] and result["image"] == evidence["image"],
                        "comparison artifacts changed")
            else:
                evidence.update(binaries=result["binaries"], image=result["image"])
            evidence["trials"].append({"trial": trial, "max_delay_ms": delay,
                                       "workloads": summaries, "collected_sat": 384})
        evidence.update(passed=True, comparison_complete=not args.pilot)
    except Exception as error:
        evidence["error"] = type(error).__name__
        raise
    finally:
        signal.alarm(0)
        write_json(args.output / "result.json", evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary-dir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--image", required=True, help="existing ARM64 image with Python and strace")
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--pilot-delay-ms", type=int, choices=sorted(set(POLICIES)))
    args = parser.parse_args()
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("storage cadence trial exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    run(args)


if __name__ == "__main__":
    main()
