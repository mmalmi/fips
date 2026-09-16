#!/usr/bin/env python3
"""Validate and summarize the real-service cadence experiment (stdlib only)."""
import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean


def paired(before, after):
    if len(before) != len(after):
        raise ValueError("measurement shape changed")
    return zip(before, after)


def delta(before, after, key):
    a, b = before[key], after[key]
    if not isinstance(a, int) or not isinstance(b, int) or b < a:
        raise ValueError(f"missing or reset counter: {key}")
    return b - a


def summarize(row):
    data = row["data"]
    if len(data["before"]) != 5 or len(data["after"]) != 5:
        raise ValueError("expected five measured service processes")
    counts = {"idle": [], "bursty": [64] * 8, "steady": [3200], "high_rate": [32000]}
    if [p["sender"]["requested_packets"] for p in data["probes"]] != counts[data["workload"]]:
        raise ValueError("offered workload changed")
    result = defaultdict(float)
    for key in ("submitted_packets", "unsubmitted_packets", "delivered_packets",
                "delivered_bytes", "duplicates", "out_of_order_packets", "invalid_packets",
                "latency_samples", "invalid_timestamps", "latency_sum_us", "nodes_with_error"):
        result[key] = 0
    for before, after in paired(data["before"], data["after"]):
        a, b = before["measurements"], after["measurements"]
        if a["process_id"] != b["process_id"]:
            raise ValueError("a service restarted during a measurement")
        result["process_cpu_ms"] += delta(a, b, "process_cpu_ns") / 1e6
        for name, prior in a["operations"].items():
            current = b["operations"][name]
            spans = delta(prior, current, "spans")
            if delta(prior, current, "cpu_samples") != spans:
                raise ValueError(f"missing thread CPU samples: {name}")
            result["journal_writes"] += delta(prior, current, "journal_writes")
            result["journal_bytes"] += delta(prior, current, "journal_bytes_written")
            result["journal_syncs"] += delta(prior, current, "journal_syncs")
            if name in ("payment_sign", "payment_usage", "payment_update"):
                result["payment_cpu_ms"] += delta(prior, current, "thread_cpu_ns") / 1e6
                result["payment_journal_bytes"] += delta(prior, current, "journal_bytes_written")
                result["payment_journal_writes"] += delta(prior, current, "journal_writes")
            if name == "payment_sign":
                result["signs"] += spans
            if name == "payment_update":
                result["updates"] += spans
        control_before = {c["service_port"]: c["counters"] for c in before["control_traffic"]}
        for service in after["control_traffic"]:
            if service["service_port"] == 44743:
                prior = control_before[44743]
                result["payment_record_bytes"] += delta(prior, service["counters"], "stream_bytes_sent")
                result["payment_requests"] += delta(prior, service["counters"], "requests_started")
        peers_before = {p["npub"]: p for p in before["peers"] if p["connected"]}
        peers_after = {p["npub"]: p for p in after["peers"] if p["connected"]}
        if peers_before.keys() != peers_after.keys():
            raise ValueError("connected topology changed during a matched run")
        for identity, current in peers_after.items():
            prior = peers_before[identity]
            if prior["link_id"] != current["link_id"]:
                raise ValueError("link counters changed epoch")
            result["aggregate_link_bytes"] += delta(prior, current, "sent_bytes")
        if after["last_error"]:
            result["nodes_with_error"] += 1
    buckets = None
    bounds = None
    for probe in data["probes"]:
        sent, received = probe["sender"], probe["receiver"]
        result["submitted_packets"] += sent["submitted_packets"]
        result["unsubmitted_packets"] += sent["requested_packets"] - sent["submitted_packets"]
        result["delivered_packets"] += received["unique_packets"]
        result["delivered_bytes"] += received["unique_bytes"]
        result["duplicates"] += received["duplicate_packets"]
        result["out_of_order_packets"] += received["out_of_order_packets"]
        result["invalid_packets"] += received["invalid_packets"]
        latency = received["latency"]
        if latency["samples"] + latency["invalid_timestamps"] != received["unique_packets"]:
            raise ValueError("timing sample coverage differs from packet delivery")
        result["latency_samples"] += latency["samples"]
        result["invalid_timestamps"] += latency["invalid_timestamps"]
        result["latency_sum_us"] += latency["sum_us"]
        if buckets is None:
            bounds = latency["bucket_upper_bounds_us"]
            buckets = [0] * len(latency["bucket_counts"])
        if bounds != latency["bucket_upper_bounds_us"]:
            raise ValueError("latency histogram changed")
        buckets = [a + b for a, b in paired(buckets, latency["bucket_counts"])]
    result["missing_submitted_packets"] = result["submitted_packets"] - result["delivered_packets"]
    if result["missing_submitted_packets"] < 0:
        raise ValueError("received more unique packets than submitted")
    result["mean_latency_us"] = result["latency_sum_us"] / result["latency_samples"] if result["latency_samples"] else None
    result["p95_upper_us"] = None
    if buckets:
        if sum(buckets) != result["latency_samples"]:
            raise ValueError("histogram differs from valid sample count")
        cumulative = 0
        for index, count in enumerate(buckets):
            cumulative += count
            if cumulative >= result["latency_samples"] * 0.95:
                result["p95_upper_us"] = bounds[index] if index < len(bounds) else None
                break
    result["observation_seconds"] = data["observation_elapsed_ms"] / 1000
    result["goodput_mbps"] = result["delivered_bytes"] * 8 / (data["offered_elapsed_ms"] * 1000)
    result["process_cpu_seconds_per_gib"] = result["process_cpu_ms"] / 1000 * 2**30 / result["delivered_bytes"] if result["delivered_bytes"] else None
    return dict(result)


def analyze(path):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    metadata = rows[0]
    if metadata["schema"] != 1 or metadata["funded_directions"] != 2:
        raise ValueError("unsupported experiment schema or funding setup")
    records = [r for r in rows[1:] if "data" in r]
    conserved = {r["trial"]: r for r in rows[1:] if r.get("conserved")}
    expected = [250, 500, 1000, 2000, 2000, 1000, 500, 250]
    if len(records) != 32 or len(conserved) != 8:
        raise ValueError("incomplete matrix or missing financial conservation evidence")
    grouped = defaultdict(list)
    trials = []
    for trial_id, delay in enumerate(expected):
        accounting = conserved[trial_id]
        if accounting["collected_sat"] != accounting["issued_sat"] or accounting["settled_channels"] != 6:
            raise ValueError("invalid trial conservation")
        trial_records = [r for r in records if r["trial"] == trial_id]
        if [r["data"]["workload"] for r in trial_records] != ["idle", "bursty", "steady", "high_rate"]:
            raise ValueError("unmatched workload sequence")
        for row in trial_records:
            if row["max_delay_ms"] != delay:
                raise ValueError("unmatched policy order")
            result = summarize(row)
            trials.append({"trial":trial_id, "max_delay_ms":delay, "workload":row["data"]["workload"], **result})
            grouped[(row["data"]["workload"], delay)].append(result)
    return metadata, trials, grouped


def markdown(metadata, grouped):
    lines = ["# Cadence measurements", "", f"Optimized build: **{metadata['optimized']}**. Two opposite-order repetitions; five real service processes and three paid relays over loopback UDP.", "",
        "All costs below sum the five service processes. CPU is measured CPU time. Payment CPU covers synchronous signing, usage handling and balance update handling; it excludes scheduler, serialization and transport CPU. Storage is logical relay journal I/O, excluding Cashu SQLite and physical writes. Record bytes exclude TCP/FIPS/carrier overhead. These are offered workloads, not maximum throughput.", "",
        "| Workload | Limit ms | Delivered / submitted | Payment CPU ms | All CPU ms | Updates | Payment records KiB | Payment journal writes | Mean delay ms |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for workload in ("idle", "bursty", "steady", "high_rate"):
        for delay in (250, 500, 1000, 2000):
            values = grouped[(workload, delay)]
            avg = lambda k: mean(v.get(k, 0) for v in values)
            latency = f"{avg('mean_latency_us') / 1000:.3f}" if all(v["mean_latency_us"] is not None for v in values) else "—"
            lines.append(f"| {workload} | {delay} | {int(sum(v['delivered_packets'] for v in values))} / {int(sum(v['submitted_packets'] for v in values))} | {avg('payment_cpu_ms'):.2f} | {avg('process_cpu_ms'):.2f} | {avg('updates'):.1f} | {avg('payment_record_bytes') / 1024:.2f} | {avg('payment_journal_writes'):.1f} | {latency} |")
    lines += ["", "Delivery totals combine both repetitions; other values are arithmetic means per observation window. Idle includes 4 seconds plus the common 3-second tail. Other windows include traffic, a bounded receive drain and the same tail. Raw trial summaries retain loss, CPU/GiB, timing quality and aggregate link counters. Impaired links, complete payment wire attribution and physical device performance remain separate work."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    metadata, trials, grouped = analyze(args.report)
    print(markdown(metadata, grouped) if args.markdown else json.dumps({"metadata":metadata, "trials":trials}, indent=2))
