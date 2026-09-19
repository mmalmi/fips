#!/usr/bin/env python3
"""Validate and summarize the real-service cadence experiment (stdlib only)."""
import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean
from native_counters import record as record_native_counters
from service_carrier import record as record_service_carrier
from validation import (HARDWARE_SCHEDULE, HARDWARE_WORKLOADS, OS_IO_COUNTERS,
                        PAYMENT_OPERATIONS, POLICIES, WORKLOADS, payment_counters, probe_delivery_loss,
                        quiet_boundary, unsigned, validate_gap,
                        validate_hardware_schedule, validate_host_pair,
                        validate_idle, validate_measurements, validate_probe)


def paired(before, after):
    if len(before) != len(after):
        raise ValueError("measurement shape changed")
    return zip(before, after)


def delta(before, after, key):
    a, b = before[key], after[key]
    if unsigned(b) < unsigned(a):
        raise ValueError(f"missing or reset counter: {key}")
    return b - a


def summarize_node(before, after):
    result = defaultdict(float)
    a, b = before["measurements"], after["measurements"]
    validate_measurements(a, b)
    result["process_cpu_ms"] += delta(a, b, "process_cpu_ns") / 1e6
    for name, prior in a["operations"].items():
        current = b["operations"][name]
        spans = delta(prior, current, "spans")
        if delta(prior, current, "cpu_samples") != spans:
            raise ValueError(f"missing thread CPU samples: {name}")
        result["journal_writes"] += delta(prior, current, "journal_writes")
        result["journal_bytes"] += delta(prior, current, "journal_bytes_written")
        result["journal_syncs"] += delta(prior, current, "journal_syncs")
        result["journal_commits"] += delta(prior, current, "journal_commits")
        if name in PAYMENT_OPERATIONS:
            result["payment_cpu_ms"] += delta(prior, current, "thread_cpu_ns") / 1e6
            result["payment_journal_bytes"] += delta(prior, current, "journal_bytes_written")
            result["payment_journal_writes"] += delta(prior, current, "journal_writes")
            result["payment_journal_syncs"] += delta(prior, current, "journal_syncs")
            result["payment_journal_commits"] += delta(prior, current, "journal_commits")
            result["payment_spans"] += spans
        if name == "payment_sign":
            result["signs"] += spans
        if name == "payment_usage":
            result["usage_polls"] += spans
        if name == "payment_update":
            result["updates"] += spans
    prior, current = payment_counters(before), payment_counters(after)
    result["payment_record_bytes"] += delta(prior, current, "stream_bytes_sent")
    result["payment_requests"] += delta(prior, current, "requests_started")
    result["payment_received_bytes"] += delta(prior, current, "stream_bytes_received")
    result["payment_received_requests"] += delta(prior, current, "requests_received")
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
    return dict(result)


def normalize_cpu(result, delivered_bytes):
    for category in ("process", "payment"):
        seconds = result[category + "_cpu_ms"] / 1000
        result[category + "_cpu_seconds"] = seconds
        result[category + "_cpu_seconds_per_mib"] = (
            seconds * 2**20 / delivered_bytes if delivered_bytes else None
        )


def summarize(row, schema=2, delivery_rejections=None):
    data = row["data"]
    counts = (HARDWARE_WORKLOADS if schema == 3 else WORKLOADS)[data["workload"]]
    if len(data["probes"]) != len(counts):
        raise ValueError("offered workload changed")
    for index, (probe, count) in enumerate(zip(data["probes"], counts)):
        if delivery_rejections is None:
            validate_probe(probe, count, schema)
        else:
            missing = probe_delivery_loss(probe, count, schema)
            if missing:
                delivery_rejections.append({
                    "trial": row["trial"], "max_delay_ms": row["max_delay_ms"],
                    "workload": data["workload"], "probe_index": index,
                    "submitted_packets": count, "delivered_packets": count - missing,
                    "missing_packets": missing, "reason": "clean-link delivery loss",
                })
    if schema == 3:
        validate_hardware_schedule(data)
    if quiet_boundary(data["before"], schema) != quiet_boundary(data["after"], schema):
        raise ValueError("paying channels changed during measurement")
    validate_gap(data["before_guard"], data["before"], schema)
    validate_gap(data["after"], data["after_guard"], schema)
    result = defaultdict(float)
    for key in ("submitted_packets", "unsubmitted_packets", "delivered_packets",
                "delivered_bytes", "duplicates", "out_of_order_packets", "invalid_packets",
                "latency_samples", "invalid_timestamps", "latency_sum_us", "nodes_with_error"):
        result[key] = 0
    node_results = {}
    os_io = {key: 0 for key in OS_IO_COUNTERS}
    for before, after in paired(data["before"], data["after"]):
        measured = summarize_node(before, after)
        for key, value in measured.items():
            result[key] += value
        if schema == 3:
            validate_host_pair(before, after)
            a, b = before["host_process"], after["host_process"]
            measured.update(
                npub=after["npub"], pid=b["pid"], start_ticks=b["start_ticks"],
                rss_before_kib=a["rss_kib"], rss_after_kib=b["rss_kib"],
                reported_vmhwm_after_kib=b["peak_rss_kib"],
                os_io=({key: delta(a, b, key) for key in OS_IO_COUNTERS}
                       if b["io_available"] else None),
            )
            if measured["os_io"] is not None:
                for key in OS_IO_COUNTERS:
                    os_io[key] += measured["os_io"][key]
            node_results[b["host"]] = measured
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
        if latency is None:
            continue
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
    offered = unsigned(data["offered_elapsed_ms"])
    observed = unsigned(data["observation_elapsed_ms"])
    if not offered or observed < offered + 3000:
        raise ValueError("missing common three-second payment tail")
    result["observation_seconds"] = observed / 1000
    result["goodput_mbps"] = result["delivered_bytes"] * 8 / (offered * 1000)
    result["process_cpu_seconds_per_gib"] = result["process_cpu_ms"] / 1000 * 2**30 / result["delivered_bytes"] if result["delivered_bytes"] else None
    result["payment_cpu_seconds_per_gib"] = result["payment_cpu_ms"] / 1000 * 2**30 / result["delivered_bytes"] if result["delivered_bytes"] else None
    result["payment_record_bytes_per_delivered_byte"] = result["payment_record_bytes"] / result["delivered_bytes"] if result["delivered_bytes"] else None
    result["payment_journal_bytes_per_delivered_byte"] = result["payment_journal_bytes"] / result["delivered_bytes"] if result["delivered_bytes"] else None
    result["payment_cpu_ms_per_update"] = result["payment_cpu_ms"] / result["updates"] if result["updates"] else None
    if schema == 3:
        normalize_cpu(result, result["delivered_bytes"])
        for node in node_results.values():
            normalize_cpu(node, result["delivered_bytes"])
        result["nodes"] = node_results
        observed = sum(node["os_io"] is not None for node in node_results.values())
        result["os_io_observed_nodes"] = observed
        result["os_io"] = os_io if observed == len(node_results) else None
        for key in ("rss_before_kib", "rss_after_kib", "reported_vmhwm_after_kib"):
            result[key] = sum(node[key] for node in node_results.values())
    if data["workload"] == "idle" and schema == 2:
        validate_idle(result)
        if result["payment_received_bytes"] or result["payment_received_requests"]:
            raise ValueError("idle payment traffic received")
    return dict(result)


def record_vmhwm(data, result, previous):
    """Preserve raw boundary readings; an observed maximum is not a proven peak."""
    boundaries = [(name, data[name]) for name in ("before_guard", "before", "after", "after_guard")]
    if previous is not None:
        boundaries.insert(0, ("previous_after_guard", previous))
    result["vmhwm_decreases"] = []
    for index, node in enumerate(data["before"]):
        host = node["host_process"]["host"]
        samples = {name: nodes[index]["host_process"]["peak_rss_kib"] for name, nodes in boundaries}
        result["nodes"][host]["vmhwm_samples_kib"] = samples
        result["nodes"][host]["maximum_observed_vmhwm_kib"] = max(samples.values())
        for (before, a), (after, b) in zip(samples.items(), list(samples.items())[1:]):
            if b < a:
                result["vmhwm_decreases"].append({
                    "host": host, "before_boundary": before, "after_boundary": after,
                    "before_kib": a, "after_kib": b, "decrease_kib": a - b,
                })


def analyze(path, pilot=False):
    return read_report(path, analyze_rows, pilot)


def diagnose(path, pilot=False):
    """Report valid measured costs without accepting a matrix with delivery loss."""
    return read_report(path, diagnose_rows, pilot)


def read_report(path, analyzer, pilot):
    try:
        return analyzer(
            [json.loads(line) for line in path.read_text().splitlines()], pilot=pilot,
        )
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError(f"incomplete or invalid report: {error}") from error


def analyze_rows(rows, pilot=False):
    return validated_rows(rows, pilot)


def diagnose_rows(rows, pilot=False):
    rejections = []
    metadata, trials, _ = validated_rows(rows, pilot, rejections)
    return {"diagnostic": True, "accepted": not rejections, "rejections": rejections,
            "metadata": metadata, "trials": trials}


def validated_rows(rows, pilot, delivery_rejections=None):
    metadata = rows[0]
    schema = metadata["schema"]
    if type(schema) is not int or schema not in (2, 3) or metadata["funded_directions"] != 2:
        raise ValueError("unsupported experiment schema or funding setup")
    if type(pilot) is not bool:
        raise ValueError("pilot validation mode must be explicit")
    if pilot:
        if schema != 3 or metadata.get("pilot") is not True:
            raise ValueError("pilot validation requires a schema-3 pilot report")
    elif metadata.get("pilot", False) is not False:
        raise ValueError("pilot report cannot establish a complete comparison")
    expected_trials = 1 if pilot else 8
    policy_order = POLICIES
    if pilot:
        delay = metadata.get("pilot_delay_ms", 250)
        if type(delay) is not int or delay not in POLICIES:
            raise ValueError("unsupported pilot policy")
        policy_order = (delay,)
    elif metadata.get("pilot_delay_ms") is not None:
        raise ValueError("pilot policy cannot alter a full comparison")
    native_counters = metadata.get("native_counters", False)
    if type(native_counters) is not bool or (native_counters and schema != 3):
        raise ValueError("native counters require explicit hardware metadata")
    service_carrier = metadata.get("payment_service_carrier", False)
    if type(service_carrier) is not bool:
        raise ValueError("payment carrier counters require explicit boolean metadata")
    log_filter = metadata.get("dataplane_drop_log_filter")
    if log_filter is not None and (schema != 3 or not isinstance(log_filter, str)
                                   or not 1 <= len(log_filter) <= 256):
        raise ValueError("drop log observations require an explicit bounded hardware filter")
    if metadata["optimized"] is not True:
        raise ValueError("cadence comparison requires an optimized build")
    fixed = {"nodes": 5, "paid_relays": 3, "repeats": 2, "unpaid_percent": 50,
             "window_msat": 4000, "grace_msat": 8000,
             "channel_capacity_sat": 256, "fee_msat_per_kib": 1,
             "transport": "UDP loopback"}
    if schema == 3:
        fixed.update(
            nodes=3, paid_relays=1, active_channels=2, channel_capacity_sat=32,
            billing="forwarding_data", quote_max_units=16777216,
            transport="native Ethernet over 802.11s", one_way_latency=False,
            common_tail_ms=3000,
        )
        if json.dumps(metadata.get("workload_schedule"), sort_keys=True) != json.dumps(
                HARDWARE_SCHEDULE, sort_keys=True):
            raise ValueError("fixed hardware workload schedule changed")
    if any(metadata.get(key) != value or type(metadata.get(key)) is not type(value)
           for key, value in fixed.items()):
        raise ValueError("fixed experiment configuration changed")
    records = [r for r in rows[1:] if "data" in r]
    accounting_rows = [r for r in rows[1:] if "conserved" in r]
    conserved = {r["trial"]: r for r in accounting_rows}
    if (len(records) != 4 * expected_trials or len(accounting_rows) != expected_trials
            or set(conserved) != set(range(expected_trials))):
        raise ValueError("incomplete matrix or missing financial conservation evidence")
    if schema == 3 and (
            [r["trial"] for r in records] != [trial for trial in range(expected_trials) for _ in range(4)]
            or [r["trial"] for r in accounting_rows] != list(range(expected_trials))):
        raise ValueError("hardware trial sequence changed")
    grouped = defaultdict(list)
    trials = []
    issued, channels = (384, 2) if schema == 3 else (5120, 6)
    for trial_id, delay in enumerate(policy_order[:expected_trials]):
        accounting = conserved[trial_id]
        if (accounting["conserved"] is not True or accounting["max_delay_ms"] != delay
                or unsigned(accounting["collected_sat"]) != issued
                or unsigned(accounting["issued_sat"]) != issued
                or unsigned(accounting["settled_channels"]) != channels):
            raise ValueError("invalid trial conservation")
        trial_records = [r for r in records if r["trial"] == trial_id]
        if [r["data"]["workload"] for r in trial_records] != ["idle", "bursty", "steady", "high_rate"]:
            raise ValueError("unmatched workload sequence")
        previous = None
        for row in trial_records:
            if row["max_delay_ms"] != delay:
                raise ValueError("unmatched policy order")
            result = summarize(row, schema, delivery_rejections)
            record_service_carrier(row["data"], result, previous, service_carrier,
                                   native_ethernet=schema == 3)
            if previous is not None:
                validate_gap(previous, row["data"]["before_guard"], schema)
            if schema == 3:
                record_vmhwm(row["data"], result, previous)
                record_native_counters(row["data"], result, previous, native_counters, log_filter)
            previous = row["data"]["after_guard"]
            trials.append({"trial":trial_id, "max_delay_ms":delay, "workload":row["data"]["workload"], **result})
            grouped[(row["data"]["workload"], delay)].append(result)
    return metadata, trials, grouped


def markdown(metadata, grouped):
    if metadata.get("pilot") is True:
        raise ValueError("pilot output is not a policy comparison; use JSON")
    lines = ["# Cadence measurements", "", f"Optimized build: **{metadata['optimized']}**. Two opposite-order repetitions; five real service processes and three paid relays over loopback UDP.", "",
        "All costs below sum the five service processes. CPU is measured CPU time. Payment CPU covers synchronous signing, usage handling and balance update handling; it excludes scheduler, control-envelope serialization outside those spans, and transport CPU. Storage is logical relay journal I/O, excluding Cashu SQLite and physical writes. Record bytes exclude TCP/FIPS/carrier overhead. These are offered workloads, not maximum throughput.", "",
        "| Workload | Limit ms | Delivered / submitted | Payment CPU ms | All CPU ms | Updates | Payment records KiB | Payment journal writes | Mean delay ms |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for workload in ("idle", "bursty", "steady", "high_rate"):
        for delay in (250, 500, 1000, 2000):
            values = grouped[(workload, delay)]
            avg = lambda k: mean(v.get(k, 0) for v in values)
            latency = f"{avg('mean_latency_us') / 1000:.3f}" if all(v["mean_latency_us"] is not None for v in values) else "—"
            lines.append(f"| {workload} | {delay} | {int(sum(v['delivered_packets'] for v in values))} / {int(sum(v['submitted_packets'] for v in values))} | {avg('payment_cpu_ms'):.2f} | {avg('process_cpu_ms'):.2f} | {avg('updates'):.1f} | {avg('payment_record_bytes') / 1024:.2f} | {avg('payment_journal_writes'):.1f} | {latency} |")
    if metadata.get("payment_service_carrier", False):
        lines += ["", "Local payment-service carrier bytes include submitted TCP/FIPS segments, "
                  "acknowledgments and retransmissions. JSON retains per-node/transport workload "
                  "deltas and separate guard-gap deltas. Ethernet's three-byte prefix is separate. "
                  "These counts exclude opaque transit, shared handshakes/MMP/rekeys, kernel "
                  "encapsulation/retries and radio airtime; they are not physical wire bytes. "
                  "Idle transport activity remains visible even without another payment."]
    if metadata["schema"] == 3:
        lines[2] = (
            "Optimized build: **True**. Two opposite-order repetitions; three real "
            "router service processes and one paid relay over native Ethernet over 802.11s."
        )
        lines[4] = (
            "Costs sum the three service processes. Payment CPU covers only the existing "
            "synchronous spans; relay journal I/O is logical and excludes SDK/SQLite writes. "
            "OS process I/O, when available, is separate and is not payment-attributed. "
            "Unavailable I/O and incomplete aggregate I/O remain null, not zero. "
            "RSS and kernel-reported VmHWM are sampled at each boundary; raw VmHWM decreases "
            "are retained. Record bytes exclude TCP/FIPS/carrier overhead and radio airtime. "
            "One-way latency is unmeasured because router clocks are independent. "
            "Radio idle payment activity inside the measured window is reported."
        )
        lines += [
            "", "Per-trial JSON retains total and per-node CPU seconds/MiB, goodput, "
            "RSS, raw VmHWM samples and decreases, OS I/O deltas, payment spans/records, "
            "and logical journal commits/syncs. Per-node CPU uses the same end-to-end "
            "delivered application bytes as the total; zero-delivery ratios are null. "
            "Maximum observed VmHWM is not a proven window or lifetime peak; summed "
            "end-sample readings need not be simultaneous. "
            "Idle lasts four seconds; all eight bursts include their final 800 ms sleep. "
            "High rate offers 8,000 packets. All windows include the same three-second tail. "
            "These offered workloads do not establish maximum throughput or an optimal policy.",
        ]
        return "\n".join(lines) + "\n"
    lines += ["", "Delivery totals combine both repetitions; other values are arithmetic means per observation window. Idle includes 4 seconds plus the common 3-second tail. Other windows include traffic, a bounded receive drain and the same tail. Raw trial summaries retain loss, CPU/GiB, timing quality and aggregate link counters. Impaired links, complete payment wire attribution and physical device performance remain separate work."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--pilot", action="store_true",
                        help="validate only an explicitly marked schema-3 pilot trial")
    parser.add_argument("--diagnostics", action="store_true",
                        help="emit measured costs for valid delivery-loss evidence; rejection still exits nonzero")
    args = parser.parse_args()
    if args.diagnostics:
        if args.markdown:
            parser.error("diagnostics require JSON, not a comparison table")
        result = diagnose(args.report, pilot=args.pilot)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["accepted"] else 1)
    else:
        metadata, trials, grouped = analyze(args.report, pilot=args.pilot)
        print(markdown(metadata, grouped) if args.markdown else json.dumps({"metadata":metadata, "trials":trials}, indent=2))
