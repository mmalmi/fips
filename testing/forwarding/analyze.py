#!/usr/bin/env python3
"""Summarize forwarding benchmark raw artifacts into JSON and Markdown."""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path


PING_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")
RATE_RE = re.compile(r"\b([a-z0-9_]+)=([0-9.]+)/s\b")


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    rank = max(0, math.ceil((pct / 100) * len(values)) - 1)
    return values[rank]


def ping_summary(path: Path) -> dict:
    text = path.read_text(errors="replace") if path.exists() else ""
    samples = [float(match.group(1)) for match in PING_RE.finditer(text)]
    transmitted_match = re.search(r"(\d+) packets transmitted", text)
    received_match = re.search(r"(\d+) received", text)
    transmitted = int(transmitted_match.group(1)) if transmitted_match else len(samples)
    received = int(received_match.group(1)) if received_match else len(samples)
    return {
        "transmitted": transmitted,
        "received": received,
        "loss_percent": (100 * (transmitted - received) / transmitted) if transmitted else None,
        "latency_ms": {
            "min": min(samples) if samples else None,
            "avg": (sum(samples) / len(samples)) if samples else None,
            "p50": percentile(samples, 50),
            "p95": percentile(samples, 95),
            "p99": percentile(samples, 99),
            "max": max(samples) if samples else None,
        },
    }


def perf_summary(path: Path) -> dict:
    totals: dict[str, float] = {}
    intervals = 0
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if not line.startswith("[pipe "):
                continue
            intervals += 1
            for name, rate in RATE_RE.findall(line):
                totals[name] = totals.get(name, 0.0) + float(rate)

    def ratio(packet_event: str, batch_event: str) -> float | None:
        batches = totals.get(batch_event, 0)
        return totals.get(packet_event, 0) / batches if batches else None

    return {
        "intervals": intervals,
        "packets_per_batch": {
            "crypto_open": ratio("dataplane_crypto_open_packets", "dataplane_crypto_open_batch"),
            "crypto_seal": ratio("dataplane_crypto_seal_packets", "dataplane_crypto_seal_batch"),
            "live_output": ratio(
                "dataplane_live_output_batch_packets", "dataplane_live_output_batch"
            ),
            "udp_sendmmsg": ratio("udp_send_sendmmsg_packets", "udp_send_sendmmsg_batch"),
        },
        "seal_allocations_per_packet": (
            totals.get("dataplane_seal_allocated", 0)
            / totals.get("dataplane_crypto_seal_packets", 1)
            if totals.get("dataplane_crypto_seal_packets", 0)
            else None
        ),
    }


def forwarding_packets(path: Path) -> int | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    forwarding = data.get("forwarding", data.get("data", {}).get("forwarding", {}))
    value = forwarding.get("forwarded_packets")
    return int(value) if value is not None else None


def iperf_summary(path: Path) -> dict:
    data = json.loads(path.read_text())
    end = data.get("end", {})
    received = end.get("sum_received", {})
    sent = end.get("sum_sent", {})
    # UDP iperf JSON commonly reports receiver results in sum, not
    # sum_received. Prefer the receiver-side object whenever present.
    if not received:
        received = end.get("sum", {})
    return {
        "throughput_mbps": received.get("bits_per_second", 0) / 1_000_000,
        "delivered_bytes": received.get("bytes", 0),
        "seconds": received.get("seconds"),
        "loss_percent": received.get("lost_percent"),
        "jitter_ms": received.get("jitter_ms"),
        "retransmits": sent.get("retransmits"),
    }


def fmt(value: float | None, digits: int = 3) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()
    root = args.result_dir
    manifest = json.loads((root / "cases.json").read_text())
    before = forwarding_packets(root / "forwarding-before.json")
    after = forwarding_packets(root / "forwarding-after.json")
    summary = {
        "metadata": manifest["metadata"],
        "idle": ping_summary(root / "idle.ping"),
        "b_forwarded_packets_delta": (
            after - before if before is not None and after is not None else None
        ),
        "cases": [],
    }
    for case in manifest["cases"]:
        name = case["name"]
        iperf = iperf_summary(root / f"{name}.iperf.json")
        cpu_seconds = float((root / f"{name}.cpu-seconds").read_text().strip())
        delivered_gbit = iperf["delivered_bytes"] * 8 / 1_000_000_000
        summary["cases"].append(
            {
                **case,
                **iperf,
                "latency": ping_summary(root / f"{name}.ping"),
                "b_cpu_seconds": cpu_seconds,
                "b_cpu_seconds_per_gbit": cpu_seconds / delivered_gbit if delivered_gbit else None,
                "b_perf": perf_summary(root / f"{name}.pipe.log"),
            }
        )

    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    idle = summary["idle"]
    lines = [
        "# FIPS A–B–C forwarding benchmark",
        "",
        f"B forwarded-packet delta: `{summary['b_forwarded_packets_delta']}`",
        "",
        "| case | throughput Mbps | loss % | ping avg/p95/p99 ms | B CPU-sec/Gbit | seal/output/send batch |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for case in summary["cases"]:
        latency = case["latency"]["latency_ms"]
        batch = case["b_perf"]["packets_per_batch"]
        lines.append(
            f"| {case['name']} | {fmt(case['throughput_mbps'])} | {fmt(case['loss_percent'])} "
            f"| {fmt(latency['avg'])}/{fmt(latency['p95'])}/{fmt(latency['p99'])} "
            f"| {fmt(case['b_cpu_seconds_per_gbit'])} "
            f"| {fmt(batch['crypto_seal'], 2)}/{fmt(batch['live_output'], 2)}/{fmt(batch['udp_sendmmsg'], 2)} |"
        )
    idle_latency = idle["latency_ms"]
    lines.extend(
        [
            "",
            f"Idle ping: loss `{fmt(idle['loss_percent'])}%`, "
            f"avg/p95/p99 `{fmt(idle_latency['avg'])}/{fmt(idle_latency['p95'])}/{fmt(idle_latency['p99'])} ms`.",
            "",
            "The final column is packets per batch at B. Values near 1 expose batching collapse.",
        ]
    )
    (root / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
