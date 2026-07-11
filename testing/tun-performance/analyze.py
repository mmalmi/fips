#!/usr/bin/env python3
"""Summarize raw direct system-TUN benchmark artifacts."""

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
    return values[max(0, math.ceil((pct / 100) * len(values)) - 1)]


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
            "avg": sum(samples) / len(samples) if samples else None,
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
                totals[name] = totals.get(name, 0) + float(rate)

    def ratio(packets: str, frames: str) -> float | None:
        frame_count = totals.get(frames, 0)
        return totals.get(packets, 0) / frame_count if frame_count else None

    return {
        "intervals": intervals,
        "tun_read_packets_per_frame": ratio("tun_read_packets", "tun_read_frames"),
        "tun_write_packets_per_frame": ratio("tun_write_packets", "tun_write_frames"),
        "tun_read_packets": totals.get("tun_read_packets"),
        "tun_read_frames": totals.get("tun_read_frames"),
        "tun_write_packets": totals.get("tun_write_packets"),
        "tun_write_frames": totals.get("tun_write_frames"),
    }


def iperf_summary(path: Path) -> dict:
    data = json.loads(path.read_text())
    end = data.get("end", {})
    received = end.get("sum_received", {}) or end.get("sum", {})
    sent = end.get("sum_sent", {})
    return {
        "throughput_mbps": received.get("bits_per_second", 0) / 1_000_000,
        "delivered_bytes": received.get("bytes", 0),
        "seconds": received.get("seconds"),
        "loss_percent": received.get("lost_percent"),
        "jitter_ms": received.get("jitter_ms"),
        "retransmits": sent.get("retransmits"),
    }


def forwarding_value(path: Path, key: str) -> int | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    forwarding = data.get("forwarding", data.get("data", {}).get("forwarding", {}))
    value = forwarding.get(key)
    return int(value) if value is not None else None


def counter_delta(root: Path, node: str, key: str) -> int | None:
    before = forwarding_value(root / f"{node}-before.json", key)
    after = forwarding_value(root / f"{node}-after.json", key)
    return after - before if before is not None and after is not None else None


def fmt(value: float | None, digits: int = 3) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()
    root = args.result_dir
    manifest = json.loads((root / "cases.json").read_text())
    summary = {
        "metadata": manifest["metadata"],
        "idle": ping_summary(root / "idle.ping"),
        "a_originated_packets_delta": counter_delta(root, "a", "originated_packets"),
        "b_delivered_packets_delta": counter_delta(root, "b", "delivered_packets"),
        "cases": [],
    }
    for case in manifest["cases"]:
        name = case["name"]
        iperf = iperf_summary(root / f"{name}.iperf.json")
        cpu_a = float((root / f"{name}.a.cpu-seconds").read_text().strip())
        cpu_b = float((root / f"{name}.b.cpu-seconds").read_text().strip())
        delivered_gbit = iperf["delivered_bytes"] * 8 / 1_000_000_000
        per_gbit = lambda value: value / delivered_gbit if delivered_gbit else None
        summary["cases"].append(
            {
                **case,
                **iperf,
                "latency": ping_summary(root / f"{name}.ping"),
                "cpu_seconds": {"a": cpu_a, "b": cpu_b, "combined": cpu_a + cpu_b},
                "cpu_seconds_per_gbit": {
                    "a": per_gbit(cpu_a),
                    "b": per_gbit(cpu_b),
                    "combined": per_gbit(cpu_a + cpu_b),
                },
                "perf": {
                    "a": perf_summary(root / f"{name}.a.pipe.log"),
                    "b": perf_summary(root / f"{name}.b.pipe.log"),
                },
            }
        )

    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = [
        "# FIPS direct system-TUN benchmark",
        "",
        f"FIPS counters: A originated `{summary['a_originated_packets_delta']}`, "
        f"B delivered `{summary['b_delivered_packets_delta']}` packets.",
        "",
        "| case | Mbps | loss % | ping avg/p95/p99 ms | CPU-sec/Gbit A/B/sum | A read pkt/frame | B write pkt/frame |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for case in summary["cases"]:
        latency = case["latency"]["latency_ms"]
        cpu = case["cpu_seconds_per_gbit"]
        a_read = case["perf"]["a"]["tun_read_packets_per_frame"]
        b_write = case["perf"]["b"]["tun_write_packets_per_frame"]
        lines.append(
            f"| {case['name']} | {fmt(case['throughput_mbps'])} | {fmt(case['loss_percent'])} "
            f"| {fmt(latency['avg'])}/{fmt(latency['p95'])}/{fmt(latency['p99'])} "
            f"| {fmt(cpu['a'])}/{fmt(cpu['b'])}/{fmt(cpu['combined'])} "
            f"| {fmt(a_read, 2)} | {fmt(b_write, 2)} |"
        )
    idle = summary["idle"]
    latency = idle["latency_ms"]
    lines.extend(
        [
            "",
            f"Idle ping: loss `{fmt(idle['loss_percent'])}%`, "
            f"avg/p95/p99 `{fmt(latency['avg'])}/{fmt(latency['p95'])}/{fmt(latency['p99'])} ms`.",
            "",
            "TUN packet/frame ratios appear only in an opt-in profiling run; values above 1 show VNET batching/offload.",
        ]
    )
    (root / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
