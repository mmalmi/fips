#!/usr/bin/env python3
"""Analyze the isolated multi-peer forwarding fairness experiment."""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path


PING_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(0, math.ceil((pct / 100) * len(ordered)) - 1)
    return ordered[rank]


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
        "loss_percent": (
            100 * (transmitted - received) / transmitted if transmitted else None
        ),
        "latency_ms": {
            "min": min(samples) if samples else None,
            "avg": sum(samples) / len(samples) if samples else None,
            "p50": percentile(samples, 50),
            "p95": percentile(samples, 95),
            "p99": percentile(samples, 99),
            "max": max(samples) if samples else None,
        },
    }


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def iperf_summary(path: Path) -> dict:
    data = read_json(path)
    end = data.get("end", {})
    received = end.get("sum_received") or end.get("sum") or {}
    sent = end.get("sum_sent") or {}
    return {
        "throughput_mbps": received.get("bits_per_second", 0) / 1_000_000,
        "delivered_bytes": received.get("bytes", 0),
        "seconds": received.get("seconds"),
        "loss_percent": received.get("lost_percent"),
        "retransmits": sent.get("retransmits"),
        "error": data.get("error"),
    }


def forwarding_packets(path: Path) -> int | None:
    data = read_json(path)
    forwarding = data.get("forwarding", data.get("data", {}).get("forwarding", {}))
    value = forwarding.get("forwarded_packets")
    return int(value) if value is not None else None


def connected_peers(path: Path) -> int:
    return sum(
        peer.get("connectivity") == "connected"
        for peer in read_json(path).get("peers", [])
    )


def evaluate_gates(summary: dict, requirements: dict) -> dict[str, bool]:
    d_flow = summary["d_small_flow"]
    d_ping = summary["d_loaded_ping"]
    before = summary["connected_peers_before"]
    after = summary["connected_peers_after"]
    forwarded = summary["b_forwarded_packets_delta"]
    expected_peers = {"a": 1, "b": 3, "c": 1, "d": 1}
    return {
        "a_saturated_flow_progress": summary["a_tcp8"]["throughput_mbps"] > 0,
        "d_small_flow_progress": (
            d_flow["throughput_mbps"] >= requirements["d_min_throughput_mbps"]
        ),
        "d_small_flow_loss_bounded": (
            d_flow["loss_percent"] is not None
            and d_flow["loss_percent"] <= requirements["d_max_loss_percent"]
        ),
        "d_loaded_ping_progress": (
            d_ping["received"] >= requirements["d_min_ping_replies"]
            and d_ping["loss_percent"] is not None
            and d_ping["loss_percent"] <= requirements["d_max_ping_loss_percent"]
        ),
        "b_forwarded_both_flows": forwarded is not None and forwarded > 0,
        "peer_liveness_established": before == expected_peers,
        # This is also the control/liveness priority assertion: all three B
        # links and every leaf session must remain connected after saturation.
        "peer_liveness_preserved": after == expected_peers,
    }


def fmt(value: float | None, digits: int = 3) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()
    root = args.result_dir
    manifest = read_json(root / "manifest.json")
    before = forwarding_packets(root / "forwarding-before.json")
    after = forwarding_packets(root / "forwarding-after.json")
    a_tcp8 = iperf_summary(root / "a-tcp8.iperf.json")
    d_small = iperf_summary(root / "d-small.iperf.json")
    cpu_seconds = float((root / "b.cpu-seconds").read_text().strip())
    delivered_gbit = (
        (a_tcp8["delivered_bytes"] + d_small["delivered_bytes"]) * 8 / 1_000_000_000
    )
    summary = {
        "metadata": manifest.get("metadata", {}),
        "d_offered_rate": manifest.get("d_offered_rate"),
        "a_tcp8": a_tcp8,
        "d_small_flow": d_small,
        "d_idle_ping": ping_summary(root / "d-idle.ping"),
        "d_loaded_ping": ping_summary(root / "d-loaded.ping"),
        "b_cpu_seconds": cpu_seconds,
        "b_cpu_seconds_per_gbit": (
            cpu_seconds / delivered_gbit if delivered_gbit else None
        ),
        "b_forwarded_packets_delta": (
            after - before if before is not None and after is not None else None
        ),
        "connected_peers_before": {
            node: connected_peers(root / f"peers-before-{node}.json")
            for node in "abcd"
        },
        "connected_peers_after": {
            node: connected_peers(root / f"peers-after-{node}.json")
            for node in "abcd"
        },
    }
    summary["gates"] = evaluate_gates(summary, manifest["gates"])
    summary["passed"] = all(summary["gates"].values())
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    idle = summary["d_idle_ping"]
    loaded = summary["d_loaded_ping"]
    idle_latency = idle["latency_ms"]
    loaded_latency = loaded["latency_ms"]
    lines = [
        "# FIPS multi-peer forwarding fairness benchmark",
        "",
        f"Result: `{'PASS' if summary['passed'] else 'FAIL'}`",
        "",
        "| traffic | throughput Mbps | loss % | latency avg/p95/p99 ms |",
        "|---|---:|---:|---:|",
        f"| A→C TCP8 saturation | {fmt(a_tcp8['throughput_mbps'])} | — | — |",
        f"| D→C small UDP | {fmt(d_small['throughput_mbps'])} | "
        f"{fmt(d_small['loss_percent'])} | — |",
        f"| D→C idle ping | — | {fmt(idle['loss_percent'])} | "
        f"{fmt(idle_latency['avg'])}/{fmt(idle_latency['p95'])}/{fmt(idle_latency['p99'])} |",
        f"| D→C ping under A load | — | {fmt(loaded['loss_percent'])} | "
        f"{fmt(loaded_latency['avg'])}/{fmt(loaded_latency['p95'])}/{fmt(loaded_latency['p99'])} |",
        "",
        f"B CPU: `{fmt(cpu_seconds)} s`, `{fmt(summary['b_cpu_seconds_per_gbit'])} CPU-sec/Gbit`; "
        f"forwarded delta: `{summary['b_forwarded_packets_delta']}`.",
        "",
        f"Connected peers before/after: `{summary['connected_peers_before']}` / "
        f"`{summary['connected_peers_after']}`.",
        "",
        "Gates:",
        "",
    ]
    lines.extend(
        f"- [{'x' if passed else ' '}] {name}" for name, passed in summary["gates"].items()
    )
    (root / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
