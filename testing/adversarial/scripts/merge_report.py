#!/usr/bin/env python3
"""Merge adversarial phase reports and victim snapshots into one report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PHASES = [
    "udp-random",
    "udp-msg1",
    "udp-established",
    "udp-spoofed",
    "tcp-malformed",
    "tcp-slowloris",
]


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text())


def dig(obj: Any, *path: str, default: Any = None) -> Any:
    cur = obj
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def fips_data(snapshot: dict, query: str) -> dict:
    return dig(snapshot, "fips", query, "data", default={}) or {}


def proc_value(snapshot: dict, key: str, default: int = 0) -> int:
    value = dig(snapshot, "proc_status", key, default=default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def transport_stats(snapshot: dict, transport_type: str) -> dict:
    out: dict[str, int | float] = {}
    transports = fips_data(snapshot, "transports").get("transports", [])
    for item in transports:
        if item.get("type") != transport_type:
            continue
        stats = item.get("stats", {})
        for key, value in stats.items():
            if isinstance(value, (int, float)):
                out[key] = out.get(key, 0) + value
    return out


def delta(after: dict, before: dict, key: str) -> int | float:
    return after.get(key, 0) - before.get(key, 0)


def phase_row(results: Path, phase: str) -> dict:
    before = load_json(results / "snapshots" / f"before-{phase}.json") or {}
    after = load_json(results / "snapshots" / f"after-{phase}.json") or {}
    during = load_json(results / "snapshots" / f"during-{phase}.json")
    traffic = load_json(results / "phases" / f"{phase}.json") or {}

    udp_before = transport_stats(before, "udp")
    udp_after = transport_stats(after, "udp")
    tcp_before = transport_stats(before, "tcp")
    tcp_after = transport_stats(after, "tcp")
    status_after = fips_data(after, "status")

    row = {
        "phase": phase,
        "traffic": traffic,
        "victim": {
            "rss_kb_before": proc_value(before, "VmRSS_kb"),
            "rss_kb_after": proc_value(after, "VmRSS_kb"),
            "hwm_kb_after": proc_value(after, "VmHWM_kb"),
            "fds_before": dig(before, "fd_count", default=0),
            "fds_after": dig(after, "fd_count", default=0),
            "threads_after": proc_value(after, "Threads"),
            "peer_count_after": status_after.get("peer_count"),
            "connection_count_after": status_after.get("connection_count"),
            "udp_stats_delta": {
                key: delta(udp_after, udp_before, key)
                for key in sorted(set(udp_before) | set(udp_after))
                if delta(udp_after, udp_before, key)
            },
            "tcp_stats_delta": {
                key: delta(tcp_after, tcp_before, key)
                for key in sorted(set(tcp_before) | set(tcp_after))
                if delta(tcp_after, tcp_before, key)
            },
        },
    }
    if during:
        status_during = fips_data(during, "status")
        row["victim"]["during"] = {
            "rss_kb": proc_value(during, "VmRSS_kb"),
            "hwm_kb": proc_value(during, "VmHWM_kb"),
            "fds": dig(during, "fd_count", default=0),
            "threads": proc_value(during, "Threads"),
            "peer_count": status_during.get("peer_count"),
            "connection_count": status_during.get("connection_count"),
            "ss": dig(during, "ss", default={}),
        }
    return row


def fmt_int(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def fmt_float(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return f"{float(value):,.1f}"
    except (TypeError, ValueError):
        return str(value)


def summary_markdown(report: dict) -> str:
    lines = [
        "# FIPS Adversarial Ingress Report",
        "",
        "## Phase Summary",
        "",
        "| Phase | Sent/opened | Errors | Rate/sec | RSS delta | HWM | FDs after | Conns after | UDP delta | TCP delta |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for row in report["phases"]:
        traffic = row["traffic"]
        victim = row["victim"]
        sent = (
            traffic.get("sent")
            or traffic.get("connected_and_sent")
            or traffic.get("opened")
            or traffic.get("closed")
            or 0
        )
        errors = (
            traffic.get("send_errors")
            or traffic.get("connect_or_send_errors")
            or traffic.get("errors")
            or 0
        )
        rate = traffic.get("pps") or traffic.get("connections_per_sec")
        rss_delta = victim["rss_kb_after"] - victim["rss_kb_before"]
        udp_delta = victim.get("udp_stats_delta", {})
        tcp_delta = victim.get("tcp_stats_delta", {})
        udp_text = ", ".join(f"{k}+{fmt_int(v)}" for k, v in udp_delta.items()) or "-"
        tcp_text = ", ".join(f"{k}+{fmt_int(v)}" for k, v in tcp_delta.items()) or "-"
        lines.append(
            "| {phase} | {sent} | {errors} | {rate} | {rss_delta} KiB | {hwm} KiB | {fds} | {conns} | {udp} | {tcp} |".format(
                phase=row["phase"],
                sent=fmt_int(sent),
                errors=fmt_int(errors),
                rate=fmt_float(rate),
                rss_delta=fmt_int(rss_delta),
                hwm=fmt_int(victim["hwm_kb_after"]),
                fds=fmt_int(victim["fds_after"]),
                conns=fmt_int(victim["connection_count_after"]),
                udp=udp_text,
                tcp=tcp_text,
            )
        )

    lines.extend(["", "## Slowloris During-Hold Snapshot", ""])
    slow = next((row for row in report["phases"] if row["phase"] == "tcp-slowloris"), None)
    during = dig(slow or {}, "victim", "during", default=None)
    if during:
        lines.extend(
            [
                f"- RSS: {fmt_int(during.get('rss_kb'))} KiB",
                f"- HWM: {fmt_int(during.get('hwm_kb'))} KiB",
                f"- FDs: {fmt_int(during.get('fds'))}",
                f"- Threads: {fmt_int(during.get('threads'))}",
                f"- FIPS connection_count: {fmt_int(during.get('connection_count'))}",
                f"- TCP :8443 sockets: {json.dumps(during.get('ss', {}).get('tcp', {}), sort_keys=True)}",
            ]
        )
    else:
        lines.append("- No during-hold snapshot captured.")

    lines.extend(["", "## Safety", ""])
    for item in report.get("safety", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--safety", action="append", default=[])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    results = Path(args.results)
    report = {
        "phases": [phase_row(results, phase) for phase in PHASES],
        "safety": args.safety,
    }
    (results / "latest.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    summary = summary_markdown(report)
    (results / "summary.md").write_text(summary)
    print(summary)


if __name__ == "__main__":
    main()
