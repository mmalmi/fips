#!/usr/bin/env python3
"""Collect a victim snapshot from inside the victim container."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path


PID = "1"


def run(cmd: list[str], timeout: float = 5.0) -> dict:
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "elapsed_secs": time.time() - started,
        }
    except Exception as exc:  # noqa: BLE001 - this is a diagnostic snapshot.
        return {"ok": False, "error": str(exc), "elapsed_secs": time.time() - started}


def fipsctl(*args: str) -> dict:
    proc = run(["fipsctl", *args])
    if not proc.get("ok"):
        return {"ok": False, "error": proc.get("stderr") or proc.get("error") or "fipsctl failed"}
    try:
        return {"ok": True, "data": json.loads(proc["stdout"])}
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"invalid JSON: {exc}", "stdout": proc.get("stdout", "")[:1000]}


def proc_status() -> dict:
    fields: dict[str, str | int] = {}
    for line in Path(f"/proc/{PID}/status").read_text().splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        raw = raw.strip()
        if raw.endswith(" kB"):
            fields[f"{key}_kb"] = int(raw[:-3].strip())
        else:
            fields[key] = raw
    return fields


def proc_stat() -> dict:
    text = Path(f"/proc/{PID}/stat").read_text()
    after = text.rsplit(")", 1)[1].strip().split()
    clk = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    # after[0] is state; original stat fields 14/15 become indexes 11/12 here.
    utime = int(after[11])
    stime = int(after[12])
    return {
        "utime_ticks": utime,
        "stime_ticks": stime,
        "cpu_secs": (utime + stime) / clk,
    }


def fd_count() -> int:
    return len(list(Path(f"/proc/{PID}/fd").iterdir()))


def parse_proc_net(path: str) -> dict:
    result: dict[str, dict[str, int]] = {}
    lines = Path(path).read_text().splitlines()
    i = 0
    while i + 1 < len(lines):
        if ":" not in lines[i] or ":" not in lines[i + 1]:
            i += 1
            continue
        name_a, keys_raw = lines[i].split(":", 1)
        name_b, vals_raw = lines[i + 1].split(":", 1)
        if name_a != name_b:
            i += 1
            continue
        keys = keys_raw.split()
        vals = vals_raw.split()
        if len(keys) == len(vals):
            result[name_a] = {k: int(v) for k, v in zip(keys, vals)}
        i += 2
    return result


def ss_counts() -> dict:
    proc = run(["ss", "-Htan"], timeout=2.0)
    tcp = {"total_8443": 0, "estab_8443": 0, "listen_8443": 0, "syn_recv_8443": 0}
    if proc.get("ok"):
        for line in proc["stdout"].splitlines():
            if ":8443" not in line:
                continue
            parts = line.split()
            if not parts:
                continue
            state = parts[0].lower()
            tcp["total_8443"] += 1
            if state == "estab":
                tcp["estab_8443"] += 1
            elif state == "listen":
                tcp["listen_8443"] += 1
            elif state == "syn-recv":
                tcp["syn_recv_8443"] += 1

    proc = run(["ss", "-Huan"], timeout=2.0)
    udp_2121 = 0
    if proc.get("ok"):
        udp_2121 = sum(1 for line in proc["stdout"].splitlines() if ":2121" in line)
    return {"tcp": tcp, "udp_2121_sockets": udp_2121}


def main() -> None:
    snapshot = {
        "timestamp": time.time(),
        "proc_status": proc_status(),
        "proc_stat": proc_stat(),
        "fd_count": fd_count(),
        "net_snmp": parse_proc_net("/proc/net/snmp"),
        "net_netstat": parse_proc_net("/proc/net/netstat"),
        "ss": ss_counts(),
        "fips": {
            "status": fipsctl("show", "status"),
            "transports": fipsctl("show", "transports"),
            "connections": fipsctl("show", "connections"),
            "routing": fipsctl("show", "routing"),
            "tree": fipsctl("show", "tree"),
            "bloom": fipsctl("show", "bloom"),
        },
    }
    print(json.dumps(snapshot, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
