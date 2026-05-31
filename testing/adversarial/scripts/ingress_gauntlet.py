#!/usr/bin/env python3
"""Packet generators for the adversarial ingress harness.

This script is run inside the attacker container. It intentionally avoids
external dependencies so the unified FIPS test image can run it as-is.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import time
from pathlib import Path


MSG1_PAYLOAD_LEN = 110
MSG1_WIRE_SIZE = 114


def now() -> float:
    return time.time()


def run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def route_iface(target: str) -> str:
    out = run(["ip", "route", "get", target], check=True).stdout.split()
    if "dev" in out:
        return out[out.index("dev") + 1]
    return "eth0"


def source_ips(target: str, count: int, start: int) -> list[str]:
    addr = ipaddress.ip_address(target)
    if addr.version != 4:
        raise ValueError("this harness currently expects an IPv4 Docker bridge target")
    parts = target.split(".")
    prefix = ".".join(parts[:3])
    return [f"{prefix}.{start + i}" for i in range(count)]


def ensure_aliases(iface: str, ips: list[str]) -> dict:
    added = 0
    existed = 0
    errors: list[dict] = []
    for ip in ips:
        proc = run(["ip", "addr", "add", f"{ip}/24", "dev", iface])
        if proc.returncode == 0:
            added += 1
        elif "File exists" in proc.stderr:
            existed += 1
        else:
            errors.append({"ip": ip, "stderr": proc.stderr.strip(), "returncode": proc.returncode})
    return {"iface": iface, "requested": len(ips), "added": added, "existed": existed, "errors": errors}


def msg1_payload(rng: random.Random, sender_idx: int) -> bytes:
    buf = bytearray(MSG1_WIRE_SIZE)
    buf[0] = 0x01
    buf[1] = 0x00
    buf[2:4] = struct.pack("<H", MSG1_PAYLOAD_LEN)
    buf[4:8] = struct.pack("<I", sender_idx & 0xFFFFFFFF)
    for i in range(8, MSG1_WIRE_SIZE):
        buf[i] = rng.randrange(0, 256)
    return bytes(buf)


def established_payload(rng: random.Random, counter: int, inner_len: int = 32) -> bytes:
    # [prefix:4][receiver_idx:4][counter:8][ciphertext:inner_len][fake_tag:16]
    buf = bytearray(16 + inner_len + 16)
    buf[0] = 0x00
    buf[1] = 0x00
    buf[2:4] = struct.pack("<H", inner_len)
    buf[4:8] = struct.pack("<I", rng.randrange(1, 0xFFFFFFFF))
    buf[8:16] = struct.pack("<Q", counter & 0xFFFFFFFFFFFFFFFF)
    for i in range(16, len(buf)):
        buf[i] = rng.randrange(0, 256)
    return bytes(buf)


def random_payload(rng: random.Random, size: int) -> bytes:
    return bytes(rng.randrange(0, 256) for _ in range(size))


def make_udp_sockets(ips: list[str]) -> tuple[list[socket.socket], list[dict]]:
    sockets: list[socket.socket] = []
    errors: list[dict] = []
    for ip in ips:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((ip, 0))
            sockets.append(s)
        except OSError as exc:
            errors.append({"source": ip, "errno": exc.errno, "error": str(exc)})
            s.close()
    return sockets, errors


def udp_phase(args: argparse.Namespace, kind: str) -> dict:
    rng = random.Random(args.seed)
    iface = route_iface(args.target)
    ips = source_ips(args.target, args.sources, args.source_start)
    aliases = ensure_aliases(iface, ips)
    sockets, bind_errors = make_udp_sockets(ips)
    target = (args.target, args.udp_port)

    sent = 0
    send_errors = 0
    bytes_sent = 0
    started = now()
    for i in range(args.udp_packets):
        if not sockets:
            break
        if kind == "udp-random":
            payload = random_payload(rng, args.payload_size)
        elif kind == "udp-msg1":
            payload = msg1_payload(rng, i + 1)
        elif kind == "udp-established":
            payload = established_payload(rng, i + 1)
        else:
            raise ValueError(f"unknown udp phase: {kind}")

        sock = sockets[i % len(sockets)]
        try:
            n = sock.sendto(payload, target)
            sent += 1
            bytes_sent += n
        except OSError:
            send_errors += 1
    elapsed = now() - started
    for sock in sockets:
        sock.close()

    return {
        "phase": kind,
        "target": f"{args.target}:{args.udp_port}",
        "iface": iface,
        "source_count": len(ips),
        "socket_count": len(sockets),
        "aliases": aliases,
        "bind_errors": bind_errors[:20],
        "attempted": args.udp_packets,
        "sent": sent,
        "send_errors": send_errors,
        "bytes_sent": bytes_sent,
        "elapsed_secs": elapsed,
        "pps": sent / elapsed if elapsed > 0 else 0.0,
        "bytes_per_sec": bytes_sent / elapsed if elapsed > 0 else 0.0,
    }


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    acc = 0
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) + data[i + 1]
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def raw_spoofed_phase(args: argparse.Namespace) -> dict:
    rng = random.Random(args.seed)
    iface = route_iface(args.target)
    started = now()
    sent = 0
    send_errors = 0
    bytes_sent = 0
    skipped = None
    ips = source_ips(args.target, args.sources, args.source_start)
    aliases = ensure_aliases(iface, ips)

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.bind((iface, socket.htons(0x0800)))
    except OSError as exc:
        return {
            "phase": "udp-spoofed",
            "skipped": True,
            "skip_reason": f"AF_PACKET raw socket unavailable: {exc}",
            "elapsed_secs": now() - started,
        }

    victim_mac = resolve_neighbor_mac(iface, args.target)
    if not victim_mac:
        sock.close()
        return {
            "phase": "udp-spoofed",
            "skipped": True,
            "skip_reason": f"could not resolve victim MAC for {args.target} on {iface}",
            "elapsed_secs": now() - started,
        }

    for i in range(args.udp_packets):
        src = ips[i % len(ips)]
        dst = args.target
        src_port = 20000 + (i % 30000)
        payload = msg1_payload(rng, i + 1) if i % 2 == 0 else random_payload(rng, args.payload_size)
        udp_len = 8 + len(payload)
        total_len = 20 + udp_len
        ident = rng.randrange(0, 0xFFFF)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total_len,
            ident,
            0,
            64,
            socket.IPPROTO_UDP,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
        ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
        udp_header = struct.pack("!HHHH", src_port, args.udp_port, udp_len, 0)
        frame = (
            mac_to_bytes(victim_mac)
            + spoofed_source_mac(i)
            + struct.pack("!H", 0x0800)
            + ip_header
            + udp_header
            + payload
        )
        try:
            sock.send(frame)
            sent += 1
            bytes_sent += len(frame)
        except OSError as exc:
            send_errors += 1
            if skipped is None and exc.errno in (errno.EPERM, errno.EACCES):
                skipped = str(exc)
                break
    sock.close()
    elapsed = now() - started
    result = {
        "phase": "udp-spoofed",
        "target": f"{args.target}:{args.udp_port}",
        "iface": iface,
        "method": "af_packet_ethernet",
        "victim_mac": victim_mac,
        "virtual_source_count": len(ips),
        "aliases": aliases,
        "attempted": args.udp_packets,
        "sent": sent,
        "send_errors": send_errors,
        "bytes_sent": bytes_sent,
        "elapsed_secs": elapsed,
        "pps": sent / elapsed if elapsed > 0 else 0.0,
        "bytes_per_sec": bytes_sent / elapsed if elapsed > 0 else 0.0,
    }
    if skipped:
        result["skipped"] = True
        result["skip_reason"] = skipped
    return result


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def spoofed_source_mac(i: int) -> bytes:
    # Locally administered unicast MACs: 02:fa:...
    return bytes([0x02, 0xFA, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF, 0x01])


def resolve_neighbor_mac(iface: str, target: str) -> str | None:
    run(["ping", "-c", "1", "-W", "1", target])
    proc = run(["ip", "neigh", "show", "to", target, "dev", iface])
    match = re.search(r"\blladdr\s+([0-9a-fA-F:]{17})\b", proc.stdout)
    if match:
        return match.group(1).lower()
    return None


def tcp_malformed_one(target: str, port: int, idx: int, timeout: float) -> tuple[int, int, str | None]:
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if idx % 3 == 0:
                sock.sendall(b"\x16\x03\x01\x00\x2e")  # TLS-ish, version nibble != 0.
            elif idx % 3 == 1:
                sock.sendall(b"\x05\x00\x00\x00")  # unknown FMP phase.
            else:
                sock.sendall(b"\x01\x00\x01\x00x")  # Msg1 phase with wrong length.
            return (1, 0, None)
    except OSError as exc:
        return (0, 1, str(exc))


def tcp_malformed_phase(args: argparse.Namespace) -> dict:
    started = now()
    sent = 0
    errors = 0
    samples: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = [
            pool.submit(tcp_malformed_one, args.target, args.tcp_port, i, args.tcp_timeout)
            for i in range(args.tcp_connections)
        ]
        for fut in concurrent.futures.as_completed(futs):
            ok, err, msg = fut.result()
            sent += ok
            errors += err
            if msg and len(samples) < 10:
                samples.append(msg)
    elapsed = now() - started
    return {
        "phase": "tcp-malformed",
        "target": f"{args.target}:{args.tcp_port}",
        "attempted": args.tcp_connections,
        "connected_and_sent": sent,
        "connect_or_send_errors": errors,
        "error_samples": samples,
        "elapsed_secs": elapsed,
        "connections_per_sec": sent / elapsed if elapsed > 0 else 0.0,
    }


def tcp_slowloris_phase(args: argparse.Namespace) -> dict:
    started = now()
    sockets: list[socket.socket] = []
    errors: list[str] = []
    for i in range(args.tcp_connections):
        try:
            sock = socket.create_connection((args.target, args.tcp_port), timeout=args.tcp_timeout)
            sock.settimeout(args.tcp_timeout)
            if args.slowloris_prefix_bytes > 0:
                sock.sendall(b"\x01"[: args.slowloris_prefix_bytes])
            sockets.append(sock)
        except OSError as exc:
            if len(errors) < 20:
                errors.append(str(exc))

    ready = {
        "phase": "tcp-slowloris",
        "opened": len(sockets),
        "errors": len(errors),
        "error_samples": errors,
        "hold_secs": args.hold_secs,
        "ready_at": now(),
    }
    if args.ready_file:
        Path(args.ready_file).write_text(json.dumps(ready, indent=2) + "\n")

    time.sleep(args.hold_secs)
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass
    elapsed = now() - started
    ready.update(
        {
            "target": f"{args.target}:{args.tcp_port}",
            "attempted": args.tcp_connections,
            "elapsed_secs": elapsed,
            "closed": len(sockets),
        }
    )
    return ready


def write_report(path: str | None, report: dict) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text)
    print(text, end="")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one adversarial ingress phase")
    parser.add_argument("--phase", required=True, choices=[
        "udp-random",
        "udp-msg1",
        "udp-established",
        "udp-spoofed",
        "tcp-malformed",
        "tcp-slowloris",
    ])
    parser.add_argument("--target", default="172.33.0.10")
    parser.add_argument("--udp-port", type=int, default=2121)
    parser.add_argument("--tcp-port", type=int, default=8443)
    parser.add_argument("--sources", type=int, default=64)
    parser.add_argument("--source-start", type=int, default=100)
    parser.add_argument("--udp-packets", type=int, default=20000)
    parser.add_argument("--payload-size", type=int, default=64)
    parser.add_argument("--tcp-connections", type=int, default=96)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--tcp-timeout", type=float, default=2.0)
    parser.add_argument("--hold-secs", type=float, default=8.0)
    parser.add_argument("--slowloris-prefix-bytes", type=int, default=1)
    parser.add_argument("--ready-file")
    parser.add_argument("--out")
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.phase in {"udp-random", "udp-msg1", "udp-established"}:
        report = udp_phase(args, args.phase)
    elif args.phase == "udp-spoofed":
        report = raw_spoofed_phase(args)
    elif args.phase == "tcp-malformed":
        report = tcp_malformed_phase(args)
    elif args.phase == "tcp-slowloris":
        report = tcp_slowloris_phase(args)
    else:
        raise AssertionError(args.phase)
    report["seed"] = args.seed
    report["ended_at"] = now()
    write_report(args.out, report)


if __name__ == "__main__":
    main()
