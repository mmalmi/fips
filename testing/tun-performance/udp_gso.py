#!/usr/bin/env python3
"""Linux UDP_SEGMENT sender and sequence-aware UDP receiver."""

from __future__ import annotations

import argparse
import errno
import json
import socket
import struct
import sys
import time


SOL_UDP = getattr(socket, "SOL_UDP", 17)
UDP_SEGMENT = 103
SEQUENCE_SIZE = 8


def parse_rate(value: str) -> float:
    units = {"": 1.0, "K": 1_000.0, "M": 1_000_000.0, "G": 1_000_000_000.0}
    value = value.strip().upper()
    suffix = value[-1] if value and value[-1] in units and not value[-1].isdigit() else ""
    number = value[:-1] if suffix else value
    rate = float(number) * units[suffix]
    if rate <= 0:
        raise ValueError("rate must be positive")
    return rate


def make_batch(first_sequence: int, segment_size: int, segments: int) -> bytes:
    if segment_size < SEQUENCE_SIZE:
        raise ValueError(f"segment size must be at least {SEQUENCE_SIZE}")
    tail = bytes(segment_size - SEQUENCE_SIZE)
    return b"".join(struct.pack("!Q", first_sequence + index) + tail for index in range(segments))


def sender(args: argparse.Namespace) -> int:
    rate_bps = parse_rate(args.rate)
    destination = socket.getaddrinfo(
        args.destination, args.port, socket.AF_INET6, socket.SOCK_DGRAM
    )[0][4]
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, args.socket_buffer)
    cmsg = [(SOL_UDP, UDP_SEGMENT, struct.pack("H", args.segment_size))]
    batch_bytes = args.segment_size * args.segments
    interval = batch_bytes * 8 / rate_bps
    sequence = 0
    syscalls = 0
    started = time.monotonic()
    deadline = started + args.duration
    next_send = started
    try:
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            if now < next_send:
                time.sleep(next_send - now)
                now = time.monotonic()
                if now >= deadline:
                    break
            payload = make_batch(sequence, args.segment_size, args.segments)
            sent = sock.sendmsg([payload], cmsg, 0, destination)
            if sent != len(payload):
                raise OSError(f"short UDP_SEGMENT send: {sent}/{len(payload)}")
            sequence += args.segments
            syscalls += 1
            next_send += interval
            if next_send < now - 0.1:
                next_send = now
    except OSError as error:
        unsupported = error.errno in {
            errno.EINVAL,
            errno.ENOPROTOOPT,
            errno.EOPNOTSUPP,
            errno.ENOSYS,
        }
        print(
            json.dumps(
                {
                    "udp_segment_supported": False if unsupported else None,
                    "error": str(error),
                    "errno": error.errno,
                    "sent_datagrams": sequence,
                    "send_syscalls": syscalls,
                }
            )
        )
        return 2 if unsupported else 1
    finally:
        sock.close()

    elapsed = time.monotonic() - started
    print(
        json.dumps(
            {
                "udp_segment_supported": True,
                "destination": destination[0],
                "elapsed_seconds": elapsed,
                "offered_rate_bps": rate_bps,
                "segment_size": args.segment_size,
                "segments_per_send": args.segments,
                "sent_datagrams": sequence,
                "sent_bytes": sequence * args.segment_size,
                "send_syscalls": syscalls,
                "datagrams_per_syscall": sequence / syscalls if syscalls else None,
            }
        )
    )
    return 0


def receiver(args: argparse.Namespace) -> int:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.socket_buffer)
    sock.bind(("::", args.port))
    sock.settimeout(0.1)
    deadline = time.monotonic() + args.duration
    first_at = None
    last_at = None
    first_sequence = None
    highest_sequence = -1
    out_of_order = 0
    malformed = 0
    datagrams = 0
    delivered_bytes = 0
    while time.monotonic() < deadline:
        try:
            payload, _address = sock.recvfrom(65535)
        except socket.timeout:
            if last_at is not None and time.monotonic() - last_at >= args.idle_timeout:
                break
            continue
        now = time.monotonic()
        first_at = now if first_at is None else first_at
        last_at = now
        datagrams += 1
        delivered_bytes += len(payload)
        if len(payload) < SEQUENCE_SIZE:
            malformed += 1
            continue
        sequence = struct.unpack_from("!Q", payload)[0]
        first_sequence = sequence if first_sequence is None else first_sequence
        if sequence <= highest_sequence:
            out_of_order += 1
        highest_sequence = max(highest_sequence, sequence)
    sock.close()
    active_seconds = (last_at - first_at) if first_at is not None and last_at is not None else 0
    print(
        json.dumps(
            {
                "received_datagrams": datagrams,
                "delivered_bytes": delivered_bytes,
                "first_sequence": first_sequence,
                "highest_sequence": highest_sequence if datagrams else None,
                "out_of_order_or_duplicate": out_of_order,
                "malformed_datagrams": malformed,
                "active_seconds": active_seconds,
            }
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    send = subparsers.add_parser("send")
    send.add_argument("destination")
    send.add_argument("--port", type=int, default=5202)
    send.add_argument("--duration", type=float, required=True)
    send.add_argument("--rate", required=True)
    send.add_argument("--segment-size", type=int, default=1100)
    send.add_argument("--segments", type=int, default=32)
    send.add_argument("--socket-buffer", type=int, default=16 * 1024 * 1024)
    send.set_defaults(handler=sender)

    receive = subparsers.add_parser("receive")
    receive.add_argument("--port", type=int, default=5202)
    receive.add_argument("--duration", type=float, required=True)
    receive.add_argument("--idle-timeout", type=float, default=0.5)
    receive.add_argument("--socket-buffer", type=int, default=16 * 1024 * 1024)
    receive.set_defaults(handler=receiver)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
