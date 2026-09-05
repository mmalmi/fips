#!/usr/bin/env python3
"""Continuous ICMPv6 probes that stop sending before draining pending replies."""

import argparse
import signal
import socket
import struct
import sys
import time
from threading import Event


def run_probe(sock, target, interval, should_stop, output=sys.stdout, drain_timeout=2.0):
    transmitted = received = 0
    pending = set()
    next_send = time.monotonic()
    deadline = None
    while True:
        now = time.monotonic()
        if deadline is None and should_stop():
            deadline = now + drain_timeout
        if deadline is not None and (not pending or now >= deadline):
            break
        if deadline is None and now >= next_send:
            transmitted += 1
            # Linux ping sockets provide the checksum and per-socket identifier.
            packet = struct.pack("!BBHHHQd", 128, 0, 0, 0, transmitted & 0xffff, transmitted, now)
            sock.send(packet + bytes(40))
            pending.add(transmitted)
            next_send = now + interval
        wait_until = deadline if deadline is not None else next_send
        sock.settimeout(max(0.0001, min(0.05, wait_until - time.monotonic())))
        try:
            reply = sock.recv(4096)
        except socket.timeout:
            continue
        if len(reply) != 64 or reply[0] != 129:
            continue
        sequence, sent_at = struct.unpack("!Qd", reply[8:24])
        if not 1 <= sequence <= transmitted:
            continue
        pending.discard(sequence)
        received += 1
        rtt = (time.monotonic() - sent_at) * 1000
        print(f"[{time.time():.6f}] 64 bytes from {target}: icmp_seq={sequence} time={rtt:.3f} ms",
              file=output, flush=True)
    print(f"{transmitted} packets transmitted, {received} received", file=output, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("interval must be positive")
    stopped = Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6) as sock:
        sock.connect((args.target, 0))
        run_probe(sock, args.target, args.interval, stopped.is_set)


if __name__ == "__main__":
    main()
