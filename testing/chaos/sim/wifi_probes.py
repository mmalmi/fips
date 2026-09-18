"""Shared bounded diagnostics for the existing guarded wireless services."""

import secrets

from .wifi_priority_checks import received


def arm(run, source, destination, count, size, *, round_trip=False):
    shape = {"stream_id": secrets.token_hex(16), "packet_count": count, "payload_bytes": size}
    reflection = {"reflect": True} if round_trip else {}
    run.ctl(destination, "receive_probe", probe={
        **shape, "source": run.participants()[source].npub, "measure_one_way_latency": False,
        **reflection,
    })
    return shape


def send(run, source, destination, shape, rate, *, round_trip=False):
    latency = {"measure_round_trip": True} if round_trip else {}
    return run.ctl(source, "send_probe", probe={
        **shape, "destination": run.participants()[destination].npub,
        "packets_per_second": rate, **latency,
    })["probe"]


def receive(run, source, destination, shape, *, complete=False, round_trip=False):
    report = run.ctl(source if round_trip else destination, "status")["probe"]
    identity = run.participants()[destination if round_trip else source].npub
    received(report, shape, identity, complete=complete, round_trip=round_trip)
    return report
