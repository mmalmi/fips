"""Shared finite workload schedule for wireless and storage cadence experiments."""

import secrets
import time

from .paid_settlement import require


POLICIES = (250, 500, 1000, 2000, 2000, 1000, 500, 250)
SCHEDULE = {
    "idle": {"duration_ms": 4000},
    "bursty": {"packet_counts": [64] * 8, "payload_bytes": 1000,
               "packets_per_second": 1000, "after_each_sleep_ms": 800},
    "steady": {"packet_counts": [3200], "payload_bytes": 1000, "packets_per_second": 400},
    "high_rate": {"packet_counts": [8000], "payload_bytes": 1000, "packets_per_second": 4000},
}


def policies(args):
    delay = getattr(args, "pilot_delay_ms", None)
    if delay is not None and (not args.pilot or type(delay) is not int or delay not in POLICIES):
        raise ValueError("pilot delay requires --pilot and a supported policy")
    return (delay or 250,) if args.pilot else POLICIES


def probe_status(self, destination):
    started = time.monotonic_ns()
    receiver = self.ctl(destination, "status")["probe"]
    return {"receiver": receiver, "observed_ns": [started, time.monotonic_ns()]}


def observe_after_gap(self, probe, *, destination="n03"):
    """Keep a supplemental same-stream read separate from strict delivery evidence."""
    observed = probe_status(self, destination)
    before, after = probe["receiver"], observed["receiver"]
    require(all(before[key] == after[key] for key in
                ("source", "stream_id", "expected_packets", "payload_bytes")),
            "post-gap probe identity changed")
    require(before["unique_packets"] <= after["unique_packets"] <= after["expected_packets"],
            "post-gap probe counter reset or exceeded its stream")
    return observed


def stream(self, count, rate, *, source="n01", destination="n03", drain_seconds=2):
    shape = {"stream_id": secrets.token_hex(16), "packet_count": count, "payload_bytes": 1000}
    self.ctl(destination, "receive_probe", probe={
        **shape, "source": self.nodes[source].npub, "measure_one_way_latency": False,
    })
    sent = self.ctl(source, "send_probe", probe={
        **shape, "destination": self.nodes[destination].npub, "packets_per_second": rate,
    })["probe"]
    deadline = time.monotonic() + drain_seconds
    while True:
        observation = probe_status(self, destination)
        received = observation["receiver"]
        require(received["source"] == self.nodes[source].npub
                and received["stream_id"] == shape["stream_id"]
                and sent["stream_id"] == shape["stream_id"],
                "measurement probe identity changed")
        if received["unique_packets"] == count or time.monotonic() >= deadline:
            break
        time.sleep(0.02)
    # Record partial submission and loss. Never resend measured payloads.
    return {"sender": sent, "receiver": received, "packets_per_second": rate,
            "after_sleep_ms": 0, "receiver_observed_ns": observation["observed_ns"]}


def perform(stream, name, *, started=None, after_gap=None):
    if started is None:
        started = time.monotonic()
    probes = []
    schedule = SCHEDULE[name]
    if name == "idle":
        time.sleep(schedule["duration_ms"] / 1000)
    else:
        for count in schedule["packet_counts"]:
            probe = stream(count, schedule["packets_per_second"])
            sleep_ms = schedule.get("after_each_sleep_ms", 0)
            if sleep_ms:
                time.sleep(sleep_ms / 1000)
                if after_gap is not None:
                    probe["post_gap_observation"] = after_gap(probe)
            probe["after_sleep_ms"] = sleep_ms
            probes.append(probe)
    return {"probes": probes, "offered_elapsed_ms": int((time.monotonic() - started) * 1000)}
