"""Shared bounded diagnostics for the existing guarded wireless services."""

from concurrent.futures import ThreadPoolExecutor
import secrets
import time

from .paid_relay import eventually
from .paid_settlement import require
from .wifi_priority_checks import received, submitted


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


def send_with_radio_cut(run, source, destination, shape, rate, radio, evidence, *,
                        round_trip=False, verify_route=None):
    """Cut during partial delivery, drain one finite send, and let the caller restore."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        evidence["dispatch_started"] = time.monotonic()
        evidence["rate"] = rate
        evidence["earliest_final_send_seconds"] = (shape["packet_count"] - 1) / rate
        future = pool.submit(send, run, source, destination, shape, rate, round_trip=round_trip)
        sender_error = None
        try:
            def partial():
                require(not future.done(), "probe sender finished before the radio cut")
                receiver = source if round_trip else destination
                report = run.ctl(receiver, "status").get("probe")
                if not report or report["stream_id"] != shape["stream_id"]:
                    return None
                report = receive(run, source, destination, shape, round_trip=round_trip)
                return report if 0 < report["unique_packets"] < shape["packet_count"] else None

            evidence["before_cut"] = eventually("partial delivery before radio departure", partial, 10)
            if verify_route is not None:
                evidence["pre_cut_route"] = verify_route()
            require(not future.done(), "probe sender finished before the radio cut")
            cut_started = time.monotonic()
            require(cut_started - evidence["dispatch_started"] < evidence["earliest_final_send_seconds"],
                    "radio cut started after the earliest final paced send")
            evidence["cut_started"] = cut_started
            run.save()  # An uncertain radio command still needs the caller's restoration.
            evidence["cut_attempted"] = True
            radio.mesh_down()
            evidence["cut_completed"] = time.monotonic()
            # A pending control response alone does not prove remote sending continues.
            require(evidence["cut_completed"] - evidence["dispatch_started"]
                    < evidence["earliest_final_send_seconds"],
                    "radio cut completed after the earliest final paced send")
            require(not future.done(), "radio departure did not overlap active sending")
        finally:
            # Never replay a finite send, including when its reply is lost.
            try:
                evidence["sender"] = future.result(timeout=35)
            except Exception as error:
                sender_error = error
                evidence["sender_error"] = type(error).__name__
            run.save()
        if sender_error is not None:
            raise sender_error
        submitted(evidence["sender"], shape)
        return evidence["sender"]
