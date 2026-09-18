"""Bounded evidence for automatic provider changes on real wireless links."""

import math
from dataclasses import dataclass

from .paid_settlement import require
from .wifi_diamond_checks import counter


POLICY = {"feedback_timeout_ms": 15_000, "retry_after_ms": 60_000,
          "trial_max_units": 32_768, "min_improvement_percent": 10,
          "max_loss_percent": 25, "max_rtt_ms": 5_000}
FEES = {"n01": 128, "n02": 160}
PRICE_CEILING = 192
FULL_QUOTA = 128 * 1024
PAYLOAD_BYTES = 256
PHASE_SECONDS = 180


@dataclass(frozen=True)
class Workload:
    packets: int
    rate: int
    batches: int
    spacing_seconds: float
    drain_seconds: float


NORMAL_WORKLOAD = Workload(16, 4, 16, 10, 5)
ACTIVE_WORKLOAD = Workload(32, 2, 8, 0, 0.5)


def watch(status, destination, *, paused=False):
    watches = status["watched_routes"]
    require(len(watches) == 1 and watches[0]["destination"] == destination
            and watches[0]["max_rate_msat_per_kib"] == PRICE_CEILING
            and watches[0]["billing"] == "forwarding_data"
            and watches[0]["paused"] is paused, "automatic watch authority changed")
    return watches[0]


def bounded_capital(status):
    budget = status["funding_budget"]
    require(counter(budget["wallet_refunded_sat"]) == 0
            and counter(budget["wallet_debited_sat"]) <= 128
            and counter(budget["locked_sat"]) + counter(budget["pending_reserved_sat"]) <= 128
            and counter(budget["exposure_sat"]) <= 128,
            "automatic route selection exceeded original capital bounds")
    require(counter(status["remaining_budget_sat"]) <= 128, "buyer budget increased")


def current_purchase(status, destination):
    matches = [p for p in status["purchases"] if p["contract"]["destination"] == destination]
    require(len(matches) <= 1 and len(matches) == len(status["purchases"]),
            "unexpected active source route")
    return matches[0] if matches else None


def trial_ids(status, provider):
    return {p["contract"]["id"] for p in status["history"]
            if p["provider"] == provider and p["contract"]["max_units"] == POLICY["trial_max_units"]}


def working_route(before, quality, after, *, destination, destination_npub, provider, fee):
    """Bracket the separate query with one unchanged accepted agreement."""
    for status in (before, after):
        bounded_capital(status)
        active = watch(status, destination_npub)
        if active["pending"] is not None:
            return None
    first, last = current_purchase(before, destination), current_purchase(after, destination)
    if first is None or first != last or first["provider"] != provider:
        return None
    contract = first["contract"]
    require(contract["billing"] == "forwarding_data" and contract["price"] == {"msat": fee, "per_bytes": 1024}
            and first["channel"]["capacity_sat"] == 64, "selected price or channel terms changed")
    require(quality["destination"] == destination_npub and quality["price_selection"] == POLICY
            and quality["feedback_window_ms"] == POLICY["feedback_timeout_ms"], "quality policy changed")
    if contract["max_units"] != FULL_QUOTA:
        require(contract["max_units"] == POLICY["trial_max_units"], "unexpected trial quota")
        return None
    value = quality["quality"]
    if (value["next_hop"] != provider or value["receiver_reports_enabled"] is not True
            or value["has_recent_delivery_feedback"] is not True or value["delivery_feedback_timed_out"]):
        return None
    for field, maximum in (("rtt_ms", POLICY["max_rtt_ms"]), ("loss_rate", POLICY["max_loss_percent"] / 100)):
        metric = value[field]
        if (type(metric) not in (int, float) or not math.isfinite(metric)
                or not 0 <= metric <= maximum):
            return None
    if (type(value["goodput_bps"]) not in (int, float) or not math.isfinite(value["goodput_bps"])
            or value["goodput_bps"] <= 0):
        return None
    require(counter(value["sent_packets"]) > 0 and counter(value["sent_bytes"]) > 0,
            "quality has no source application evidence")
    return first


def paid_channel_progress(status, channel, prior_sat):
    progress = status["payment_progress"].get(channel)
    if progress is None:
        return False
    authorized = counter(progress["authorized_sat"])
    evidence = counter(progress["evidence_msat"])
    acknowledgment = progress["acknowledged_msat"]
    return (authorized > prior_sat and evidence > prior_sat * 1000
            and acknowledgment is not None and counter(acknowledgment) >= authorized * 1000
            and progress["in_flight"] is False)
