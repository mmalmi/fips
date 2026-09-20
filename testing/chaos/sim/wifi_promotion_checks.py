"""Strict boundaries for one live, testbench-only native promotion interruption."""

import json
import math
from pathlib import Path

from .paid_settlement import amount, require
from .wifi_diamond_selection import FULL_QUOTA, POLICY
from .wifi_remote import digest


CEILING = 8192
FEE = 1024
HOLD_MS = 180_000


def options(args):
    enabled = getattr(args, "interrupted_promotion", False)
    provenance = getattr(args, "promotion_provenance", None)
    if not enabled:
        if provenance is not None:
            raise ValueError("--promotion-provenance requires --interrupted-promotion")
        return None
    if any(getattr(args, key, None) for key in (
            "active_outage", "brief_outage", "outage_node", "recovery_timing", "beacon_interval_secs")):
        raise ValueError("--interrupted-promotion is a separate live middle-radio scenario")
    if provenance is None:
        raise ValueError("interrupted promotion requires instrumented build provenance")
    recorded = Path(provenance).read_bytes()
    document = json.loads(recorded)
    verification = document["verification"]
    artifact = verification["artifact"]
    binary = args.binary.read_bytes()
    require(set(verification["features"]) == {"testbench", "measurements"}
            and set(document["source"]["features"]) == {"testbench", "measurements"}
            and verification["target"] == "aarch64-unknown-linux-musl"
            and verification["build"]["exit_code"] == 0
            and verification["source_changes_during_build"] == []
            and verification["patch_unchanged"] is True
            and verification["portable_lock_restored"] is True,
            "promotion needs the verified instrumented ARM64 testbench build")
    require(artifact["sha256"] == digest(binary) and amount(artifact["bytes"]) == len(binary),
            "promotion artifact does not match build provenance")
    return {"provenance_sha256": digest(recorded),
            "binary_sha256": artifact["sha256"], "features": verification["features"],
            "source_commit": verification["source_commit"], "performance_comparable": False}


def configure(config, source):
    config["terms"]["quote_max_units"] = FULL_QUOTA
    config["return_allowance"] = False
    if source:
        config["price_selection"] = dict(POLICY)
    return config


def watch(status, destination, *, paused=False):
    watches = status["watched_routes"]
    require(len(watches) == 1 and watches[0]["destination"] == destination
            and watches[0]["max_rate_msat_per_kib"] == CEILING
            and watches[0]["billing"] == "forwarding_data"
            and watches[0]["paused"] is paused, "original promotion Watch changed")
    return watches[0]


def purchase(status, destination, provider, *, trial_quota=None):
    rows = status["purchases"]
    require(len(rows) <= 1, "source acquired another active route")
    if not rows:
        return None
    value = rows[0]
    require(value["provider"] == provider and value["contract"]["destination"] == destination
            and value["contract"]["price"] == {"msat": FEE, "per_bytes": 1024}
            and value["contract"]["billing"] == "forwarding_data"
            and value["channel"]["capacity_sat"] == 32,
            "promotion escaped the original provider, tariff or channel cap")
    expected_trial = POLICY["trial_max_units"] if trial_quota is None else amount(trial_quota)
    require(expected_trial > 0 and value["contract"]["max_units"] in (expected_trial, FULL_QUOTA),
            "promotion has an unexpected quota")
    return value


def quality(reply, destination, provider, *, working=False, unknown=False):
    require(reply["destination"] == destination and reply["price_selection"] == POLICY
            and reply["feedback_window_ms"] == POLICY["feedback_timeout_ms"],
            "promotion changed the native source quality policy")
    value = reply["quality"]
    if not working:
        require(value["delivery_feedback_timed_out"] is False,
                "idle promotion has outstanding timed-out native delivery")
        if unknown:
            require(value["loss_rate"] is None, "withdrawal has qualifying or failure loss evidence")
        return True
    if (value["receiver_reports_enabled"] is not True or value["next_hop"] != provider
            or value["has_recent_delivery_feedback"] is not True
            or value["delivery_feedback_timed_out"] is not False):
        return False
    for field, maximum in (("loss_rate", POLICY["max_loss_percent"] / 100),
                           ("rtt_ms", POLICY["max_rtt_ms"])):
        metric = value[field]
        if type(metric) not in (int, float) or not math.isfinite(metric) or not 0 <= metric <= maximum:
            return False
    return amount(value["sent_packets"]) > 0 and amount(value["sent_bytes"]) > 0


def barrier(status, buyer, destination, *, held=False):
    require(status["armed"] is True and status["active"] is True
            and status["buyer"] == buyer and status["destination"] == destination
            and status["trial_max_units"] == POLICY["trial_max_units"] and status["hold_ms"] == HOLD_MS
            and status["terminal_reason"] is None
            and all(amount(status[field]) == 0 for field in (
                "capacity_bypassed", "response_timeouts", "response_cancellations", "closed_responders")),
            "acceptance barrier is not the active bounded instrument")
    if held:
        require(amount(status["held_responses"]) > 0 and isinstance(status["captured"], dict),
                "matching request count is not a held successful provider commitment")
    return status.get("captured")


def held_boundary(status, source, provider, trial, destination):
    captured = status["captured"]
    full = captured["purchase"]
    require(full["provider"] == trial["provider"] and full["channel"] == trial["channel"]
            and full["contract"]["destination"] == trial["contract"]["destination"]
            and full["contract"]["price"] == trial["contract"]["price"]
            and full["contract"]["max_units"] == FULL_QUOTA,
            "held commitment is not the original trial's full promotion")
    old = source["outgoing"][trial["contract"]["id"]]
    new = source["outgoing"][full["contract"]["id"]]
    incoming = provider["incoming"][full["contract"]["id"]]
    require(old["purchase"] == trial and old["accepted"] is True and old["retired"] is True
            and new["purchase"] == full and new["accepted"] is False and new["retired"] is False
            and new["offer"].get("trial", False) is False
            and new["offer"]["id"] == captured["offer_id"]
            and source["watched_routes"][destination]["pending"]["id"] == captured["offer_id"]
            and incoming["phase"] == "Active" and incoming["offer"]["id"] == captured["offer_id"]
            and incoming["channel"] == full["channel"] and incoming["contract"] == full["contract"],
            "held promotion lacks durable provider commit and retired source predecessor")
    return captured


def withdrawn(controller, captured, destination):
    return (captured["offer_id"] in controller.get("recovery_only", [])
            and controller["watched_routes"][destination]["pending"] is None)
