"""Fail-closed observations for one bounded mixed-class wireless experiment."""

import copy
from bisect import bisect_left

from .paid_settlement import require


def natural(value):
    require(type(value) is int and value >= 0, "missing unsigned priority evidence")
    return value


def workload(args):
    ranges = {
        "free_packets": (1, 65_536), "free_rate": (1, 16_000),
        "free_bytes": (40, 1_000), "paid_packets": (2, 64),
        "paid_rate": (1, 64), "paid_bytes": (40, 256),
        "free_bytes_per_second": (1, 64 * 1024 * 1024),
        "free_burst_bytes": (4096, 1024 * 1024), "overlap_seconds": (5, 30),
    }
    result = {}
    for key, (low, high) in ranges.items():
        value = getattr(args, key)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{key} must be an integer in {low}..{high}")
        result[key] = value
    for kind in ("free", "paid"):
        if result[kind + "_packets"] > result[kind + "_rate"] * 30:
            raise ValueError("each finite probe must fit within the production 30-second bound")
    return result


def free_policy(schedule):
    return {scope + suffix: schedule[field]
            for scope in ("global", "peer")
            for suffix, field in (("_bytes_per_second", "free_bytes_per_second"),
                                  ("_burst_bytes", "free_burst_bytes"))}


def patch_config(config, changes):
    require(set(changes) <= {"neighbors", "destination_fees"},
            "priority setup cannot rewrite financial terms or transport bindings")
    result = copy.deepcopy(config)
    result.update(copy.deepcopy(changes))
    return result


def loopback_address(value):
    require(isinstance(value, str), "missing loopback listener")
    host, separator, port = value.rpartition(":")
    require(separator and host == "127.0.0.1" and port.isascii() and port.isdecimal()
            and 1 <= int(port) <= 65535, "auxiliary transport escaped the exact loopback bind")
    return value


def adjacency(states, identities, udp_addresses):
    expected = {
        "n01": {"n02": "ethernet"},
        "n02": {"n01": "ethernet", "n03": "ethernet", "free-source": "udp"},
        "n03": {"n02": "ethernet", "free-sink": "udp"},
        "free-source": {"n02": "udp"}, "free-sink": {"n03": "udp"},
    }
    require(set(states) == set(identities) == set(expected)
            and len(set(identities.values())) == 5, "priority participant identities changed")
    for name, neighbors in expected.items():
        state = states[name]
        require(state["npub"] == identities[name], "priority service identity changed")
        peers = state["peers"]
        require(len(peers) == len(neighbors), "unexpected or stale priority topology peer")
        wanted = {identities[key]: (key, transport) for key, transport in neighbors.items()}
        require({peer["npub"] for peer in peers} == set(wanted), "priority topology has a shortcut")
        for peer in peers:
            other, transport = wanted[peer["npub"]]
            require(peer["connected"] is True and peer["transport"] == transport,
                    "priority adjacency changed transport or disconnected")
            if transport == "udp":
                require(loopback_address(peer["address"]) == udp_addresses[other],
                        "auxiliary peer address differs from its observed listener")
    return states


def submitted(report, shape):
    require(report["stream_id"] == shape["stream_id"]
            and natural(report["requested_packets"]) == shape["packet_count"]
            and natural(report["submitted_packets"]) == shape["packet_count"]
            and natural(report["submitted_bytes"]) == shape["packet_count"] * shape["payload_bytes"]
            and report["stopped_reason"] is None, "priority probe was not fully submitted")


def received(report, shape, source, *, complete=False, round_trip=False):
    require(report["stream_id"] == shape["stream_id"] and report["source"] == source
            and report["expected_packets"] == shape["packet_count"]
            and report["payload_bytes"] == shape["payload_bytes"], "priority probe identity or shape changed")
    count = natural(report["unique_packets"])
    require(count <= shape["packet_count"]
            and natural(report["unique_bytes"]) == count * shape["payload_bytes"]
            and natural(report["missing_packets"]) + count == shape["packet_count"]
            and natural(report["duplicate_packets"]) == natural(report["invalid_packets"]) == 0
            and report["latency"] is None, "priority receiver has invalid, duplicate or inconsistent data")
    if round_trip:
        round_trip_latency(report)
    else:
        require(report.get("round_trip_latency") is None, "unexpected round-trip measurement")
    if complete:
        require(count == shape["packet_count"], "paid or recovery probe delivery is incomplete")
    return count


def round_trip_latency(report):
    """Validate a same-clock histogram; percentile results are bucket bounds."""
    latency = report.get("round_trip_latency")
    require(isinstance(latency, dict) and report["latency"] is None,
            "explicit round-trip timing required")
    samples = natural(latency["samples"])
    require(samples == natural(report["unique_packets"])
            and natural(latency["invalid_timestamps"]) == 0,
            "round-trip delivery lacks valid local timestamps")
    bounds, counts = latency["bucket_upper_bounds_us"], latency["bucket_counts"]
    require(isinstance(bounds, list) and 1 <= len(bounds) <= 64
            and all(natural(value) > 0 for value in bounds)
            and bounds == sorted(set(bounds)) and isinstance(counts, list)
            and len(counts) == len(bounds) + 1 and sum(map(natural, counts)) == samples,
            "invalid round-trip histogram")
    total = natural(latency["sum_us"])
    low, high = latency["min_us"], latency["max_us"]
    if samples:
        require(natural(low) <= natural(high) and low * samples <= total <= high * samples,
                "round-trip extrema or sum disagree")
        occupied = [index for index, count in enumerate(counts) if count]
        first, last = bisect_left(bounds, low), bisect_left(bounds, high)
        require(occupied[0] == first and occupied[-1] == last,
                "round-trip extrema lie outside occupied histogram buckets")
        minimum = [max(low, bounds[index - 1] + 1 if index else 0) for index in occupied]
        maximum = [min(high, bounds[index] if index < len(bounds) else high) for index in occupied]
        min_sum = sum(counts[index] * limit for index, limit in zip(occupied, minimum))
        max_sum = sum(counts[index] * limit for index, limit in zip(occupied, maximum))
        # The reported extrema must each occur at least once, not merely fit a bin.
        min_sum += high - minimum[-1]
        max_sum -= maximum[0] - low
        require(min_sum <= total <= max_sum, "round-trip sum contradicts its histogram")
    else:
        require(low is None and high is None and total == 0, "empty timing invented samples")

    def percentile_bound(percent):
        rank = (samples * percent + 99) // 100
        cumulative = 0
        for index, count in enumerate(counts):
            cumulative += count
            if cumulative >= rank:
                return bounds[index] if samples and index < len(bounds) else None
        return None

    return {"samples": samples, "mean_us": total / samples if samples else None,
            "min_us": low, "max_us": high, "p50_upper_bound_us": percentile_bound(50),
            "p95_upper_bound_us": percentile_bound(95)}


def running(future):
    if future.done():
        future.result()  # Preserve an actual sender error rather than calling it overlap.
        raise RuntimeError("free sender completed before paid delivery and payment overlap")


def bandwidth(sample):
    value = sample["free_routes"]["bandwidth"]
    for key in ("admitted_packets", "charged_units", "rate_denied", "peer_capacity_denied", "tracked_peers"):
        natural(value[key])
    return value


def same_middle(before, after):
    first, last = before["host_process"], after["host_process"]
    require(first["host"] == last["host"] == "n02"
            and (first["pid"], first["start_ticks"]) == (last["pid"], last["start_ticks"]),
            "middle-router process changed during priority observation")
    require(before["sample_timing"]["finished_monotonic_ns"]
            <= after["sample_timing"]["started_monotonic_ns"], "priority samples are not ordered")


def pressure_pair(before, after, paid_count):
    """Both snapshots are enclosed by partially delivered paid-stream reads."""
    for item in (before, after):
        left, right = (natural(item[key]["unique_packets"])
                       for key in ("receiver_before", "receiver_after"))
        if not 0 < left <= right < paid_count:
            return False
    if after["receiver_before"]["unique_packets"] <= before["receiver_after"]["unique_packets"]:
        return False
    first, last = before["middle"], after["middle"]
    same_middle(first, last)
    old, new = (sample["native"]["status"]["data"]["forwarding"] for sample in (first, last))
    deltas = {}
    for key in ("drop_background_full_packets", "drop_background_full_bytes"):
        deltas[key] = natural(new[key]) - natural(old[key])
        require(deltas[key] >= 0, "background pressure counters decreased")
    return deltas if all(deltas.values()) else False


def payment(status):
    progress = status["payment_progress"]
    require(isinstance(progress, dict) and len(progress) == 1,
            "paid source must retain exactly one original channel")
    channel, current = next(iter(progress.items()))
    require(isinstance(channel, str) and bool(channel), "missing payment channel identity")
    value = {key: natural(current[key]) for key in ("evidence_msat", "authorized_sat")}
    ack = current["acknowledged_msat"]
    value.update(acknowledged_msat=None if ack is None else natural(ack), in_flight=current["in_flight"])
    require(type(value["in_flight"]) is bool, "invalid payment scheduler evidence")
    pid = natural(status["measurements"]["process_id"])
    require(pid > 0 and status["measurements"]["version"] == 1, "measurement-enabled source required")
    return {"channel": channel, "process_id": pid, **value}


def acknowledged(before, after):
    require((before["channel"], before["process_id"]) == (after["channel"], after["process_id"]),
            "paid source changed process or original channel")
    for key in ("evidence_msat", "authorized_sat"):
        require(after[key] >= before[key], "automatic payment evidence decreased")
    ack = after["acknowledged_msat"]
    if ack is not None and before["acknowledged_msat"] is not None:
        require(ack >= before["acknowledged_msat"], "automatic acknowledgment decreased")
    return (after["evidence_msat"] > before["evidence_msat"]
            and after["authorized_sat"] > before["authorized_sat"]
            and reconciled(after))


def reconciled(current):
    target = max(current["evidence_msat"], current["authorized_sat"] * 1000)
    ack = current["acknowledged_msat"]
    return current["in_flight"] is False and ack is not None and ack >= target


def bounded_free(before, after, policy):
    same_middle(before, after)
    first, last = bandwidth(before), bandwidth(after)
    elapsed_ns = after["sample_timing"]["finished_monotonic_ns"] - before["sample_timing"]["started_monotonic_ns"]
    # Round upward using controller time; the sample bracket contains all charges.
    seconds = (elapsed_ns + 999_999_999) // 1_000_000_000
    charged = last["charged_units"] - first["charged_units"]
    require(charged > 0 and last["admitted_packets"] > first["admitted_packets"]
            and last["tracked_peers"] == 1 and last["peer_capacity_denied"] == 0,
            "free forwarding lacks one bounded active neighbor")
    limits = {scope: policy[scope + "_burst_bytes"] + seconds * policy[scope + "_bytes_per_second"]
              for scope in ("global", "peer")}
    require(charged <= min(limits.values()), "free traffic exceeded its configured allowance")
    return {"charged_units": charged, "elapsed_seconds_upper_bound": seconds, "limits": limits}
