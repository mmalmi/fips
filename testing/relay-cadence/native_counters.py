"""Validate existing native observations without interpreting drops as receipts."""

from validation import host_identity, unsigned


GROUPS = {
    "forwarding": {f"{kind}_{unit}" for kind in (
        "received", "decode_error", "ttl_exhausted", "delivered", "forwarded",
        "drop_no_route", "drop_mtu_exceeded", "drop_send_error", "drop_policy_denied",
        "originated") for unit in ("packets", "bytes")},
    "congestion": {"ce_forwarded", "ce_received", "congestion_detected", "kernel_drop_events"},
    "error_signals": {
        "coords_required", "coords_required_unbound", "path_broken", "path_broken_unbound",
        "mtu_exceeded", "mtu_exceeded_unbound", "routing_signal_forged", "emit_over_peer_budget",
        "emit_over_dest_interval", "emit_limiter_at_capacity", "mtu_exceeded_stale_path",
        "mtu_exceeded_below_floor", "mtu_exceeded_uncorroborated",
        "path_mtu_notification_below_floor", "lookup_resp_mtu_below_floor",
    },
}
BACKGROUND = {"drop_background_full_packets", "drop_background_full_bytes"}


def groups(data, expected=GROUPS):
    for group in expected:
        values = data[group]
        layouts = (GROUPS[group],)
        if group == "forwarding":
            # Preserve historical reports without inventing absent queue counters.
            layouts += (GROUPS[group] | BACKGROUND,)
        if not isinstance(values, dict) or set(values) not in layouts:
            raise ValueError(f"missing or changed native counter group: {group}")
        for value in values.values():
            unsigned(value)
    return {group: data[group] for group in expected}


def difference(before, after):
    result = {}
    for group, values in before.items():
        if set(values) != set(after[group]):
            raise ValueError(f"native counter layout changed: {group}")
        result[group] = {}
        for field, value in values.items():
            current = after[group][field]
            if current < value:
                raise ValueError(f"native counter reset: {group}.{field}")
            result[group][field] = current - value
    return result


def validate(node):
    native = node["native"]
    if not isinstance(native, dict) or set(native) != {"status", "routing"}:
        raise ValueError("missing native status or routing observation")
    for reply in native.values():
        if not isinstance(reply, dict) or reply.get("status") != "ok":
            raise ValueError("native observation failed")
    status, routing = native["status"]["data"], native["routing"]["data"]
    if (status["npub"] != node["npub"]
            or unsigned(status["pid"]) != node["host_process"]["pid"]
            or not isinstance(status["exe_path"], str) or not status["exe_path"]):
        raise ValueError("native observation has a different process identity")
    observed = groups(routing)
    # The native status query precedes routing in the guarded shell sample.
    difference(groups(status, ("forwarding",)), observed)
    return observed


def sample_pair(before, after):
    if host_identity(before) != host_identity(after):
        raise ValueError("native observations changed process epoch")
    if before["native"]["status"]["data"]["exe_path"] != after["native"]["status"]["data"]["exe_path"]:
        raise ValueError("native executable identity changed")
    first, last = validate(before), validate(after)
    difference({"forwarding": first["forwarding"]},
               groups(after["native"]["status"]["data"], ("forwarding",)))
    return difference(first, last)


def record(data, result, previous, enabled, log_filter=None):
    boundaries = [(name, data[name]) for name in ("before_guard", "before", "after", "after_guard")]
    if previous is not None:
        boundaries.insert(0, ("previous_after_guard", previous))
    for _, nodes in boundaries:
        for node in nodes:
            if ("native" in node) != enabled:
                raise ValueError("native observations differ from explicit metadata")
            if ("dataplane_log" in node) != (log_filter is not None):
                raise ValueError("drop log observations differ from explicit metadata")
    if log_filter is not None:
        result["dataplane_log_ranges"] = {}
        for index, node in enumerate(data["before"]):
            samples = {}
            for name, nodes in boundaries:
                sample = nodes[index]["dataplane_log"]
                if sample["filter"] != log_filter:
                    raise ValueError("dataplane drop log filter changed")
                size = unsigned(sample["bytes"])
                if samples and size < next(reversed(samples.values())):
                    raise ValueError("dataplane drop log shrank within the process epoch")
                samples[name] = size
            result["dataplane_log_ranges"][node["host_process"]["host"]] = samples
    if not enabled:
        return
    result["native_gap_counters"] = {}
    for (a_name, a), (b_name, b) in zip(boundaries, boundaries[1:]):
        deltas = {before["host_process"]["host"]: sample_pair(before, after)
                  for before, after in zip(a, b)}
        if (a_name, b_name) == ("before", "after"):
            for host, values in deltas.items():
                result["nodes"][host]["native_counters"] = values
        else:
            result["native_gap_counters"][f"{a_name}_to_{b_name}"] = deltas
