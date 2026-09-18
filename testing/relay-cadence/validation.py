"""Acceptance rules for the fixed clean-link experiment, not impaired trials."""

PAYMENT_PORT = 44743
PAYMENT_OPERATIONS = ("payment_sign", "payment_usage", "payment_update")
OPERATIONS = {"other", *PAYMENT_OPERATIONS, "payment_open", "payment_stop", "window_checkpoint"}
COUNTERS = {"spans", "cpu_samples", "thread_cpu_ns", "elapsed_ns",
            "journal_bytes_written", "journal_writes", "journal_syncs", "journal_commits"}
POLICIES = (250, 500, 1000, 2000, 2000, 1000, 500, 250)
WORKLOADS = {"idle": [], "bursty": [64] * 8, "steady": [3200], "high_rate": [32000]}
HARDWARE_WORKLOADS = {**WORKLOADS, "high_rate": [8000]}
HARDWARE_SCHEDULE = {
    "idle": {"duration_ms": 4000},
    "bursty": {"packet_counts": [64] * 8, "payload_bytes": 1000,
               "packets_per_second": 1000, "after_each_sleep_ms": 800},
    "steady": {"packet_counts": [3200], "payload_bytes": 1000,
               "packets_per_second": 400},
    "high_rate": {"packet_counts": [8000], "payload_bytes": 1000,
                  "packets_per_second": 4000},
}
OS_IO_COUNTERS = ("read_bytes", "write_bytes", "rchar", "wchar", "syscr", "syscw")


def unsigned(value):
    if type(value) is not int or value < 0:
        raise ValueError("expected nonnegative integer evidence")
    return value


def validate_measurements(before, after):
    if before["version"] != 1 or after["version"] != 1:
        raise ValueError("unsupported measurement counter version")
    if before["process_id"] != after["process_id"]:
        raise ValueError("a service restarted during measurement")
    if unsigned(after["process_cpu_ns"]) < unsigned(before["process_cpu_ns"]):
        raise ValueError("process CPU counter reset")
    if set(before["operations"]) != OPERATIONS or set(after["operations"]) != OPERATIONS:
        raise ValueError("measurement operations changed or are missing")
    for name, prior in before["operations"].items():
        current = after["operations"][name]
        if set(prior) != COUNTERS or set(current) != COUNTERS:
            raise ValueError("measurement counters changed or are missing")
        for key in COUNTERS:
            if unsigned(current[key]) < unsigned(prior[key]):
                raise ValueError(f"measurement counter reset: {name}.{key}")


def host_identity(node):
    """PID namespaces are independent; bind counters to one host and process epoch."""
    process = node["host_process"]
    host, npub = process["host"], node["npub"]
    if host not in ("n01", "n02", "n03") or not isinstance(npub, str) or not npub:
        raise ValueError("invalid hardware host or node identity")
    for field in ("pid", "start_ticks", "rss_kib", "peak_rss_kib"):
        unsigned(process[field])
    if type(process["io_available"]) is not bool:
        raise ValueError("hardware I/O availability must be explicit")
    for field in OS_IO_COUNTERS:
        if process["io_available"]:
            unsigned(process[field])
        elif process[field] is not None:
            raise ValueError("unavailable hardware I/O must remain null")
    if (not process["pid"] or not process["start_ticks"]
            or process["pid"] != unsigned(node["measurements"]["process_id"])):
        raise ValueError("hardware process identity differs from measurement source")
    if process["rss_kib"] > process["peak_rss_kib"]:
        raise ValueError("current RSS exceeds the process-lifetime high-water mark")
    return host, npub, process["pid"], process["start_ticks"]


def validate_host_pair(before, after):
    if host_identity(before) != host_identity(after):
        raise ValueError("hardware host, node or process epoch changed")
    a, b = before["host_process"], after["host_process"]
    if a["io_available"] != b["io_available"]:
        raise ValueError("hardware I/O availability changed")
    counters = (*OS_IO_COUNTERS, "peak_rss_kib") if a["io_available"] else ("peak_rss_kib",)
    for field in counters:
        if b[field] < a[field]:
            raise ValueError(f"hardware process counter reset: {field}")


def quiet_boundary(nodes, schema=2):
    """Acknowledged credit must cover current local evidence and signed liability."""
    expected_nodes, expected_channels = (3, 2) if schema == 3 else (5, 6)
    if len(nodes) != expected_nodes:
        raise ValueError(f"expected {expected_nodes} measured service processes")
    channels = {}
    processes, hosts, identities = set(), set(), set()
    for index, node in enumerate(nodes):
        if schema == 3:
            process = host_identity(node)
            host, npub = process[:2]
            if host in hosts or npub in identities:
                raise ValueError("duplicate hardware host or node identity")
            hosts.add(host)
            identities.add(npub)
        else:
            process = unsigned(node["measurements"]["process_id"])
        if not process or process in processes:
            raise ValueError("expected distinct measured service processes")
        processes.add(process)
        if node["last_error"] is not None:
            raise ValueError("controller error at measurement boundary")
        progress = node["payment_progress"]
        if not isinstance(progress, dict):
            raise ValueError("missing payment progress")
        for channel, state in progress.items():
            if not isinstance(channel, str) or not channel or channel in channels:
                raise ValueError("duplicate or invalid payment channel")
            evidence = unsigned(state["evidence_msat"])
            authorized = unsigned(state["authorized_sat"]) * 1000
            acknowledged = unsigned(state["acknowledged_msat"])
            if state["in_flight"] is not False or acknowledged < max(evidence, authorized):
                raise ValueError("unreconciled payment work at measurement boundary")
            channels[channel] = process if schema == 3 else index
    if len(channels) != expected_channels:
        raise ValueError(f"expected {expected_channels} reconciled paying channels")
    return channels


def payment_counters(node):
    services = node["control_traffic"]
    ports = [service["service_port"] for service in services]
    if len(ports) != len(set(ports)) or ports.count(PAYMENT_PORT) != 1:
        raise ValueError("missing or duplicate payment control counters")
    return next(s["counters"] for s in services if s["service_port"] == PAYMENT_PORT)


def validate_gap(previous, current, schema=2):
    """No payment or durability work may escape into the unmeasured gap."""
    if quiet_boundary(previous, schema) != quiet_boundary(current, schema):
        raise ValueError("paying channels changed between workloads")
    for before, after in zip(previous, current):
        if schema == 3:
            validate_host_pair(before, after)
        validate_measurements(before["measurements"], after["measurements"])
        if before["payment_progress"] != after["payment_progress"]:
            raise ValueError("payment evidence changed outside measurement windows")
        if payment_counters(before) != payment_counters(after):
            raise ValueError("payment traffic outside measurement windows")
        for name, counters in before["measurements"]["operations"].items():
            latest = after["measurements"]["operations"][name]
            if name in PAYMENT_OPERATIONS and counters != latest:
                raise ValueError("payment work outside measurement windows")
            for key in ("journal_writes", "journal_bytes_written", "journal_syncs", "journal_commits"):
                if counters[key] != latest[key]:
                    raise ValueError("durable work outside measurement windows")


def validate_probe(probe, count, schema=2):
    sent, received = probe["sender"], probe["receiver"]
    if sent["stopped_reason"] is not None:
        raise ValueError("probe sender stopped")
    if sent["stream_id"] != received["stream_id"]:
        raise ValueError("probe stream identity changed")
    for value in (sent["requested_packets"], sent["submitted_packets"],
                  received["expected_packets"], received["unique_packets"]):
        if unsigned(value) != count:
            raise ValueError("clean-link probe has partial submission or delivery loss")
    if received["payload_bytes"] != 1000:
        raise ValueError("offered packet size changed")
    for value in (sent["submitted_bytes"], received["unique_bytes"]):
        if unsigned(value) != count * 1000:
            raise ValueError("probe byte accounting differs from workload")
    for key in ("missing_packets", "duplicate_packets", "invalid_packets"):
        if unsigned(received[key]) != 0:
            raise ValueError("clean-link probe is missing, duplicated or invalid")
    if schema == 3:
        if received["latency"] is not None:
            raise ValueError("hardware one-way latency must remain unmeasured")
    elif unsigned(received["latency"]["invalid_timestamps"]) != 0:
        raise ValueError("clean-link latency has invalid timestamps")


def validate_idle(result):
    for key in ("payment_requests", "payment_record_bytes", "signs", "updates",
                "payment_cpu_ms", "journal_writes", "journal_bytes", "journal_syncs"):
        if result[key] != 0:
            raise ValueError(f"idle work did not quiesce: {key}")


def validate_hardware_schedule(data):
    schedule = HARDWARE_SCHEDULE[data["workload"]]
    if data["workload"] == "idle":
        if unsigned(data["offered_elapsed_ms"]) < schedule["duration_ms"]:
            raise ValueError("hardware idle window ended early")
        return
    elapsed_us = 0
    for probe in data["probes"]:
        if (unsigned(probe["packets_per_second"]) != schedule["packets_per_second"]
                or unsigned(probe["after_sleep_ms"]) != schedule.get("after_each_sleep_ms", 0)):
            raise ValueError("hardware probe schedule changed")
        elapsed_us += unsigned(probe["sender"]["elapsed_us"])
        elapsed_us += probe["after_sleep_ms"] * 1000
    # The outer clock is stored in whole milliseconds. These intervals are
    # sequential; all sender work and all eight burst sleeps belong inside it.
    if unsigned(data["offered_elapsed_ms"]) * 1000 + 1000 < elapsed_us:
        raise ValueError("hardware offered window omits probe work or sleep")
